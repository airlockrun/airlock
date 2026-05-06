package trigger

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	promptpkg "github.com/airlockrun/airlock/prompt"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/goai/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// PromptProxy manages conversation history and forwards prompts to agent containers.
type PromptProxy struct {
	dispatcher            *Dispatcher
	db                    *db.DB
	s3                    *storage.S3Client
	logger                *zap.Logger
	resolveTranscription  TranscriptionResolver
}

// NewPromptProxy creates a PromptProxy. The resolver is invoked to obtain the
// admin-configured transcription model when a voice note arrives; pass nil to
// disable auto-transcription (voice notes flow through as plain attachments).
func NewPromptProxy(dispatcher *Dispatcher, database *db.DB, s3 *storage.S3Client, resolveTranscription TranscriptionResolver, logger *zap.Logger) *PromptProxy {
	return &PromptProxy{
		dispatcher:           dispatcher,
		db:                   database,
		s3:                   s3,
		logger:               logger,
		resolveTranscription: resolveTranscription,
	}
}

// HandleMessage processes an incoming DM for an agent via a bridge.
// Manages conversation history, forwards to agent, streams response events
// to the provided channel, stores response when complete.
// The events channel is closed when streaming completes.
func (p *PromptProxy) HandleMessage(
	ctx context.Context,
	agentID, bridgeID, userID uuid.UUID,
	externalID string,
	storeHistory bool,
	oneShot bool,
	userMessage string,
	files []BridgeFile,
	referenced *BridgeReferencedMessage,
	events chan<- ResponseEvent,
) (string, error) {
	q := dbq.New(p.db.Pool())

	var conversationID pgtype.UUID

	switch {
	case oneShot:
		// One-shot mode: fresh ephemeral conversation per turn. Delete on
		// return so no history accumulates. Cascade FK on agent_messages
		// drops any rows the agent persisted during the run.
		if externalID == "" {
			close(events)
			return "", fmt.Errorf("one-shot bridge conversation requires external_id")
		}
		turnExternalID := externalID + ":oneshot:" + uuid.New().String()
		conv, err := q.GetOrCreateConversationByExternal(ctx, dbq.GetOrCreateConversationByExternalParams{
			AgentID:    toPgUUID(agentID),
			Source:     "bridge",
			Title:      truncate(userMessage, 100),
			BridgeID:   toPgUUID(bridgeID),
			ExternalID: pgtype.Text{String: turnExternalID, Valid: true},
		})
		if err != nil {
			close(events)
			return "", fmt.Errorf("create one-shot conversation: %w", err)
		}
		conversationID = conv.ID
		defer func() {
			// Best-effort delete with a fresh context — the request ctx
			// may already be cancelled by the time the streaming finishes.
			delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := dbq.New(p.db.Pool()).DeleteConversation(delCtx, conversationID); err != nil {
				p.logger.Warn("one-shot: delete ephemeral conversation",
					zap.String("conversation_id", convert.PgUUIDToString(conversationID)),
					zap.Error(err),
				)
			}
		}()

	case storeHistory && userID != uuid.Nil:
		// Authenticated bridge user → conversation keyed on (agent, user, source).
		conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
			AgentID:    toPgUUID(agentID),
			UserID:     toPgUUID(userID),
			Source:     "bridge",
			Title:      truncate(userMessage, 100),
			BridgeID:   toPgUUID(bridgeID),
			ExternalID: pgtype.Text{String: externalID, Valid: externalID != ""},
		})
		if err != nil {
			close(events)
			return "", fmt.Errorf("get/create conversation: %w", err)
		}
		conversationID = conv.ID

	case storeHistory:
		// Public/anonymous (session mode) → keyed on (agent, source, external_id) with user_id NULL.
		if externalID == "" {
			close(events)
			return "", fmt.Errorf("public bridge conversation requires external_id")
		}
		conv, err := q.GetOrCreateConversationByExternal(ctx, dbq.GetOrCreateConversationByExternalParams{
			AgentID:    toPgUUID(agentID),
			Source:     "bridge",
			Title:      truncate(userMessage, 100),
			BridgeID:   toPgUUID(bridgeID),
			ExternalID: pgtype.Text{String: externalID, Valid: true},
		})
		if err != nil {
			close(events)
			return "", fmt.Errorf("get/create public conversation: %w", err)
		}
		conversationID = conv.ID
	}

	// Always wrap a referenced message into the user prompt so the LLM
	// has the explicit context regardless of mode. In one-shot it's the
	// only context the model gets; in session mode it strengthens the
	// signal beyond whatever happens to be in history.
	userMessage = wrapReferencedMessage(userMessage, referenced)

	// Resolve access once — reused for slash-command gating and for
	// filtering per-caller extra system prompts. Non-members fall through
	// to AccessPublic, which is correct for anonymous public-channel users.
	access := ResolveAgentAccess(ctx, q, agentID, userID)

	// Intercept slash commands (/clear, /compact, ...) before forwarding.
	// `/clear` and unknown commands return a reply directly so the bridge
	// driver renders it like a normal message. `/compact` falls through to
	// the agent with ForceCompact=true so Sol's Runner.Compact produces the
	// reply via its usual streaming path.
	var forceCompact bool
	if conversationID.Valid {
		if cmd, err := TrySlashCommand(ctx, q, conversationID, agentID, access, userMessage, p.logger); err != nil {
			close(events)
			return "", fmt.Errorf("slash command: %w", err)
		} else if cmd.Handled {
			if !cmd.ForwardAsCompact {
				events <- ResponseEvent{Type: "text-delta", Text: cmd.Reply}
				close(events)
				return cmd.Reply, nil
			}
			forceCompact = true
		}
	}

	// Pre-allocate agent-facing storage keys for each file so transcription
	// can tag its output with the same key the file will be uploaded under.
	// Keeps the transcript ↔ source file link explicit for the LLM.
	paths := make([]string, len(files))
	for i := range files {
		paths[i] = "tmp/" + uuid.New().String()[:8] + "-" + files[i].Filename
	}

	// Auto-transcribe voice notes before forwarding. Transcription failures
	// fall back to attaching the audio without a transcript — we never drop
	// the user's message. The original ogg is still uploaded below.
	userMessage = p.transcribeVoiceNotes(ctx, userMessage, files, paths)

	// Store attached files in agent's S3 prefix and build FileInfo entries.
	var fileInfos []agentsdk.FileInfo
	for i, f := range files {
		s3Key := "agents/" + agentID.String() + "/" + paths[i]
		if err := p.s3.PutObject(ctx, s3Key, bytes.NewReader(f.Data), int64(len(f.Data))); err != nil {
			p.logger.Error("store bridge file failed", zap.String("path", paths[i]), zap.Error(err))
			continue
		}
		fileInfos = append(fileInfos, agentsdk.FileInfo{
			Path:        paths[i],
			Filename:    f.Filename,
			ContentType: f.ContentType,
			Size:        int64(len(f.Data)),
		})
	}

	// Resolve access-filtered extra system prompt fragments. Failure to load
	// the agent row is non-fatal — we just skip extras rather than blocking
	// the whole prompt.
	var extraSystemPrompt string
	if ag, err := q.GetAgentByID(ctx, toPgUUID(agentID)); err == nil {
		extraSystemPrompt = promptpkg.RenderExtras(ag.ExtraPrompts, access)
	}

	// Forward to agent container — SessionStore handles message loading and persistence.
	// CallerAccess is required for the agent's bind-time gating (admin-only
	// JS bindings like requestUpgrade, queryDB, execDB). Web path does the
	// same in api/conversations.go; without it the agent defaults to
	// AccessUser and admin-only verbs ReferenceError when called from a
	// bridge-triggered run.
	input := agentsdk.PromptInput{
		Message:           userMessage,
		ConversationID:    convert.PgUUIDToString(conversationID),
		Files:             fileInfos,
		ExtraSystemPrompt: extraSystemPrompt,
		ForceCompact:      forceCompact,
		CallerAccess:      access,
	}
	if forceCompact {
		input.Message = ""
	}

	// Parity with the web path ([api/conversations.go:396-400]): if there's a
	// suspended run (pending permission check), free-text messages resolve it
	// as denied and the new message is re-reasoned in the same run.
	if suspendedRun, err := q.GetLatestSuspendedRun(ctx, toPgUUID(agentID)); err == nil {
		input.ResumeRunID = convert.PgUUIDToString(suspendedRun.ID)
		approved := false
		input.Approved = &approved
		_ = q.ResolveSuspendedRun(ctx, suspendedRun.ID)
	}

	rc, runID, err := p.dispatcher.ForwardPrompt(ctx, agentID, input, &bridgeID)
	if err != nil {
		close(events)
		return "", fmt.Errorf("forward prompt: %w", err)
	}
	defer rc.Close()

	// Stream NDJSON response — forwards events to driver and collects text.
	// Message persistence is handled by the SessionStore in the agent container.
	responseText, _, _, err := StreamNDJSONResponse(rc, runID.String(), events)
	if err != nil {
		return "", fmt.Errorf("stream response: %w", err)
	}

	return responseText, nil
}

// HandleCallback resolves a suspended run based on a bridge UI callback
// (inline-keyboard tap). data is the opaque platform payload — expected format:
//
//	"approve:<runID>"  — resume with Approved=true, no prompt
//	"deny:<runID>"     — resume with Approved=false + a "Rejected by user." prompt
//
// If the referenced run is no longer suspended (e.g. already resolved via web),
// emits a single "info" event and returns — the driver's AnswerCallbackQuery
// should still fire to clear the spinner.
func (p *PromptProxy) HandleCallback(
	ctx context.Context,
	agentID, bridgeID, userID uuid.UUID,
	externalID, data string,
	events chan<- ResponseEvent,
) (staleRun bool, err error) {
	q := dbq.New(p.db.Pool())

	action, runIDStr, ok := parseCallbackData(data)
	if !ok {
		close(events)
		return false, fmt.Errorf("invalid callback data %q", data)
	}
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		close(events)
		return false, fmt.Errorf("invalid run id in callback: %w", err)
	}

	run, err := q.GetSuspendedRunByID(ctx, toPgUUID(runID))
	if err != nil {
		// Stale button — the run was already resolved (e.g. via web or another tap).
		events <- ResponseEvent{Type: "info", Text: "This confirmation has already been resolved."}
		close(events)
		return true, nil
	}
	_ = run // status check is already implicit in GetSuspendedRunByID

	if err := q.ResolveSuspendedRun(ctx, toPgUUID(runID)); err != nil {
		close(events)
		return false, fmt.Errorf("resolve suspended run: %w", err)
	}

	// Look up the conversation so SessionStore on the agent side persists
	// messages into the right thread. For unauthenticated public callers
	// the conversation is keyed on the external chat ID, not on user_id.
	var convID pgtype.UUID
	if userID != uuid.Nil {
		conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
			AgentID:    toPgUUID(agentID),
			UserID:     toPgUUID(userID),
			Source:     "bridge",
			BridgeID:   toPgUUID(bridgeID),
			ExternalID: pgtype.Text{String: externalID, Valid: externalID != ""},
		})
		if err != nil {
			close(events)
			return false, fmt.Errorf("get conversation: %w", err)
		}
		convID = conv.ID
	} else {
		if externalID == "" {
			close(events)
			return false, fmt.Errorf("public callback requires external_id")
		}
		conv, err := q.GetConversationByExternal(ctx, dbq.GetConversationByExternalParams{
			AgentID:    toPgUUID(agentID),
			Source:     "bridge",
			ExternalID: pgtype.Text{String: externalID, Valid: true},
		})
		if err != nil {
			close(events)
			return false, fmt.Errorf("get public conversation: %w", err)
		}
		convID = conv.ID
	}

	approved := action == "approve"
	// Same CallerAccess plumbing as HandleMessage above — admin-only
	// bindings need it to survive the resume turn too.
	access := ResolveAgentAccess(ctx, q, agentID, userID)
	input := agentsdk.PromptInput{
		ConversationID: convert.PgUUIDToString(convID),
		ResumeRunID:    runIDStr,
		Approved:       &approved,
		CallerAccess:   access,
	}
	if !approved {
		// Match the web "reject" flow so the LLM has something to re-reason from.
		input.Message = "Rejected by user."
	}

	rc, newRunID, err := p.dispatcher.ForwardPrompt(ctx, agentID, input, &bridgeID)
	if err != nil {
		close(events)
		return false, fmt.Errorf("forward prompt: %w", err)
	}
	defer rc.Close()

	if _, _, _, err := StreamNDJSONResponse(rc, newRunID.String(), events); err != nil {
		return false, fmt.Errorf("stream response: %w", err)
	}
	return false, nil
}

// parseCallbackData splits "approve:<runID>" / "deny:<runID>" payloads.
func parseCallbackData(data string) (action, runID string, ok bool) {
	i := strings.IndexByte(data, ':')
	if i <= 0 || i == len(data)-1 {
		return "", "", false
	}
	action = data[:i]
	runID = data[i+1:]
	if action != "approve" && action != "deny" {
		return "", "", false
	}
	return action, runID, true
}

// transcribeVoiceNotes runs each BridgeFile marked IsVoiceNote through the
// configured transcription model and appends the resulting text to
// userMessage. Resolver / transcription failures are logged and the original
// audio files remain attached unchanged — we never drop the message.
func (p *PromptProxy) transcribeVoiceNotes(ctx context.Context, userMessage string, files []BridgeFile, keys []string) string {
	if p.resolveTranscription == nil {
		return userMessage
	}
	var (
		transcripts   []string
		resolverTried bool
		tm            model.TranscriptionModel
	)
	for i := range files {
		if !files[i].IsVoiceNote {
			continue
		}
		if !resolverTried {
			resolverTried = true
			var err error
			tm, err = p.resolveTranscription(ctx)
			if err != nil {
				if !errors.Is(err, ErrTranscriptionNotConfigured) {
					p.logger.Warn("transcription resolve failed — attaching audio without transcript",
						zap.Error(err))
				}
				return userMessage
			}
		}
		audioBytes, filename, mime, tErr := audio.NormalizeForSTT(ctx, files[i].Data, files[i].Filename, files[i].ContentType)
		if tErr != nil {
			p.logger.Warn("voice transcode failed — sending original bytes",
				zap.String("filename", files[i].Filename),
				zap.Error(tErr))
		}
		result, err := tm.Transcribe(ctx, model.TranscribeCallOptions{
			Audio:    audioBytes,
			MimeType: mime,
			Filename: filename,
		})
		if err != nil {
			p.logger.Warn("transcription failed — attaching audio without transcript",
				zap.String("filename", files[i].Filename),
				zap.Error(err))
			continue
		}
		if result != nil && result.Text != "" {
			// Tag each transcript with its source key so the LLM can link
			// the text back to the attached audio file (e.g. to re-listen
			// via attachToContext if tone or language matters).
			transcripts = append(transcripts,
				fmt.Sprintf("[Voice note auto-transcript — source: %q]\n%s", keys[i], result.Text))
		}
	}
	if len(transcripts) == 0 {
		return userMessage
	}
	joined := strings.Join(transcripts, "\n")
	if userMessage == "" {
		return joined
	}
	return userMessage + "\n" + joined
}

// buildAgentStatusContext queries agent connections and webhooks,
// returns a status string for the LLM. Empty when everything is configured.
func (p *PromptProxy) buildAgentStatusContext(ctx context.Context, agentID uuid.UUID) string {
	q := dbq.New(p.db.Pool())
	pgID := toPgUUID(agentID)

	var sections []string

	// Connections needing setup (no credentials).
	conns, _ := q.ListConnectionsByAgent(ctx, pgID)
	for _, c := range conns {
		if c.AccessTokenRef == "" {
			sections = append(sections, fmt.Sprintf(
				"- Connection %q needs authorization. The user should visit: %s",
				c.Name, c.AuthUrl))
		}
	}

	// Webhooks that haven't received events yet.
	webhooks, _ := q.ListWebhooksByAgentWithStatus(ctx, pgID)
	for _, wh := range webhooks {
		if !wh.LastReceivedAt.Valid {
			sections = append(sections, fmt.Sprintf(
				"- Webhook %q has not received events yet. Setup instructions should be available in the agent's configuration page.",
				wh.Path))
		}
	}

	if len(sections) == 0 {
		return ""
	}

	return "The following setup items need attention for this agent:\n" +
		strings.Join(sections, "\n") +
		"\n\nIf the user asks about functionality that depends on these, let them know what needs to be configured."
}

// truncate clips s to at most maxLen *bytes*, backing off to the
// previous UTF-8 rune boundary so a multi-byte sequence (e.g. Cyrillic,
// emoji) is never split. A naive s[:maxLen] would leave a dangling lead
// byte that Postgres rejects with `invalid byte sequence for encoding
// "UTF8"` when the result lands in a text column. Mirrors the helper in
// api/conversations.go — kept in both packages because the call sites
// are otherwise unrelated and a single shared util isn't worth the
// import dependency.
// wrapReferencedMessage prepends a tagged context block describing a
// reply target or forwarded message, so the LLM can distinguish that
// content from the asker's own prompt. Returns userMessage unchanged
// when there's nothing to wrap.
func wrapReferencedMessage(userMessage string, ref *BridgeReferencedMessage) string {
	if ref == nil || ref.Text == "" {
		return userMessage
	}
	kind := ref.Kind
	if kind == "" {
		kind = BridgeReferenceReply
	}
	var attrs strings.Builder
	attrs.WriteString(`kind="`)
	attrs.WriteString(kind)
	attrs.WriteString(`"`)
	if ref.SenderName != "" {
		attrs.WriteString(` from="`)
		attrs.WriteString(ref.SenderName)
		attrs.WriteString(`"`)
	}
	if !ref.AuthoredAt.IsZero() {
		attrs.WriteString(` at="`)
		attrs.WriteString(ref.AuthoredAt.UTC().Format(time.RFC3339))
		attrs.WriteString(`"`)
	}
	var b strings.Builder
	b.WriteString("<referenced_message ")
	b.WriteString(attrs.String())
	b.WriteString(">\n")
	b.WriteString(ref.Text)
	b.WriteString("\n</referenced_message>\n\n")
	b.WriteString(userMessage)
	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	for end := maxLen; end > 0; end-- {
		if utf8.RuneStart(s[end]) {
			return s[:end]
		}
	}
	return ""
}

// --- NDJSON streaming ---

type usageInfo struct {
	PromptTokens     int
	CompletionTokens int
}

// StreamNDJSONResponse reads NDJSON events from a response stream, forwards
// ResponseEvents to the events channel for real-time delivery, and collects
// the full text response. Closes the events channel when done. runID is
// stamped onto confirmation_required events so drivers can build
// callback-bound UI (e.g. Telegram inline keyboards).
func StreamNDJSONResponse(body io.Reader, runID string, events chan<- ResponseEvent) (string, []message.Message, *usageInfo, error) {
	defer close(events)

	scanner := bufio.NewScanner(body)
	// A single NDJSON event can embed base64 file content (e.g. image tool
	// results). Match api/event_publisher.go's ceiling so the bridge stream
	// doesn't error on what the web path happily passes through.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	var sb strings.Builder
	var usage *usageInfo
	var newMessages []message.Message

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}

		switch event.Type {
		case "text-delta":
			var delta struct {
				Text string `json:"text"`
			}
			json.Unmarshal(event.Data, &delta)
			sb.WriteString(delta.Text)
			events <- ResponseEvent{Type: "text-delta", Text: delta.Text}

		case "messages":
			var msgs []message.Message
			if json.Unmarshal(event.Data, &msgs) == nil {
				newMessages = msgs
			}

		case "tool-call":
			var tc struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Input      json.RawMessage `json:"input"`
			}
			json.Unmarshal(event.Data, &tc)
			events <- ResponseEvent{
				Type:       "tool-call",
				ToolCallID: tc.ToolCallID,
				ToolName:   tc.ToolName,
				ToolInput:  string(tc.Input),
			}

		case "tool-result":
			var tr struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Output     json.RawMessage `json:"output"`
			}
			json.Unmarshal(event.Data, &tr)
			// tr.Output is the serialized tool.Result ({"output": "...",
			// "attachments": [...], ...}). Unwrap the inner string so bridges
			// see just the tool's text output — and so JSON-encoded newlines
			// (\n) are restored to real newlines by the decoder.
			output := string(tr.Output)
			var unwrapped struct {
				Output string `json:"output"`
			}
			if json.Unmarshal(tr.Output, &unwrapped) == nil {
				output = unwrapped.Output
			}
			events <- ResponseEvent{
				Type:       "tool-result",
				ToolCallID: tr.ToolCallID,
				ToolName:   tr.ToolName,
				ToolOutput: output,
			}

		case "tool-error":
			var te struct {
				ToolCallID string `json:"toolCallId"`
				ToolName   string `json:"toolName"`
				Error      string `json:"error"`
			}
			json.Unmarshal(event.Data, &te)
			events <- ResponseEvent{
				Type:       "tool-error",
				ToolCallID: te.ToolCallID,
				ToolName:   te.ToolName,
				ToolError:  te.Error,
			}

		case "confirmation_required":
			var cr struct {
				Permission string   `json:"permission"`
				Patterns   []string `json:"patterns"`
				Code       string   `json:"code"`
				ToolCallID string   `json:"toolCallId"`
			}
			json.Unmarshal(event.Data, &cr)
			events <- ResponseEvent{
				Type:       "confirmation_required",
				Raw:        line,
				RunID:      runID,
				Permission: cr.Permission,
				Patterns:   cr.Patterns,
				Code:       cr.Code,
				ToolCallID: cr.ToolCallID,
			}

		case "finish":
			// goai emits ai-sdk v3 usage: inputTokens.total / outputTokens.total
			// are the canonical totals; fields are optional so tolerate
			// null/missing by zero-initializing.
			var finish struct {
				Usage struct {
					InputTokens struct {
						Total *int `json:"total"`
					} `json:"inputTokens"`
					OutputTokens struct {
						Total *int `json:"total"`
					} `json:"outputTokens"`
				} `json:"usage"`
			}
			json.Unmarshal(event.Data, &finish)
			ui := &usageInfo{}
			if t := finish.Usage.InputTokens.Total; t != nil {
				ui.PromptTokens = *t
			}
			if t := finish.Usage.OutputTokens.Total; t != nil {
				ui.CompletionTokens = *t
			}
			usage = ui

		case "error":
			// The agent writes `{"error": "..."}` (goai stream convention); tolerate
			// `{"message": "..."}` too. Matches api/event_publisher.go.
			var errEvent struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			json.Unmarshal(event.Data, &errEvent)
			msg := errEvent.Error
			if msg == "" {
				msg = errEvent.Message
			}
			return "", nil, nil, fmt.Errorf("agent error: %s", msg)
		}
	}

	return sb.String(), newMessages, usage, scanner.Err()
}
