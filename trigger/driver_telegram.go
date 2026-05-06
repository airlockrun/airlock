package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// TelegramDriver handles Telegram bridges via long-polling.
type TelegramDriver struct {
	httpClient *http.Client
	baseURL    string // default: "https://api.telegram.org", override for testing
	logger     *zap.Logger
}

// NewTelegramDriver creates a TelegramDriver. logger is used to surface
// Telegram API errors (notably the silent-failure Markdown/HTML parse
// rejections that otherwise vanish). Pass zap.NewNop() in tests.
func NewTelegramDriver(logger *zap.Logger) *TelegramDriver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TelegramDriver{
		httpClient: &http.Client{},
		logger:     logger,
	}
}

// NewTelegramDriverWithBaseURL creates a TelegramDriver with a custom base URL and HTTP client (for testing).
func NewTelegramDriverWithBaseURL(baseURL string, client *http.Client) *TelegramDriver {
	return &TelegramDriver{httpClient: client, baseURL: baseURL, logger: zap.NewNop()}
}

func (d *TelegramDriver) Init(ctx context.Context, br *dbq.Bridge) error {
	token := br.BotTokenRef // caller decrypts before passing to driver

	// Get the latest update offset so the first poll skips stale messages.
	updates, err := d.getUpdates(ctx, token, -1, 0)
	if err != nil {
		return nil // non-fatal
	}
	if len(updates) > 0 {
		cfg := telegramConfig{Offset: updates[len(updates)-1].UpdateID + 1}
		br.Config = mustJSON(cfg)
	}
	return nil
}

func (d *TelegramDriver) Activate(ctx context.Context, br dbq.Bridge) error {
	token := br.BotTokenRef // caller decrypts before passing to driver
	// Delete any existing webhook to ensure clean long-poll state.
	return d.callTelegram(ctx, token, "deleteWebhook", nil)
}

func (d *TelegramDriver) Teardown(_ context.Context, _ dbq.Bridge) error {
	return nil
}

// DefaultEcho reports that Telegram defaults to hiding tool bubbles: each
// tool-call / tool-result is rendered as its own chat message and a chatty
// agent quickly swamps the conversation. Users can opt in per-chat with
// `/echo on`.
func (d *TelegramDriver) DefaultEcho() bool { return false }

// RegisterCommands publishes the slash-command registry to Telegram's
// global command menu via setMyCommands. Telegram stores names without
// the leading slash.
func (d *TelegramDriver) RegisterCommands(ctx context.Context, br dbq.Bridge, cmds []SlashCommand) error {
	token := br.BotTokenRef
	tgCmds := make([]map[string]string, len(cmds))
	for i, c := range cmds {
		tgCmds[i] = map[string]string{
			"command":     c.Name,
			"description": c.Description,
		}
	}
	return d.callTelegram(ctx, token, "setMyCommands", map[string]any{
		"commands": tgCmds,
	})
}

func (d *TelegramDriver) Poll(ctx context.Context, br *dbq.Bridge) ([]BridgeEvent, error) {
	token := br.BotTokenRef // caller decrypts

	// Read offset from bridge config.
	var cfg telegramConfig
	json.Unmarshal(br.Config, &cfg)

	updates, err := d.getUpdates(ctx, token, cfg.Offset, 30)
	if err != nil {
		return nil, err
	}


	var events []BridgeEvent
	// advanceOffset must be called for EVERY update we observe — even ones we
	// can't act on — or getUpdates will keep re-delivering them forever.
	advanceOffset := func(updateID int64) {
		if updateID >= cfg.Offset {
			cfg.Offset = updateID + 1
		}
	}
	for _, u := range updates {
		// Inline-keyboard button tap — route as a BridgeCallback.
		if u.CallbackQuery != nil {
			cq := u.CallbackQuery
			// DM-only: drop callbacks from non-private chats. The bot
			// shouldn't be answering button taps in groups today.
			if cq.Message == nil || cq.Message.Chat.Type != "private" {
				advanceOffset(u.UpdateID)
				continue
			}
			events = append(events, BridgeEvent{
				BridgeID:   pgUUID(br.ID),
				ExternalID: strconv.FormatInt(cq.Message.Chat.ID, 10),
				SenderID:   strconv.FormatInt(cq.From.ID, 10),
				SenderName: cq.From.FirstName,
				Callback:   &BridgeCallback{Data: cq.Data, AckID: cq.ID},
				RawPayload: mustJSON(u),
			})
			advanceOffset(u.UpdateID)
			continue
		}

		if u.Message == nil {
			advanceOffset(u.UpdateID)
			continue
		}
		// DM-only: drop messages from groups, supergroups, channels.
		if u.Message.Chat.Type != "private" {
			advanceOffset(u.UpdateID)
			continue
		}
		ev := BridgeEvent{
			BridgeID:          pgUUID(br.ID),
			ExternalID:        strconv.FormatInt(u.Message.Chat.ID, 10),
			SenderID:          strconv.FormatInt(u.Message.From.ID, 10),
			SenderName:        u.Message.From.FirstName,
			Text:              u.Message.Text,
			ReferencedMessage: telegramReferenced(u.Message),
			RawPayload:        mustJSON(u),
		}

		// Use caption as text if message has media but no text.
		if ev.Text == "" && u.Message.Caption != "" {
			ev.Text = u.Message.Caption
		}

		// Extract photo (pick largest size).
		if len(u.Message.Photo) > 0 {
			largest := u.Message.Photo[len(u.Message.Photo)-1]
			data, err := d.downloadFile(ctx, token, largest.FileID)
			if err == nil {
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      largest.FileID,
					Filename:    "photo.jpg",
					ContentType: "image/jpeg",
					Size:        largest.FileSize,
					Data:        data,
				})
			}
		}

		// Extract document.
		if u.Message.Document != nil {
			doc := u.Message.Document
			data, err := d.downloadFile(ctx, token, doc.FileID)
			if err == nil {
				ct := doc.MimeType
				if ct == "" {
					ct = "application/octet-stream"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      doc.FileID,
					Filename:    doc.FileName,
					ContentType: ct,
					Size:        doc.FileSize,
					Data:        data,
				})
			}
		}

		// Extract voice note — tagged for auto-transcription in the bridge layer.
		if u.Message.Voice != nil {
			v := u.Message.Voice
			data, err := d.downloadFile(ctx, token, v.FileID)
			if err == nil {
				ct := v.MimeType
				if ct == "" {
					ct = "audio/ogg"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      v.FileID,
					Filename:    "voice.ogg",
					ContentType: ct,
					Size:        v.FileSize,
					Data:        data,
					IsVoiceNote: true,
				})
			}
		}

		// Extract audio file — passed through as plain attachment.
		if u.Message.Audio != nil {
			a := u.Message.Audio
			data, err := d.downloadFile(ctx, token, a.FileID)
			if err == nil {
				ct := a.MimeType
				if ct == "" {
					ct = "audio/mpeg"
				}
				name := a.FileName
				if name == "" {
					name = "audio"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      a.FileID,
					Filename:    name,
					ContentType: ct,
					Size:        a.FileSize,
					Data:        data,
				})
			}
		}

		// Extract video note — plain attachment.
		if u.Message.VideoNote != nil {
			vn := u.Message.VideoNote
			data, err := d.downloadFile(ctx, token, vn.FileID)
			if err == nil {
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      vn.FileID,
					Filename:    "video_note.mp4",
					ContentType: "video/mp4",
					Size:        vn.FileSize,
					Data:        data,
				})
			}
		}

		// Extract video — plain attachment.
		if u.Message.Video != nil {
			vid := u.Message.Video
			data, err := d.downloadFile(ctx, token, vid.FileID)
			if err == nil {
				ct := vid.MimeType
				if ct == "" {
					ct = "video/mp4"
				}
				name := vid.FileName
				if name == "" {
					name = "video.mp4"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      vid.FileID,
					Filename:    name,
					ContentType: ct,
					Size:        vid.FileSize,
					Data:        data,
				})
			}
		}

		events = append(events, ev)
		advanceOffset(u.UpdateID)
	}

	// Persist updated offset back to bridge config.
	br.Config = mustJSON(cfg)

	return events, nil
}

func (d *TelegramDriver) SendStream(ctx context.Context, br dbq.Bridge, externalID string, echo bool, events <-chan ResponseEvent) (string, error) {
	token := br.BotTokenRef
	chatID, err := strconv.ParseInt(externalID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid chat ID %q: %w", externalID, err)
	}

	// Keep a "typing…" indicator alive for the duration of the stream.
	// Telegram clears the action after ~5s or when the bot sends a message,
	// so we refresh it on a 4s ticker. Sending an initial action right away
	// makes the indicator appear before the first LLM token lands.
	stopTyping := d.keepTyping(ctx, token, chatID)
	defer stopTyping()

	var sb strings.Builder

	// flushText sends the accumulated text as a final message and resets for the next segment.
	// LLM output is markdown — convert to the HTML subset Telegram understands.
	flushText := func() {
		text := sb.String()
		if text != "" {
			_, _ = d.sendMessage(ctx, token, chatID, markdownToTelegramHTML(text))
			sb.Reset()
		}
	}

	for ev := range events {
		switch ev.Type {
		case "text-delta":
			sb.WriteString(ev.Text)

		case "tool-call":
			// When echo is off, tool-call bubbles are suppressed — in quiet
			// mode the user only sees errors and final text. Flush pending
			// text either way so it doesn't get deferred behind a tool block
			// that never renders.
			flushText()
			if echo {
				msg := formatToolCall(ev.ToolName, ev.ToolInput)
				_, _ = d.sendMessage(ctx, token, chatID, msg)
			}

		case "tool-result", "tool-error":
			// Errors always render. Successful tool-results obey echo —
			// they're the "run_js output took over my chat" noise users
			// want to silence.
			isError := ev.Type == "tool-error" || ev.ToolError != ""
			if !echo && !isError {
				continue
			}
			msg := formatToolResult(ev.ToolName, ev.ToolOutput, ev.ToolError)
			_, _ = d.sendMessage(ctx, token, chatID, msg)

		case "confirmation_required":
			flushText()
			text := formatConfirmation(ev.Permission, ev.Patterns, ev.Code)
			kb := approvalKeyboard(ev.RunID)
			_, _ = d.sendMessageWithButtons(ctx, token, chatID, text, kb)

		case "info":
			flushText()
			if ev.Text != "" {
				_, _ = d.sendMessage(ctx, token, chatID, markdownToTelegramHTML(ev.Text))
			}
		}
	}

	// Finalize remaining text.
	flushText()

	return sb.String(), nil
}

// formatToolCall formats a tool call for Telegram display (HTML parse_mode).
// Code content is wrapped in <pre> which renders as a fixed-width block and
// requires no escaping of backticks, underscores, or asterisks.
func formatToolCall(toolName, input string) string {
	var sb strings.Builder
	sb.WriteString("▶ <b>")
	sb.WriteString(html.EscapeString(toolName))
	sb.WriteString("</b>")
	if input != "" {
		// For single-arg tools, try to extract just the value.
		var args map[string]any
		if json.Unmarshal([]byte(input), &args) == nil && len(args) == 1 {
			for _, v := range args {
				sb.WriteString("\n<pre>")
				sb.WriteString(html.EscapeString(fmt.Sprint(v)))
				sb.WriteString("</pre>")
				return sb.String()
			}
		}
		sb.WriteString("\n<pre>")
		sb.WriteString(html.EscapeString(input))
		sb.WriteString("</pre>")
	}
	return sb.String()
}

// formatConfirmation renders the approval prompt body as HTML. Buttons are
// attached separately via reply_markup. Patterns are intentionally omitted
// from the UI — for run_js they're "*", and for tools where they'd be
// meaningful (bash, edit) the same info is either in the command/path
// already embedded in code or not useful to the end user reviewing.
func formatConfirmation(permission string, patterns []string, code string) string {
	_ = patterns
	var sb strings.Builder
	sb.WriteString("🔐 <b>Confirmation required</b>")
	if permission != "" {
		sb.WriteString("\nPermission: <code>")
		sb.WriteString(html.EscapeString(permission))
		sb.WriteString("</code>")
	}
	if code != "" {
		sb.WriteString("\n<pre>")
		sb.WriteString(html.EscapeString(code))
		sb.WriteString("</pre>")
	}
	return sb.String()
}

// approvalKeyboard builds the two-button inline keyboard for a suspended run.
// callback_data encodes the runID so stale taps can be detected server-side.
func approvalKeyboard(runID string) map[string]any {
	return map[string]any{
		"inline_keyboard": [][]map[string]any{
			{
				{"text": "✅ Approve", "callback_data": "approve:" + runID},
				{"text": "❌ Deny", "callback_data": "deny:" + runID},
			},
		},
	}
}

// formatToolResult formats a tool result for Telegram display (HTML parse_mode).
// output is the tool's string output (already unwrapped from tool.Result in prompt.go).
func formatToolResult(toolName, output, toolError string) string {
	if toolError != "" {
		return "✗ <b>" + html.EscapeString(toolName) + "</b>: " + html.EscapeString(toolError)
	}
	if output == "" {
		return "✓ <b>" + html.EscapeString(toolName) + "</b>"
	}
	if len(output) > 500 {
		output = output[:500] + "…"
	}
	return "✓ <b>" + html.EscapeString(toolName) + "</b>\n<pre>" + html.EscapeString(output) + "</pre>"
}

// GetMe calls the Telegram getMe API and returns the bot username.
func (d *TelegramDriver) GetMe(ctx context.Context, token string) (string, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getMe", nil, &result); err != nil {
		return "", err
	}
	if !result.OK {
		return "", fmt.Errorf("telegram getMe: not ok")
	}
	return result.Result.Username, nil
}

// TelegramChatInfo holds the subset of getChat fields we expose.
type TelegramChatInfo struct {
	Username  string
	FirstName string
	LastName  string
}

// GetChat calls the Telegram getChat API for a private chat. Because private
// chat IDs equal the user ID, this resolves a telegram user's public username
// and display name as long as that user has DM'd the bot.
func (d *TelegramDriver) GetChat(ctx context.Context, token, chatID string) (TelegramChatInfo, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getChat", map[string]string{"chat_id": chatID}, &result); err != nil {
		return TelegramChatInfo{}, err
	}
	if !result.OK {
		return TelegramChatInfo{}, fmt.Errorf("telegram getChat: not ok")
	}
	return TelegramChatInfo{
		Username:  result.Result.Username,
		FirstName: result.Result.FirstName,
		LastName:  result.Result.LastName,
	}, nil
}

// SendMessage sends a text message to a Telegram chat.
func (d *TelegramDriver) SendMessage(ctx context.Context, token string, chatID int64, text string) error {
	_, err := d.sendMessage(ctx, token, chatID, text)
	return err
}

// sendChatAction calls sendChatAction — the one-shot "typing…" indicator.
// Telegram clears it automatically after ~5 seconds or on the next outgoing
// message, so callers that want a sustained indicator must re-send it.
func (d *TelegramDriver) sendChatAction(ctx context.Context, token string, chatID int64, action string) error {
	return d.callTelegram(ctx, token, "sendChatAction", map[string]any{
		"chat_id": chatID,
		"action":  action,
	})
}

// keepTyping fires a "typing…" action immediately and then every 4 seconds
// in the background until the returned stop function is called or ctx is
// cancelled. Returns a stop closure that is safe to call multiple times.
func (d *TelegramDriver) keepTyping(ctx context.Context, token string, chatID int64) func() {
	_ = d.sendChatAction(ctx, token, chatID, "typing")

	tickCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-t.C:
				_ = d.sendChatAction(tickCtx, token, chatID, "typing")
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// SendParts sends display parts to a Telegram chat.
// Renders each part appropriately: text → sendMessage, image → sendPhoto, file → sendDocument.
func (d *TelegramDriver) SendParts(ctx context.Context, token string, chatID int64, parts []agentsdk.DisplayPart) error {
	var textBuf strings.Builder
	var lastErr error

	flush := func() {
		if textBuf.Len() > 0 {
			_, _ = d.sendMessage(ctx, token, chatID, textBuf.String())
			textBuf.Reset()
		}
	}

	for _, p := range parts {
		switch p.Type {
		case "text":
			if textBuf.Len() > 0 {
				textBuf.WriteString("\n")
			}
			textBuf.WriteString(p.Text)
		case "image":
			flush()
			caption := p.Text
			if caption == "" {
				caption = p.Alt
			}
			if len(p.Data) > 0 {
				if err := d.sendPhotoUpload(ctx, token, chatID, p.Data, p.Filename, caption); err != nil {
					lastErr = err
				}
			} else if url := firstNonEmpty(p.URL, p.Source); url != "" {
				if err := d.sendPhoto(ctx, token, chatID, url, caption); err != nil {
					lastErr = err
				}
			}
		case "file", "audio", "video":
			flush()
			if len(p.Data) > 0 {
				if err := d.sendDocumentUpload(ctx, token, chatID, p.Data, p.Filename); err != nil {
					lastErr = err
				}
			} else if url := firstNonEmpty(p.URL, p.Source); url != "" {
				if err := d.sendDocument(ctx, token, chatID, url, p.Filename); err != nil {
					lastErr = err
				}
			}
		}
	}
	flush()
	return lastErr
}

// --- Telegram API helpers ---

func (d *TelegramDriver) getUpdates(ctx context.Context, token string, offset int64, timeout int) ([]telegramUpdate, error) {
	body := map[string]any{
		"offset":  offset,
		"timeout": timeout,
	}
	var result struct {
		OK     bool             `json:"ok"`
		Result []telegramUpdate `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getUpdates", body, &result); err != nil {
		return nil, err
	}
	return result.Result, nil
}


// sendMessageDraft streams a partial message to the user (Bot API 9.3+).
func (d *TelegramDriver) sendMessageDraft(ctx context.Context, token string, chatID int64, draftID, text string) error {
	body := map[string]any{
		"business_connection_id": "", // not used, but required field structure
		"chat_id":                chatID,
		"text":                   text,
		"draft_id":               draftID,
	}
	return d.callTelegram(ctx, token, "sendMessageDraft", body)
}

// isParseError returns true if a Telegram API error is a 400 Bad Request
// caused by entity/parse failures — the signal to retry without parse_mode.
func isParseError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "status 400") &&
		(strings.Contains(s, "can't parse entities") ||
			strings.Contains(s, "can't find end of the entity") ||
			strings.Contains(s, "unsupported start tag") ||
			strings.Contains(s, "unclosed") ||
			strings.Contains(s, "Unsupported"))
}

// sendMessage sends an HTML-formatted message. On parse failure, retries
// as plain text so the user at least sees the content. Errors are logged.
func (d *TelegramDriver) sendMessage(ctx context.Context, token string, chatID int64, text string) (int64, error) {
	return d.sendMessageInner(ctx, token, chatID, text, nil)
}

// sendMessageWithButtons sends an HTML message with an attached inline keyboard.
func (d *TelegramDriver) sendMessageWithButtons(ctx context.Context, token string, chatID int64, text string, keyboard map[string]any) (int64, error) {
	return d.sendMessageInner(ctx, token, chatID, text, keyboard)
}

// sendMessageInner is the shared HTML-first, plain-text-fallback sender.
// Keyboard is attached via reply_markup when non-nil.
func (d *TelegramDriver) sendMessageInner(ctx context.Context, token string, chatID int64, text string, keyboard map[string]any) (int64, error) {
	body := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if keyboard != nil {
		body["reply_markup"] = keyboard
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}

	err := d.callTelegramJSON(ctx, token, "sendMessage", body, &result)
	if err == nil {
		return result.Result.MessageID, nil
	}

	// If HTML parsing failed, retry as plain text so the user still sees
	// the content. Log both the original failure and the retry outcome.
	if isParseError(err) {
		d.logger.Warn("telegram sendMessage HTML parse failed — retrying as plain text",
			zap.Int64("chatID", chatID),
			zap.Error(err),
			zap.String("preview", preview(text, 200)),
		)
		delete(body, "parse_mode")
		if err2 := d.callTelegramJSON(ctx, token, "sendMessage", body, &result); err2 != nil {
			d.logger.Error("telegram sendMessage plain-text fallback failed",
				zap.Int64("chatID", chatID),
				zap.Error(err2),
			)
			return 0, fmt.Errorf("plain-text fallback failed after HTML parse error: %w", err2)
		}
		return result.Result.MessageID, nil
	}

	// Non-parse error (network, 429 rate-limit, 401 auth, etc.) — log and propagate.
	d.logger.Error("telegram sendMessage failed",
		zap.Int64("chatID", chatID),
		zap.Error(err),
		zap.String("preview", preview(text, 200)),
	)
	return 0, err
}

// preview truncates a string for log lines.
func preview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AnswerCallbackQuery clears the loading spinner on a tapped inline-keyboard
// button. If text is non-empty, Telegram shows it as a transient toast.
func (d *TelegramDriver) AnswerCallbackQuery(ctx context.Context, token, callbackID, text string) error {
	body := map[string]any{"callback_query_id": callbackID}
	if text != "" {
		body["text"] = text
	}
	return d.callTelegram(ctx, token, "answerCallbackQuery", body)
}

func (d *TelegramDriver) sendPhoto(ctx context.Context, token string, chatID int64, photoURL, caption string) error {
	body := map[string]any{
		"chat_id": chatID,
		"photo":   photoURL,
	}
	if caption != "" {
		body["caption"] = markdownToTelegramHTML(caption)
		body["parse_mode"] = "HTML"
	}
	return d.callTelegram(ctx, token, "sendPhoto", body)
}

func (d *TelegramDriver) sendDocument(ctx context.Context, token string, chatID int64, documentURL, filename string) error {
	body := map[string]any{
		"chat_id":  chatID,
		"document": documentURL,
	}
	if filename != "" {
		body["caption"] = filename
	}
	return d.callTelegram(ctx, token, "sendDocument", body)
}

// sendPhotoUpload sends a photo as multipart/form-data upload (for local bytes).
func (d *TelegramDriver) sendPhotoUpload(ctx context.Context, token string, chatID int64, data []byte, filename, caption string) error {
	if filename == "" {
		filename = "photo.jpg"
	}
	return d.sendMultipart(ctx, token, "sendPhoto", chatID, "photo", data, filename, caption)
}

// sendDocumentUpload sends a document as multipart/form-data upload (for local bytes).
func (d *TelegramDriver) sendDocumentUpload(ctx context.Context, token string, chatID int64, data []byte, filename string) error {
	if filename == "" {
		filename = "file"
	}
	return d.sendMultipart(ctx, token, "sendDocument", chatID, "document", data, filename, "")
}

// sendMultipart sends a file to Telegram via multipart/form-data.
func (d *TelegramDriver) sendMultipart(ctx context.Context, token, method string, chatID int64, fieldName string, data []byte, filename, caption string) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	if caption != "" {
		w.WriteField("caption", markdownToTelegramHTML(caption))
		w.WriteField("parse_mode", "HTML")
	}
	part, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		return err
	}
	part.Write(data)
	w.Close()

	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/%s", base, token, method)

	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %s: status %d: %s", method, resp.StatusCode, string(body))
	}
	return nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// downloadFile fetches a file from Telegram by file_id.
// Uses getFile to get the file path, then downloads from the file URL.
func (d *TelegramDriver) downloadFile(ctx context.Context, token, fileID string) ([]byte, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			FilePath string `json:"file_path"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getFile", map[string]string{"file_id": fileID}, &result); err != nil {
		return nil, fmt.Errorf("getFile: %w", err)
	}
	if result.Result.FilePath == "" {
		return nil, fmt.Errorf("getFile: empty file_path")
	}

	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	fileURL := fmt.Sprintf("%s/file/bot%s/%s", base, token, result.Result.FilePath)

	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download file: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (d *TelegramDriver) callTelegram(ctx context.Context, token, method string, body any) error {
	return d.callTelegramJSON(ctx, token, method, body, nil)
}

func (d *TelegramDriver) callTelegramJSON(ctx context.Context, token, method string, body any, result any) error {
	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/%s", base, token, method)

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %s: status %d: %s", method, resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// --- Telegram types ---

type telegramConfig struct {
	Offset int64 `json:"offset"`
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	Message       *telegramMessage       `json:"message"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message"` // the message the button was attached to
	Data    string           `json:"data"`
}

type telegramMessage struct {
	MessageID      int64                 `json:"message_id"`
	Date           int64                 `json:"date"` // unix seconds
	From           telegramUser          `json:"from"`
	Chat           telegramChat          `json:"chat"`
	Text           string                `json:"text"`
	Caption        string                `json:"caption"`
	Photo          []telegramPhotoSize   `json:"photo"`
	Document       *telegramDocument     `json:"document"`
	Voice          *telegramVoice        `json:"voice"`
	Audio          *telegramAudio        `json:"audio"`
	VideoNote      *telegramVideoNote    `json:"video_note"`
	Video          *telegramVideo        `json:"video"`
	ReplyToMessage *telegramMessage      `json:"reply_to_message"`
	ForwardOrigin  *telegramForwardInfo  `json:"forward_origin"`
}

// telegramForwardInfo is the modern (Bot API 7.0+) forward_origin field.
// We only read the human-readable bits we need to render a forward
// reference; the legacy forward_from / forward_from_chat fields are
// ignored — Telegram has been emitting forward_origin alongside the
// legacy fields for years.
// telegramReferenced extracts a normalized reference (reply target or
// forward source) from an inbound message, if any. forward_origin
// (post-Bot-API-7.0) is preferred over reply_to_message — a forwarded
// message that's also a reply is rare in practice and we want the
// forward semantics in that case.
func telegramReferenced(m *telegramMessage) *BridgeReferencedMessage {
	if m == nil {
		return nil
	}
	if m.ForwardOrigin != nil {
		fo := m.ForwardOrigin
		var name string
		switch {
		case fo.SenderUser != nil:
			name = fo.SenderUser.FirstName
		case fo.SenderUserName != "":
			name = fo.SenderUserName
		case fo.AuthorSignature != "":
			name = fo.AuthorSignature
		}
		text := m.Text
		if text == "" {
			text = m.Caption
		}
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceForward,
			SenderName: name,
			Text:       text,
			AuthoredAt: time.Unix(fo.Date, 0),
		}
	}
	if m.ReplyToMessage != nil {
		ref := m.ReplyToMessage
		text := ref.Text
		if text == "" {
			text = ref.Caption
		}
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceReply,
			SenderName: ref.From.FirstName,
			Text:       text,
			AuthoredAt: time.Unix(ref.Date, 0),
		}
	}
	return nil
}

type telegramForwardInfo struct {
	Type           string        `json:"type"` // "user" | "hidden_user" | "chat" | "channel"
	Date           int64         `json:"date"`
	SenderUser     *telegramUser `json:"sender_user"`
	SenderUserName string        `json:"sender_user_name"`     // used when Type == "hidden_user"
	SenderChat     *telegramChat `json:"sender_chat"`
	AuthorSignature string       `json:"author_signature"`
}

type telegramPhotoSize struct {
	FileID   string `json:"file_id"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	FileSize int64  `json:"file_size"`
}

type telegramDocument struct {
	FileID   string `json:"file_id"`
	FileName string `json:"file_name"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
}

type telegramVoice struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
}

type telegramAudio struct {
	FileID    string `json:"file_id"`
	Duration  int    `json:"duration"`
	MimeType  string `json:"mime_type"`
	FileSize  int64  `json:"file_size"`
	FileName  string `json:"file_name"`
	Title     string `json:"title"`
	Performer string `json:"performer"`
}

type telegramVideoNote struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	FileSize int64  `json:"file_size"`
}

type telegramVideo struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
	FileName string `json:"file_name"`
}

type telegramUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
}

type telegramChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
