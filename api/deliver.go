package api

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// postDeps holds shared dependencies for postToConversation.
type postDeps struct {
	DB         *db.DB
	PubSub     *realtime.PubSub
	BridgeMgr  bridgePartsDeliverer // nil if no bridge configured
	Dispatcher *trigger.Dispatcher  // nil if TriggerLLM not used
	S3         *storage.S3Client    // for resolving presigned URLs
	Logger     *zap.Logger
}

// postOpts configures a message post to a conversation.
type postOpts struct {
	AgentID        uuid.UUID
	ConversationID uuid.UUID
	RunID          uuid.UUID           // zero = no run linkage
	Role           string              // "assistant", "system"
	Text           string              // plain text content
	Parts          []agentsdk.DisplayPart // rich content (optional)
	Source         string              // "notification", "system", etc.
	Ephemeral      bool                // stored for UI but excluded from LLM context
	TriggerLLM     bool                // forward to agent for a response turn
	LLMMessage     string              // message text for the LLM turn (if TriggerLLM)
}

// postToConversation stores a message, delivers it via the appropriate channel
// (WebSocket or bridge), and optionally triggers an LLM turn.
func postToConversation(ctx context.Context, deps postDeps, opts postOpts) error {
	q := dbq.New(deps.DB.Pool())

	// Load conversation to determine delivery channel.
	conv, err := q.GetConversationByID(ctx, toPgUUID(opts.ConversationID))
	if err != nil {
		return err
	}

	// Build text summary if not provided.
	text := opts.Text
	if text == "" && len(opts.Parts) > 0 {
		text = extractTextSummary(opts.Parts)
	}

	// Serialize parts. If the caller passed only Text, synthesize a
	// single text DisplayPart so the WS notification carries the body —
	// otherwise the live bubble renders blank (only the persisted DB
	// row has the content) until the page is refreshed.
	parts := opts.Parts
	if len(parts) == 0 && text != "" {
		parts = []agentsdk.DisplayPart{{Type: "text", Text: text}}
	}
	var partsJSON []byte
	if len(parts) > 0 {
		partsJSON, _ = json.Marshal(parts)
	}

	// Store message in DB.
	var runID pgtype.UUID
	if opts.RunID != uuid.Nil {
		runID = toPgUUID(opts.RunID)
	}
	if _, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: toPgUUID(opts.ConversationID),
		Role:           opts.Role,
		Content:        text,
		Parts:          partsJSON,
		RunID:          runID,
		Source:         opts.Source,
		Ephemeral:      opts.Ephemeral,
	}); err != nil {
		return err
	}

	// Deliver to appropriate channel.
	isBridge := conv.Source == "bridge" && conv.BridgeID.Valid &&
		conv.ExternalID.Valid && conv.ExternalID.String != "" && deps.BridgeMgr != nil

	if isBridge {
		bridgeID := pgUUID(conv.BridgeID)
		// Resolve S3 sources to presigned URLs for bridge delivery.
		bridgeParts := resolveDisplayParts(ctx, deps.S3, deps.Logger, opts.Parts)
		if err := deps.BridgeMgr.SendParts(ctx, bridgeID, conv.ExternalID.String, bridgeParts); err != nil {
			deps.Logger.Error("bridge delivery failed", zap.Error(err))
		}
	} else {
		agentIDStr := opts.AgentID.String()
		convIDStr := opts.ConversationID.String()
		// Resolve S3 keys to presigned URLs so the browser can load media directly.
		resolvedJSON := resolveMediaPartsJSON(ctx, deps.S3, deps.Logger, partsJSON)
		_ = deps.PubSub.Publish(ctx, opts.AgentID, realtime.NewEnvelope("notification", agentIDStr, &airlockv1.NotificationEvent{
			AgentId:        agentIDStr,
			ConversationId: convIDStr,
			PartsJson:      string(resolvedJSON),
			Source:         opts.Source,
		}))
	}

	// Optionally trigger an LLM turn.
	if opts.TriggerLLM && opts.LLMMessage != "" {
		// Same CallerAccess plumbing as NotifyUpgradeComplete: resolve
		// from the conversation owner so admin-only JS bindings
		// (requestUpgrade, queryDB, execDB) survive system-injected
		// follow-up turns. Without this the agent defaults to AccessUser
		// and admin verbs ReferenceError on the next turn.
		access := trigger.ResolveAgentAccess(ctx, q, opts.AgentID, pgUUID(conv.UserID))
		input := agentsdk.PromptInput{
			Message:        opts.LLMMessage,
			ConversationID: opts.ConversationID.String(),
			Source:         opts.Source,
			CallerAccess:   access,
		}

		rc, runID, err := deps.Dispatcher.ForwardPrompt(ctx, opts.AgentID, input, nil)
		if err != nil {
			return err
		}

		if isBridge {
			// Stream response, send final text to bridge.
			respEvents := make(chan trigger.ResponseEvent, 64)
			go func() {
				for range respEvents {
				}
			}()
			responseText, _, _, _ := trigger.StreamNDJSONResponse(rc, runID.String(), respEvents)
			if responseText != "" {
				parts := []agentsdk.DisplayPart{{Type: "text", Text: responseText}}
				_ = deps.BridgeMgr.SendParts(ctx, pgUUID(conv.BridgeID), conv.ExternalID.String, parts)
			}
		} else {
			publishRunEvents(ctx, rc, deps.PubSub, opts.AgentID, runID, opts.ConversationID.String(), deps.Logger)
		}

		// Fallback status — same rationale as the web prompt path: the
		// CAS in UpdateRunStatus means the agent's terminal status wins
		// when it landed. "timeout" only sticks when the agent never
		// reported back, which is the actual semantic.
		_ = q.UpdateRunStatus(ctx, dbq.UpdateRunStatusParams{
			ID:     toPgUUID(runID),
			Status: "timeout",
		})
		costIn, costOut := runLLMCostRates(ctx, q, deps.Logger, toPgUUID(opts.AgentID))
		_ = q.UpdateRunLLMStats(ctx, dbq.UpdateRunLLMStatsParams{
			RunID:      toPgUUID(runID),
			CostInput:  costIn,
			CostOutput: costOut,
		})
	}

	return nil
}

// mediaPartNeedsPresign returns true when a part's source should be turned
// into a presigned URL. Shared by resolveDisplayParts (typed struct path,
// used for bridge delivery) and resolveMediaPartsJSON (JSON passthrough
// path, used for stored message rows) so the two can't drift on what
// qualifies as "media that needs a URL."
func mediaPartNeedsPresign(partType, source, url string) bool {
	if source == "" || url != "" {
		return false
	}
	if strings.HasPrefix(source, "http") {
		return false
	}
	switch partType {
	case "text", "tool-call", "tool-result":
		return false
	}
	return true
}

// presignSource returns a 15-minute presigned URL for the S3 key, logging
// and returning "" on failure. The empty-string return is load-bearing:
// callers treat it as "leave the part as-is," matching the behavior we had
// when the two resolver functions each contained their own try/log/continue
// block.
func presignSource(ctx context.Context, s3Client *storage.S3Client, logger *zap.Logger, source string) string {
	url, err := s3Client.PublicPresignGetURL(ctx, source, 15*time.Minute)
	if err != nil {
		logger.Error("presign S3 URL", zap.String("source", source), zap.Error(err))
		return ""
	}
	return url
}

// resolveDisplayParts converts S3 source keys to short-lived presigned URLs
// so browser or bridge clients can fetch media directly. Parts that already
// have a URL or no S3 source are returned unchanged.
func resolveDisplayParts(ctx context.Context, s3Client *storage.S3Client, logger *zap.Logger, parts []agentsdk.DisplayPart) []agentsdk.DisplayPart {
	if s3Client == nil {
		return parts
	}
	out := make([]agentsdk.DisplayPart, len(parts))
	copy(out, parts)
	for i := range out {
		p := &out[i]
		if !mediaPartNeedsPresign(p.Type, p.Source, p.URL) {
			continue
		}
		if url := presignSource(ctx, s3Client, logger, p.Source); url != "" {
			p.URL = url
		}
	}
	return out
}

// resolveMediaPartsJSON walks a JSON array of parts and presigns S3 source
// keys on media entries. Non-media parts (tool-call, tool-result) are passed
// through verbatim — deserializing into DisplayPart would strip unknown
// fields like toolCallId, toolName, and args.
func resolveMediaPartsJSON(ctx context.Context, s3Client *storage.S3Client, logger *zap.Logger, partsJSON []byte) []byte {
	if len(partsJSON) == 0 || s3Client == nil {
		return partsJSON
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(partsJSON, &raw); err != nil {
		return partsJSON
	}

	changed := false
	for i, elem := range raw {
		// Peek at the type and source to decide if this part needs resolution.
		var peek struct {
			Type   string `json:"type"`
			Source string `json:"source"`
			URL    string `json:"url"`
		}
		if json.Unmarshal(elem, &peek) != nil {
			continue
		}
		if !mediaPartNeedsPresign(peek.Type, peek.Source, peek.URL) {
			continue
		}
		url := presignSource(ctx, s3Client, logger, peek.Source)
		if url == "" {
			continue
		}
		// Patch the URL into the raw JSON element.
		var obj map[string]json.RawMessage
		if json.Unmarshal(elem, &obj) != nil {
			continue
		}
		urlBytes, _ := json.Marshal(url)
		obj["url"] = urlBytes
		patched, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		raw[i] = patched
		changed = true
	}

	if !changed {
		return partsJSON
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return partsJSON
	}
	return out
}
