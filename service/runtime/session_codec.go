package runtime

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/sol/session"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// cleanupOrphanedAttachments scans the conversation's messages and deletes
// llm/ blobs referenced only in pre-checkpoint messages. Safe to call
// repeatedly — S3 DeleteObject is idempotent on missing keys. Runs
// synchronously for the scan, hands deletes to attachref.ScheduleDelete
// (which detaches to its own goroutine).
func (h *Service) CleanupOrphanedAttachments(ctx context.Context, agentID string, convID pgtype.UUID, checkpointID pgtype.UUID) {
	q := dbq.New(h.db.Pool())

	rows, err := q.ListAllMessagesByConversation(ctx, convID)
	if err != nil {
		h.logger.Warn("session compact cleanup: list messages failed", zap.Error(err))
		return
	}

	// Locate the new checkpoint — everything older becomes retired.
	var checkpointTime pgtype.Timestamptz
	for _, m := range rows {
		if m.ID == checkpointID {
			checkpointTime = m.CreatedAt
			break
		}
	}
	if !checkpointTime.Valid {
		return
	}

	liveKeys := make(map[string]struct{})
	var retired []string
	for _, m := range rows {
		if len(m.Parts) == 0 {
			continue
		}
		keys := ExtractCanonicalKeys(m.Parts, agentID)
		if m.CreatedAt.Time.Before(checkpointTime.Time) {
			retired = append(retired, keys...)
		} else {
			for _, k := range keys {
				liveKeys[k] = struct{}{}
			}
		}
	}

	toDelete := make([]string, 0, len(retired))
	for _, k := range retired {
		if _, stillLive := liveKeys[k]; stillLive {
			continue
		}
		toDelete = append(toDelete, k)
	}
	if len(toDelete) == 0 {
		return
	}
	attachref.ScheduleDelete(ctx, h.s3, h.logger, toDelete)
}

// ExtractCanonicalKeys reads `s3ref:K` sentinels from the stored goai-shaped
// parts JSON (image.image / file.data fields) and returns the canonical
// `llm/agents/<agentID>/K` keys. The sentinel survives the goai.Content
// marshal roundtrip since it's just a string in Image/Data.
func ExtractCanonicalKeys(partsJSON []byte, agentID string) []string {
	var raw []map[string]any
	if err := json.Unmarshal(partsJSON, &raw); err != nil {
		return nil
	}
	prefix := "llm/agents/" + agentID + "/"
	var out []string
	for _, p := range raw {
		typ, _ := p["type"].(string)
		var field string
		switch typ {
		case "image":
			field, _ = p["image"].(string)
		case "file":
			field, _ = p["data"].(string)
			if data, ok := p["data"].(map[string]any); ok {
				field, _ = data["data"].(string)
				if field == "" {
					field, _ = data["url"].(string)
				}
			}
		case "tool-result":
			output, _ := p["output"].(map[string]any)
			if output["type"] == "content" {
				items, _ := output["value"].([]any)
				for _, value := range items {
					item, _ := value.(map[string]any)
					kind, _ := item["type"].(string)
					if kind != "image-data" && kind != "file-data" {
						continue
					}
					data, _ := item["data"].(string)
					if key, ok := strings.CutPrefix(data, attachref.Sentinel); ok {
						out = append(out, prefix+key)
					}
				}
			}
		default:
			continue
		}
		if key, ok := strings.CutPrefix(field, attachref.Sentinel); ok {
			out = append(out, prefix+key)
		}
	}
	return out
}

// --- conversion helpers ---

// dbMessageToSession converts a DB row to a session.Message.
func DbMessageToSession(m dbq.AgentMessage) session.Message {
	// Try to parse rich parts from JSONB.
	if len(m.Parts) > 0 {
		var content message.Content
		if err := json.Unmarshal(m.Parts, &content); err == nil {
			goaiMsg := message.Message{
				Role:    message.Role(m.Role),
				Content: content,
			}
			msg := session.FromGoAIMessage(goaiMsg)
			msg.Tokens.Input, msg.Tokens.Output = int(m.ContextTokensIn.Int64), int(m.ContextTokensOut.Int64)
			// goai's FilePart doesn't carry Source, so it's dropped through
			// the JSON roundtrip. Recover it from the s3ref sentinel that
			// rides in Data so downstream consumers (sol's
			// stripOldFilesFromHistory → agentsdk's PrunedMessage callback)
			// can render a detach note that includes the re-attach key.
			for i := range msg.Parts {
				p := &msg.Parts[i]
				if p.File != nil && p.File.Source == "" {
					if key, ok := strings.CutPrefix(p.File.Data, attachref.Sentinel); ok {
						p.File.Source = key
					}
				}
			}
			return msg
		}
	}
	// Fallback: text-only message.
	return session.Message{
		Role:    m.Role,
		Content: m.Content,
		Tokens:  session.Tokens{Input: int(m.ContextTokensIn.Int64), Output: int(m.ContextTokensOut.Int64)},
	}
}

// storeSessionMessage persists a session.Message to the DB.
func StoreSessionMessage(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, runID pgtype.UUID, source string, msg session.Message) error {
	_, err := StoreSessionMessageReturningID(ctx, q, convID, runID, source, msg)
	return err
}

// storeSessionMessageReturningID persists a session.Message and returns the ID
// of the first row inserted. A single session.Message may expand into multiple
// DB rows when its parts contain tool calls + results — callers needing the
// checkpoint anchor use the first row.
func StoreSessionMessageReturningID(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, runID pgtype.UUID, source string, msg session.Message) (pgtype.UUID, error) {
	// Context observations drive compaction; billing and root budgets are separate.
	input := pgtype.Int8{Int64: int64(msg.Tokens.Input), Valid: msg.Tokens.Input != 0 || msg.Tokens.Output != 0}
	output := pgtype.Int8{Int64: int64(msg.Tokens.Output), Valid: input.Valid}
	goaiMsgs := session.MessageToGoAI(msg)
	if len(goaiMsgs) == 0 {
		row, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID:  convID,
			Role:            msg.Role,
			Content:         msg.Content,
			RunID:           runID,
			Source:          source,
			ContextTokensIn: input, ContextTokensOut: output,
		})
		if err != nil {
			return pgtype.UUID{}, err
		}
		return row.ID, nil
	}

	var firstID pgtype.UUID
	for i, goaiMsg := range goaiMsgs {
		displayText := extractSessionDisplayText(msg)
		var partsJSON []byte
		if goaiMsg.Content.IsMultiPart() {
			partsJSON, _ = json.Marshal(goaiMsg.Content)
		}

		params := dbq.CreateMessageParams{
			ConversationID: convID,
			Role:           string(goaiMsg.Role),
			Content:        displayText,
			Parts:          partsJSON,
			RunID:          runID,
			Source:         source,
		}
		// One session message may expand into several rows. Attach the observation
		// to its final boundary so earlier parts are not counted again as tail.
		if i == len(goaiMsgs)-1 {
			params.ContextTokensIn, params.ContextTokensOut = input, output
		}
		row, err := q.CreateMessage(ctx, params)
		if err != nil {
			return pgtype.UUID{}, err
		}
		if i == 0 {
			firstID = row.ID
		}
	}
	return firstID, nil
}

// extractSessionDisplayText extracts human-readable text from a session.Message.
func extractSessionDisplayText(msg session.Message) string {
	if msg.Content != "" {
		return msg.Content
	}
	var parts []string
	for _, p := range msg.Parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				parts = append(parts, p.Text)
			}
		case "tool":
			if p.Tool != nil && p.Tool.Output != "" {
				parts = append(parts, p.Tool.Output)
			}
		}
	}
	return strings.Join(parts, "")
}
