package convert

import (
	"encoding/json"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

// SysConversationToProto maps a system_conversations row to the wire
// SystemConversationInfo. When the conversation is paused for tool
// approval the pending_tool field is populated from the saved
// sol.SuspensionContext checkpoint blob.
func SysConversationToProto(t dbq.SystemConversation) *airlockv1.SystemConversationInfo {
	info := &airlockv1.SystemConversationInfo{
		Id:        uuid.UUID(t.ID.Bytes).String(),
		UserId:    uuid.UUID(t.UserID.Bytes).String(),
		Title:     t.Title,
		Status:    t.Status,
		CreatedAt: PgTimestampToProto(t.CreatedAt),
		UpdatedAt: PgTimestampToProto(t.UpdatedAt),
	}
	if t.Status == "awaiting_confirmation" && len(t.Checkpoint) > 0 {
		info.PendingTool = PendingSystemToolFromCheckpoint(t.Checkpoint)
	}
	return info
}

// PendingSystemToolFromCheckpoint pulls the first pending tool call
// out of the sol.SuspensionContext JSON blob stored on the
// conversation row. The confirmation UI is one-call-at-a-time today
// (matches agent chat); if a gate ever surfaces multiple calls at
// once we'd extend PendingSystemTool to carry a list.
func PendingSystemToolFromCheckpoint(blob []byte) *airlockv1.PendingSystemTool {
	var sc struct {
		PendingToolCalls []struct {
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"pendingToolCalls"`
	}
	if err := json.Unmarshal(blob, &sc); err != nil || len(sc.PendingToolCalls) == 0 {
		return nil
	}
	first := sc.PendingToolCalls[0]
	return &airlockv1.PendingSystemTool{
		CallId:   first.ID,
		ToolName: first.Name,
		ArgsJson: string(first.Input),
	}
}

// SysMessageToProto maps one system_messages row to the wire
// SystemMessageInfo. content carries the plain-text display string;
// parts carries the goai multi-part JSON only when set (empty
// string when NULL). MessageParts.vue / ToolBadge.vue render
// system and agent surfaces identically off this shape.
func SysMessageToProto(m dbq.SystemMessage) *airlockv1.SystemMessageInfo {
	cost, _ := m.CostEstimate.Float64Value()
	return &airlockv1.SystemMessageInfo{
		Id:           uuid.UUID(m.ID.Bytes).String(),
		Seq:          m.Seq,
		Role:         m.Role,
		Source:       m.Source,
		Content:      m.Content,
		Parts:        string(m.Parts),
		TokensIn:     m.TokensIn,
		TokensOut:    m.TokensOut,
		CostEstimate: cost.Float64,
		CreatedAt:    PgTimestampToProto(m.CreatedAt),
	}
}
