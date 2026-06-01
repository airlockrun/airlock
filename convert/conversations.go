package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// ConversationToProto maps an agent_conversations row to the wire
// ConversationInfo, defaulting an empty source to "web" so the
// frontend can always render a source chip.
//
// AgentMessage rows aren't covered here: their parts JSON may carry
// S3-keyed media references that need presigned-URL resolution
// before they're safe to ship to the client. That converter lives
// in api/conversations.go::messageToProto, alongside the S3 client
// and logger it depends on.
func ConversationToProto(c dbq.AgentConversation) *airlockv1.ConversationInfo {
	source := c.Source
	if source == "" {
		source = "web"
	}
	return &airlockv1.ConversationInfo{
		Id:        PgUUIDToString(c.ID),
		AgentId:   PgUUIDToString(c.AgentID),
		Title:     c.Title,
		Source:    source,
		CreatedAt: PgTimestampToProto(c.CreatedAt),
		UpdatedAt: PgTimestampToProto(c.UpdatedAt),
	}
}
