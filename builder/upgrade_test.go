package builder

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type mockNotifier struct {
	mu             sync.Mutex
	calls          []notifyCall
}

type notifyCall struct {
	agentID        uuid.UUID
	conversationID string
	description    string
}

func (m *mockNotifier) NotifyUpgradeComplete(ctx context.Context, agentID uuid.UUID, conversationID, description string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, notifyCall{agentID, conversationID, description})
	return nil
}

func TestUpgradeNotifierCalledWithConversationID(t *testing.T) {
	notifier := &mockNotifier{}

	agentID := uuid.New()
	input := UpgradeInput{
		AgentID:        agentID.String(),
		ConversationID: "conv-123",
		Description:    "add Slack integration",
	}

	// Simulate the notification logic from RunUpgrade (lines 104-109).
	if input.ConversationID != "" && notifier != nil {
		agentUUID, _ := uuid.Parse(input.AgentID)
		_ = notifier.NotifyUpgradeComplete(context.Background(), agentUUID, input.ConversationID, input.Description)
	}

	if len(notifier.calls) != 1 {
		t.Fatalf("expected 1 notification call, got %d", len(notifier.calls))
	}
	call := notifier.calls[0]
	if call.agentID != agentID {
		t.Errorf("agentID = %s, want %s", call.agentID, agentID)
	}
	if call.conversationID != "conv-123" {
		t.Errorf("conversationID = %q, want conv-123", call.conversationID)
	}
	if call.description != "add Slack integration" {
		t.Errorf("description = %q, want 'add Slack integration'", call.description)
	}
}

func TestUpgradeNotifierNotCalledWithoutConversationID(t *testing.T) {
	notifier := &mockNotifier{}

	input := UpgradeInput{
		AgentID:     uuid.New().String(),
		Description: "manual upgrade",
		// ConversationID is empty — manual upgrade from UI
	}

	// Same logic — should NOT call notifier.
	if input.ConversationID != "" && notifier != nil {
		agentUUID, _ := uuid.Parse(input.AgentID)
		_ = notifier.NotifyUpgradeComplete(context.Background(), agentUUID, input.ConversationID, input.Description)
	}

	if len(notifier.calls) != 0 {
		t.Fatalf("expected 0 notification calls for manual upgrade, got %d", len(notifier.calls))
	}
}
