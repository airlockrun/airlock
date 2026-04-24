package realtime

import (
	"encoding/json"
	"testing"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestHubRegisterUnregister(t *testing.T) {
	hub := NewHub(zap.NewNop())

	conn := &Conn{
		ID:       uuid.New().String(),
		UserID:   uuid.New(),

		send:     make(chan []byte, sendBufferSize),
	}

	hub.Register(conn)
	if hub.ConnCount() != 1 {
		t.Fatalf("expected 1 connection, got %d", hub.ConnCount())
	}

	hub.Unregister(conn)
	if hub.ConnCount() != 0 {
		t.Fatalf("expected 0 connections, got %d", hub.ConnCount())
	}
}

func TestHubSubscribeBroadcast(t *testing.T) {
	hub := NewHub(zap.NewNop())
	topicID := uuid.New()

	conn1 := &Conn{
		ID:       uuid.New().String(),
		UserID:   uuid.New(),

		send:     make(chan []byte, sendBufferSize),
	}
	conn2 := &Conn{
		ID:       uuid.New().String(),
		UserID:   uuid.New(),

		send:     make(chan []byte, sendBufferSize),
	}

	hub.Register(conn1)
	hub.Register(conn2)
	hub.Subscribe(conn1, topicID)
	hub.Subscribe(conn2, topicID)

	if hub.TopicConnCount(topicID) != 2 {
		t.Fatalf("expected 2 topic conns, got %d", hub.TopicConnCount(topicID))
	}

	env := NewEnvelope("test.event", topicID.String(), &airlockv1.SubscribedEvent{})
	hub.BroadcastToTopic(topicID, env)

	// Both connections should receive the message
	for _, conn := range []*Conn{conn1, conn2} {
		select {
		case data := <-conn.send:
			var received Envelope
			if err := json.Unmarshal(data, &received); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if received.Type != "test.event" {
				t.Fatalf("expected type test.event, got %s", received.Type)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for message")
		}
	}
}

// TestHubSubscribeAdditive verifies that Subscribe adds topics without
// removing existing ones — required because the WS accept handler calls
// Subscribe in a loop over every agent the user is a member of.
func TestHubSubscribeAdditive(t *testing.T) {
	hub := NewHub(zap.NewNop())
	topicA := uuid.New()
	topicB := uuid.New()

	conn := &Conn{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		send:   make(chan []byte, sendBufferSize),
	}

	hub.Register(conn)

	hub.Subscribe(conn, topicA)
	if hub.TopicConnCount(topicA) != 1 {
		t.Fatalf("expected 1 conn in topicA, got %d", hub.TopicConnCount(topicA))
	}

	hub.Subscribe(conn, topicB)
	if hub.TopicConnCount(topicA) != 1 {
		t.Fatalf("subscribing to B should not drop A; topicA conns = %d", hub.TopicConnCount(topicA))
	}
	if hub.TopicConnCount(topicB) != 1 {
		t.Fatalf("expected 1 conn in topicB, got %d", hub.TopicConnCount(topicB))
	}

	// Re-subscribing to a topic the conn is already in is idempotent —
	// TopicConnCount stays at 1 and there's no duplicate message on broadcast.
	hub.Subscribe(conn, topicA)
	if hub.TopicConnCount(topicA) != 1 {
		t.Fatalf("re-subscribe should be idempotent; topicA conns = %d", hub.TopicConnCount(topicA))
	}
}

// TestHubSubscriptionCallbacks verifies onFirstSubscribe fires exactly once
// per topic (when the first local conn joins) and onLastUnsubscribe fires
// when the last conn leaves via Unregister.
func TestHubSubscriptionCallbacks(t *testing.T) {
	hub := NewHub(zap.NewNop())
	topicA := uuid.New()
	topicB := uuid.New()

	firstCalls := make(map[uuid.UUID]int)
	lastCalls := make(map[uuid.UUID]int)
	hub.OnTopicSubscriptionChange(
		func(id uuid.UUID) { firstCalls[id]++ },
		func(id uuid.UUID) { lastCalls[id]++ },
	)

	conn := &Conn{
		ID:     uuid.New().String(),
		UserID: uuid.New(),
		send:   make(chan []byte, sendBufferSize),
	}

	hub.Register(conn)
	hub.Subscribe(conn, topicA)
	hub.Subscribe(conn, topicB)

	if firstCalls[topicA] != 1 || firstCalls[topicB] != 1 {
		t.Fatalf("expected onFirst once per topic, got %+v", firstCalls)
	}

	// Idempotent re-subscribe must not fire onFirst again.
	hub.Subscribe(conn, topicA)
	if firstCalls[topicA] != 1 {
		t.Fatalf("onFirst should fire once per topic, got %d for topicA", firstCalls[topicA])
	}

	hub.Unregister(conn)

	if lastCalls[topicA] != 1 || lastCalls[topicB] != 1 {
		t.Fatalf("expected onLast once per topic after unregister, got %+v", lastCalls)
	}
}

func TestHubUnregisterCleansUpTopic(t *testing.T) {
	hub := NewHub(zap.NewNop())
	topicID := uuid.New()

	var lastCalled uuid.UUID
	hub.OnTopicSubscriptionChange(nil, func(id uuid.UUID) { lastCalled = id })

	conn := &Conn{
		ID:       uuid.New().String(),
		UserID:   uuid.New(),

		send:     make(chan []byte, sendBufferSize),
	}

	hub.Register(conn)
	hub.Subscribe(conn, topicID)
	hub.Unregister(conn)

	if hub.TopicConnCount(topicID) != 0 {
		t.Fatalf("expected 0 topic conns after unregister")
	}
	if lastCalled != topicID {
		t.Fatalf("expected onLastUnsubscribe after unregister")
	}
}

func TestHubSendToConnection(t *testing.T) {
	hub := NewHub(zap.NewNop())

	conn := &Conn{
		ID:       uuid.New().String(),
		UserID:   uuid.New(),

		send:     make(chan []byte, sendBufferSize),
	}

	hub.Register(conn)

	env := NewEnvelope("direct.message", "", &airlockv1.ErrorEvent{Error: "hello"})
	hub.SendToConnection(conn.ID, env)

	select {
	case data := <-conn.send:
		var received Envelope
		if err := json.Unmarshal(data, &received); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if received.Type != "direct.message" {
			t.Fatalf("expected type direct.message, got %s", received.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}
}
