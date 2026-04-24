package realtime

import (
	"encoding/json"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const topicBufferMaxSize = 100

// Hub manages WebSocket connections and topic subscriptions. A single
// connection can be subscribed to many topics at once — typically every
// agent the user is a member of, wired up at WS-accept time.
type Hub struct {
	// connections by ID
	conns map[string]*Conn

	// topic subscriptions: topicID → set of connIDs
	topics map[uuid.UUID]map[string]*Conn

	// reverse index: connID → set of topics this connection is subscribed to.
	connTopics map[string]map[uuid.UUID]struct{}

	// replay buffer: recent messages per topic, replayed on subscribe
	topicBuffers map[uuid.UUID][][]byte

	mu sync.RWMutex

	logger *zap.Logger

	// Callbacks for topic subscription changes (used by PubSub)
	onFirstSubscribe  func(topicID uuid.UUID)
	onLastUnsubscribe func(topicID uuid.UUID)
}

// NewHub creates a new Hub.
func NewHub(logger *zap.Logger) *Hub {
	return &Hub{
		conns:        make(map[string]*Conn),
		topics:       make(map[uuid.UUID]map[string]*Conn),
		connTopics:   make(map[string]map[uuid.UUID]struct{}),
		topicBuffers: make(map[uuid.UUID][][]byte),
		logger:       logger,
	}
}

// OnTopicSubscriptionChange sets callbacks for when the first local connection
// subscribes to a topic and when the last unsubscribes. Used by PubSub to
// manage Redis subscriptions.
func (h *Hub) OnTopicSubscriptionChange(onFirst func(uuid.UUID), onLast func(uuid.UUID)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onFirstSubscribe = onFirst
	h.onLastUnsubscribe = onLast
}

// Register adds a connection to the hub.
func (h *Hub) Register(conn *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns[conn.ID] = conn
	h.connTopics[conn.ID] = make(map[uuid.UUID]struct{})
}

// Unregister removes a connection and all its topic subscriptions, firing
// onLastUnsubscribe for any topic that's now empty.
func (h *Hub) Unregister(conn *Conn) {
	h.mu.Lock()
	var emptiedTopics []uuid.UUID

	for topicID := range h.connTopics[conn.ID] {
		if topicConns, exists := h.topics[topicID]; exists {
			delete(topicConns, conn.ID)
			if len(topicConns) == 0 {
				delete(h.topics, topicID)
				emptiedTopics = append(emptiedTopics, topicID)
			}
		}
	}
	delete(h.connTopics, conn.ID)
	delete(h.conns, conn.ID)

	onLast := h.onLastUnsubscribe
	h.mu.Unlock()

	if onLast != nil {
		for _, t := range emptiedTopics {
			onLast(t)
		}
	}
}

// Subscribe adds the connection to the given topic if not already subscribed.
// Pre-existing topic subscriptions on this connection are not affected —
// Subscribe is additive, so the WS accept handler can call it in a loop over
// the user's member agents without disturbing anything else.
// Replays any buffered events for the topic to the newly-subscribed connection.
func (h *Hub) Subscribe(conn *Conn, topicID uuid.UUID) {
	h.mu.Lock()

	if _, ok := h.connTopics[conn.ID][topicID]; ok {
		// Idempotent: already subscribed. Skip replay to avoid duplicate events.
		h.mu.Unlock()
		return
	}

	topicConns, exists := h.topics[topicID]
	if !exists {
		topicConns = make(map[string]*Conn)
		h.topics[topicID] = topicConns
	}
	isFirst := len(topicConns) == 0
	topicConns[conn.ID] = conn
	if h.connTopics[conn.ID] == nil {
		h.connTopics[conn.ID] = make(map[uuid.UUID]struct{})
	}
	h.connTopics[conn.ID][topicID] = struct{}{}

	// Copy buffered events for replay.
	var replay [][]byte
	if buf := h.topicBuffers[topicID]; len(buf) > 0 {
		replay = make([][]byte, len(buf))
		copy(replay, buf)
	}

	onFirst := h.onFirstSubscribe
	h.mu.Unlock()

	for _, msg := range replay {
		conn.Send(msg)
	}

	if isFirst && onFirst != nil {
		onFirst(topicID)
	}
}

// BroadcastToTopic sends an envelope to all connections subscribed to a topic.
// Events are also buffered per topic so late subscribers can replay missed events.
func (h *Hub) BroadcastToTopic(topicID uuid.UUID, env Envelope) {
	data, err := json.Marshal(env)
	if err != nil {
		h.logger.Error("failed to marshal envelope", zap.Error(err))
		return
	}

	h.mu.Lock()
	// Buffer the event for replay on late subscribe.
	buf := h.topicBuffers[topicID]
	if len(buf) >= topicBufferMaxSize {
		buf = buf[1:]
	}
	h.topicBuffers[topicID] = append(buf, data)

	conns := h.topics[topicID]
	targets := make([]*Conn, 0, len(conns))
	for _, c := range conns {
		targets = append(targets, c)
	}
	h.mu.Unlock()

	for _, c := range targets {
		c.Send(data)
	}
}

// ClearTopicBuffer removes the replay buffer for a topic.
// Called after a terminal event (build complete/failed) since replay is no longer needed.
func (h *Hub) ClearTopicBuffer(topicID uuid.UUID) {
	h.mu.Lock()
	delete(h.topicBuffers, topicID)
	h.mu.Unlock()
}

// SendToConnection sends an envelope to a specific connection by ID.
func (h *Hub) SendToConnection(connID string, env Envelope) {
	h.mu.RLock()
	conn, ok := h.conns[connID]
	h.mu.RUnlock()
	if !ok {
		return
	}
	conn.SendEnvelope(env)
}

// ConnCount returns the number of active connections.
func (h *Hub) ConnCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// TopicConnCount returns the number of connections subscribed to a topic.
func (h *Hub) TopicConnCount(topicID uuid.UUID) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.topics[topicID])
}
