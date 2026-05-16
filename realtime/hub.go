package realtime

import (
	"encoding/json"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const topicBufferMaxSize = 100

// bufferedEvent pairs a marshaled envelope with the user_id it was
// published for. Replay applies the same env.UserID == conn.UserID
// gate that live broadcast does, so a late subscriber doesn't pick up
// events from another user's run that happened before they joined.
type bufferedEvent struct {
	seq    uint64
	data   []byte
	userID string
}

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
	topicBuffers map[uuid.UUID][]bufferedEvent

	// seq is the hub-global monotonic publish counter (stamped into
	// every Envelope under mu so buffer order == seq order).
	seq uint64

	// topicHighSeq[t] = max seq ever published to t; survives buffer
	// clear so a caught-up client short-circuits instead of resyncing.
	topicHighSeq map[uuid.UUID]uint64

	// topicDroppedUpTo[t] = highest seq no longer replayable for t
	// (evicted by the ring, or invalidated by ClearTopicBuffer). A
	// client whose cursor is below this missed an unrecoverable event
	// and must resync rather than receive a partial replay.
	topicDroppedUpTo map[uuid.UUID]uint64

	mu sync.RWMutex

	logger *zap.Logger

	// Callbacks for topic subscription changes (used by PubSub)
	onFirstSubscribe  func(topicID uuid.UUID)
	onLastUnsubscribe func(topicID uuid.UUID)
}

// NewHub creates a new Hub.
func NewHub(logger *zap.Logger) *Hub {
	return &Hub{
		conns:            make(map[string]*Conn),
		topics:           make(map[uuid.UUID]map[string]*Conn),
		connTopics:       make(map[string]map[uuid.UUID]struct{}),
		topicBuffers:     make(map[uuid.UUID][]bufferedEvent),
		topicHighSeq:     make(map[uuid.UUID]uint64),
		topicDroppedUpTo: make(map[uuid.UUID]uint64),
		logger:           logger,
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

	// Cursor replay. since == conn.SinceSeq is the max seq the client
	// has already processed (0 on a fresh connect / page reload).
	//   - fresh, or topic silent, or client caught up → nothing (the
	//     client's normal initial DB load is the source of truth).
	//   - cursor below what's still replayable (ring evicted it, or
	//     ClearTopicBuffer invalidated it) → resync: the client
	//     refetches authoritative state from the DB for this topic.
	//   - otherwise → replay exactly the buffered tail seq>since.
	// Never a partial replay across a gap; never the old 100×N flood.
	since := conn.SinceSeq
	hi := h.topicHighSeq[topicID]
	dropped := h.topicDroppedUpTo[topicID]
	var replay []bufferedEvent
	resync := false
	switch {
	case since == 0 || hi == 0 || since >= hi:
		// nothing to do
	case since < dropped || len(h.topicBuffers[topicID]) == 0:
		resync = true
	default:
		for _, ev := range h.topicBuffers[topicID] {
			if ev.seq > since {
				replay = append(replay, ev)
			}
		}
	}

	onFirst := h.onFirstSubscribe
	h.mu.Unlock()

	if resync {
		conn.SendEnvelope(Envelope{Type: "resync", TopicID: topicID.String()})
	} else {
		// Same user_id gate as live broadcast — see BroadcastToTopic.
		connUserID := conn.UserID.String()
		for _, ev := range replay {
			if ev.userID != "" && ev.userID != connUserID {
				continue
			}
			conn.Send(ev.data)
		}
	}

	if isFirst && onFirst != nil {
		onFirst(topicID)
	}
}

// BroadcastToTopic sends an envelope to all connections subscribed to a topic.
//
// User-id gating: if env.UserID is set, only connections whose
// authenticated user matches receive the event. Empty env.UserID
// falls through to the historical "deliver to every subscriber"
// behaviour (used for tenant-wide / system broadcasts:
// agent.synced, build events, etc).
//
// The replay buffer stores (bytes, userID) pairs so a late
// subscriber gets the same gate applied on replay — without it,
// joining late would leak events from other users' runs that
// happened before the join.
func (h *Hub) BroadcastToTopic(topicID uuid.UUID, env Envelope) {
	h.mu.Lock()
	// Stamp the hub-global seq and marshal under the same lock as the
	// buffer append, so buffer order == seq order with no torn races.
	h.seq++
	s := h.seq
	env.Seq = s
	data, err := json.Marshal(env)
	if err != nil {
		h.mu.Unlock()
		h.logger.Error("failed to marshal envelope", zap.Error(err))
		return
	}
	h.topicHighSeq[topicID] = s

	// Buffer the event for cursor replay on late/reconnecting subscribe.
	buf := h.topicBuffers[topicID]
	if len(buf) >= topicBufferMaxSize {
		// The evicted event is no longer replayable; a client whose
		// cursor is below it must resync rather than get a partial tail.
		h.topicDroppedUpTo[topicID] = buf[0].seq
		buf = buf[1:]
	}
	h.topicBuffers[topicID] = append(buf, bufferedEvent{seq: s, data: data, userID: env.UserID})

	conns := h.topics[topicID]
	targets := make([]*Conn, 0, len(conns))
	for _, c := range conns {
		targets = append(targets, c)
	}
	h.mu.Unlock()

	for _, c := range targets {
		if env.UserID != "" && env.UserID != c.UserID.String() {
			continue
		}
		c.Send(data)
	}
}

// ClearTopicBuffer removes the replay buffer for a topic.
// Called after a terminal event (build complete/failed) since replay is no longer needed.
func (h *Hub) ClearTopicBuffer(topicID uuid.UUID) {
	h.mu.Lock()
	// Everything up to the current high-water is no longer replayable;
	// a client behind it resyncs, a caught-up client (since>=hi) still
	// short-circuits. Keep topicHighSeq so that short-circuit holds.
	if hi := h.topicHighSeq[topicID]; hi > 0 {
		h.topicDroppedUpTo[topicID] = hi
	}
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
