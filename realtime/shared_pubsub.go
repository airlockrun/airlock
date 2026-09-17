package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const (
	sharedQueryTimeout = 5 * time.Second
	clearEventType     = "realtime.clear"
	maxEnvelopeBytes   = 1 << 20
)

type storedEvent struct {
	Seq      uint64    `json:"seq"`
	TopicID  uuid.UUID `json:"topicId"`
	Envelope Envelope  `json:"envelope"`
}

type sharedPubSub struct {
	running atomic.Bool
	pool    *pgxpool.Pool
	hub     *Hub
	logger  *zap.Logger
}

// NewSharedPubSub selects PostgreSQL delivery and replay. Run must run on every
// replica. Publishers never also broadcast locally; only the ordered relay does.
func NewSharedPubSub(pool *pgxpool.Pool, hub *Hub, logger *zap.Logger) *PubSub {
	if pool == nil || hub == nil || logger == nil {
		panic("realtime: nil shared pubsub dependency")
	}
	ps := NewPubSub(hub, logger)
	ps.shared = &sharedPubSub{pool: pool, hub: hub, logger: logger}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.shared != nil || len(hub.conns) != 0 || hub.seq != 0 {
		panic("realtime: shared transport requires an unused hub")
	}
	hub.shared = ps.shared
	return ps
}

func (s *sharedPubSub) publish(ctx context.Context, topicID uuid.UUID, env Envelope) error {
	if topicID == uuid.Nil {
		return errors.New("realtime: missing topic")
	}
	if strings.HasPrefix(env.Type, "run.") || env.Type == "notification" || env.Type == "topic.notification" {
		id, err := uuid.Parse(env.UserID)
		if err != nil || id == uuid.Nil {
			return errors.New("realtime: private event requires a user")
		}
		env.UserID = id.String()
	}
	env.TopicID, env.Seq = topicID.String(), 0
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(data) > maxEnvelopeBytes {
		return errors.New("realtime: envelope exceeds 1 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, sharedQueryTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	q := dbq.New(tx)
	head, err := q.AdvanceRealtimeEventHead(ctx, data)
	if err != nil {
		return err
	}
	if err := q.InsertRealtimeEvent(ctx, dbq.InsertRealtimeEventParams{
		Seq: head.Seq, TopicID: pgtype.UUID{Bytes: topicID, Valid: true},
		Envelope: data, BytePosition: head.BytePosition,
	}); err != nil {
		return err
	}
	if err := q.PruneRealtimeEvents(ctx); err != nil {
		return err
	}
	if err := q.NotifyRealtimeEvents(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Run uses NOTIFY only as a wake-up. Polling also catches lost notifications;
// retained envelopes are reloaded in commit order after listener interruptions.
func (ps *PubSub) Run(ctx context.Context) error {
	if ps.shared == nil {
		panic("realtime: Run requires shared pubsub")
	}
	s := ps.shared
	if !s.running.CompareAndSwap(false, true) {
		panic("realtime: shared pubsub relay is already running")
	}
	defer s.running.Store(false)
	var cursor uint64
	for ctx.Err() == nil {
		if err := s.listen(ctx, &cursor); err != nil && ctx.Err() == nil {
			s.logger.Error("realtime listener disconnected", zap.Error(err))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return nil
}

func (s *sharedPubSub) listen(ctx context.Context, cursor *uint64) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.Close(cleanup)
	}()
	if _, err := conn.Exec(ctx, "LISTEN airlock_realtime_events"); err != nil {
		return err
	}
	q := dbq.New(conn)
	lastCleanup := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastCleanup) >= time.Minute {
			// The same row lock as publishing prevents cleanup/publish deadlocks.
			tx, err := conn.Begin(ctx)
			if err != nil {
				return err
			}
			tq := dbq.New(tx)
			_, err = tq.LockRealtimeEventHead(ctx)
			if err == nil {
				err = tq.PruneRealtimeEvents(ctx)
			}
			if err == nil {
				err = tx.Commit(ctx)
			} else {
				_ = tx.Rollback(ctx)
			}
			if err != nil {
				return err
			}
			lastCleanup = time.Now()
		}
		row, err := q.ReadRealtimeEvents(ctx, dbq.ReadRealtimeEventsParams{Since: int64(*cursor), EventLimit: 256})
		if err != nil {
			return err
		}
		if *cursor < uint64(row.DroppedSeq) || *cursor > uint64(row.Seq) {
			s.hub.ResyncAll()
			*cursor = uint64(row.Seq)
		} else {
			var events []storedEvent
			if err := json.Unmarshal(row.Events, &events); err != nil {
				return fmt.Errorf("decode realtime events: %w", err)
			}
			for _, event := range events {
				s.hub.deliverStored(event)
				*cursor = event.Seq
			}
			if len(events) == 256 {
				continue
			}
		}
		wait, cancel := context.WithTimeout(ctx, time.Second)
		_, err = conn.WaitForNotification(wait)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return ctx.Err()
}

// replay runs under the hub lock, making snapshot replay and local live enqueue
// atomic. Per-subscription watermarks discard relay events covered by the snapshot.
func (s *sharedPubSub) replay(conn *Conn, topicID uuid.UUID) uint64 {
	ctx, cancel := context.WithTimeout(context.Background(), sharedQueryTimeout)
	defer cancel()
	since := conn.SinceSeq
	// SQL bigint and browser safe integers cannot represent arbitrary uint64 cursors.
	if since > 1<<53-1 {
		since = 0
	}
	row, err := dbq.New(s.pool).ReadRealtimeEvents(ctx, dbq.ReadRealtimeEventsParams{
		Since: int64(since), TopicID: pgtype.UUID{Bytes: topicID, Valid: true}, EventLimit: topicBufferMaxSize + 1,
	})
	if err != nil {
		s.logger.Error("read realtime replay", zap.Error(err))
		conn.disconnect()
		return 0
	}
	var events []storedEvent
	if err := json.Unmarshal(row.Events, &events); err != nil {
		s.logger.Error("decode realtime replay", zap.Error(err))
		conn.disconnect()
		return 0
	}
	resync := since == 0 || since < uint64(row.DroppedSeq) || since > uint64(row.Seq) || len(events) > topicBufferMaxSize
	for _, ev := range events {
		if ev.Envelope.Type == clearEventType {
			resync = true
		}
	}
	if resync {
		conn.SendEnvelope(Envelope{Type: "resync", TopicID: topicID.String(), Seq: uint64(row.Seq)})
	} else {
		for _, ev := range events {
			if ev.Envelope.Type == "topic.notification" {
				continue
			}
			if ev.Envelope.UserID != "" && ev.Envelope.UserID != conn.UserID.String() {
				continue
			}
			ev.Envelope.Seq = ev.Seq
			conn.SendEnvelope(ev.Envelope)
		}
	}
	return uint64(row.Seq)
}

func (h *Hub) deliverStored(event storedEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, conn := range h.topics[event.TopicID] {
		if event.Seq <= h.sharedCursors[conn.ID][event.TopicID] {
			continue
		}
		h.sharedCursors[conn.ID][event.TopicID] = event.Seq
		env := event.Envelope
		if env.Type == clearEventType || (env.UserID != "" && env.UserID != conn.UserID.String()) {
			continue
		}
		env.Seq = event.Seq
		conn.SendEnvelope(env)
	}
}
