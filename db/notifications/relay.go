// Package notifications relays PostgreSQL wakeup hints. Durable state remains
// in PostgreSQL; subscribers must subscribe before checking it and recheck after Wait.
package notifications

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Topic string

const (
	HostWork        Topic = "airlock_host_work"
	ConnectorEvents Topic = "airlock_connector_events"
)

var ErrClosed = errors.New("notification relay closed")

type key struct {
	topic Topic
	id    uuid.UUID
}

// Relay owns one direct session, independent of request pool capacity.
type Relay struct {
	mu     sync.Mutex
	subs   map[key]map[*Subscription]struct{}
	stop   context.CancelFunc
	closed <-chan struct{}
	done   chan struct{}
}

// New starts the relay. Its owner must call Shutdown before closing the database.
func New(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) *Relay {
	if ctx == nil || pool == nil || logger == nil {
		panic("notifications: nil dependency")
	}
	ctx, stop := context.WithCancel(ctx)
	r := &Relay{subs: make(map[key]map[*Subscription]struct{}), stop: stop, closed: ctx.Done(), done: make(chan struct{})}
	config := pool.Config().ConnConfig.Copy()
	go func() {
		defer close(r.done)
		for ctx.Err() == nil {
			if err := r.listen(ctx, config); err != nil && ctx.Err() == nil {
				logger.Error("work notification listener disconnected", zap.Error(err))
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return r
}

func (r *Relay) Shutdown(ctx context.Context) error {
	r.stop()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Subscription struct {
	relay *Relay
	key   key
	wake  chan struct{}
}

func (r *Relay) Subscribe(topic Topic, id uuid.UUID) *Subscription {
	if (topic != HostWork && topic != ConnectorEvents) || id == uuid.Nil {
		panic("notifications: invalid subscription key")
	}
	s := &Subscription{relay: r, key: key{topic, id}, wake: make(chan struct{}, 1)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.subs[s.key] == nil {
		r.subs[s.key] = make(map[*Subscription]struct{})
	}
	r.subs[s.key][s] = struct{}{}
	return s
}

// Close releases this subscription; it is safe to call more than once.
func (s *Subscription) Close() {
	s.relay.mu.Lock()
	defer s.relay.mu.Unlock()
	delete(s.relay.subs[s.key], s)
	if len(s.relay.subs[s.key]) == 0 {
		delete(s.relay.subs, s.key)
	}
}

// Wait returns on a keyed hint or periodic reconciliation, cancellation, or
// relay shutdown. Hints coalesce, so every successful return requires a DB read.
func (s *Subscription) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.relay.closed:
		return ErrClosed
	default:
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.relay.closed:
		return ErrClosed
	case <-s.wake:
		return nil
	case <-timer.C:
		return nil
	}
}

func (r *Relay) signal(k key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s := range r.subs[k] {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (r *Relay) listen(ctx context.Context, config *pgx.ConnConfig) error {
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.Close(cleanup)
	}()
	if _, err := conn.Exec(ctx, "LISTEN airlock_host_work; LISTEN airlock_connector_dispatch; LISTEN airlock_connector_events"); err != nil {
		return err
	}
	// A reconnect can miss commits. Wake existing subscribers for reconciliation.
	r.mu.Lock()
	for _, subscribers := range r.subs {
		for s := range subscribers {
			select {
			case s.wake <- struct{}{}:
			default:
			}
		}
	}
	r.mu.Unlock()
	q := dbq.New(conn)
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		id, err := uuid.Parse(n.Payload)
		if err != nil || id == uuid.Nil {
			continue
		}
		if n.Channel == "airlock_connector_dispatch" {
			connector, err := q.GetConnectorResource(ctx, pgtype.UUID{Bytes: id, Valid: true})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			r.signal(key{HostWork, uuid.UUID(connector.HostID.Bytes)})
		} else {
			r.signal(key{Topic(n.Channel), id})
		}
	}
}
