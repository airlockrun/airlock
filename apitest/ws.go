package apitest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/realtime"
	"github.com/coder/websocket"
)

// WSClient is a test-friendly wrapper around coder/websocket that
// connects to a running httptest.Server hosting the airlock router,
// authenticates with a user JWT, and exposes a Next/Drain API for
// asserting envelope sequences.
//
// The WS upgrade handler auto-subscribes the connection to every
// agent the user is a member of, so a test only needs to ensure
// membership rows exist before calling Connect.
type WSClient struct {
	conn   *websocket.Conn
	out    chan realtime.Envelope
	cancel context.CancelFunc
	t      *testing.T
}

// Connect dials srv.URL/ws?token=<jwt>[&since=<seq>], performs the
// WebSocket upgrade, and starts a background goroutine that reads
// envelopes into a buffered channel. The connection closes via
// t.Cleanup; tests do not call Close directly.
func Connect(t *testing.T, srv *httptest.Server, jwt string, since uint64) *WSClient {
	t.Helper()
	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	q := url.Values{}
	q.Set("token", jwt)
	if since > 0 {
		q.Set("since", fmt.Sprintf("%d", since))
	}
	wsURL += "?" + q.Encode()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("apitest: ws dial: %v", err)
	}

	out := make(chan realtime.Envelope, 64)
	ctx, cancel := context.WithCancel(context.Background())
	cli := &WSClient{conn: conn, out: out, cancel: cancel, t: t}

	go cli.readLoop(ctx)

	t.Cleanup(func() {
		cancel()
		_ = conn.Close(websocket.StatusNormalClosure, "test cleanup")
	})
	return cli
}

func (c *WSClient) readLoop(ctx context.Context) {
	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			close(c.out)
			return
		}
		var env realtime.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			c.t.Logf("apitest: ws decode envelope: %v (raw=%s)", err, string(data))
			continue
		}
		select {
		case c.out <- env:
		case <-ctx.Done():
			return
		}
	}
}

// Next blocks until the next envelope arrives, or fails the test on
// timeout. Use for asserting "the next event is X" semantics.
func (c *WSClient) Next(timeout time.Duration) realtime.Envelope {
	c.t.Helper()
	select {
	case env, ok := <-c.out:
		if !ok {
			c.t.Fatalf("apitest: ws closed before next envelope arrived")
		}
		return env
	case <-time.After(timeout):
		c.t.Fatalf("apitest: timeout waiting for ws envelope after %s", timeout)
		return realtime.Envelope{}
	}
}

// Drain returns every envelope that arrives within window. Use when a
// test expects a known count of events but doesn't care about exact
// ordering versus other concurrent flows.
func (c *WSClient) Drain(window time.Duration) []realtime.Envelope {
	c.t.Helper()
	deadline := time.After(window)
	var out []realtime.Envelope
	for {
		select {
		case env, ok := <-c.out:
			if !ok {
				return out
			}
			out = append(out, env)
		case <-deadline:
			return out
		}
	}
}

// WaitFor blocks until an envelope satisfying pred arrives, or fails
// the test on timeout. Earlier envelopes that don't match are
// discarded — use Drain if a test needs the full sequence.
func (c *WSClient) WaitFor(timeout time.Duration, pred func(realtime.Envelope) bool) realtime.Envelope {
	c.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case env, ok := <-c.out:
			if !ok {
				c.t.Fatalf("apitest: ws closed before predicate matched")
			}
			if pred(env) {
				return env
			}
		case <-deadline:
			c.t.Fatalf("apitest: timeout waiting for matching ws envelope")
			return realtime.Envelope{}
		}
	}
}
