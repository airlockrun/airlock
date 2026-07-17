package apitest_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestIntegration_Subdomain drives the SubdomainProxy chain end to end.
//
//   - subtest "registered route forwards to upstream": an agent_routes
//     row exists; a request to {slug}.apitest.local/api/hello reaches
//     the upstream fake and the response body propagates back.
//   - subtest "unregistered path returns 404": a request for a path the
//     agent never registered yields 404 (the branch I just gave a
//     zap-aware logger). Asserts the path went through the proxy by
//     ensuring it does NOT 404 at the platform-API router (no
//     /api/hello on chi).
func TestIntegration_Subdomain(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{
		OwnerID:           owner,
		Slug:              "subdom",
		AllowPublicRoutes: true,
	})

	// Upstream: mirror the request path so we can assert it survived.
	upstream := http.NewServeMux()
	upstream.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Upstream", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hi from upstream"))
	})
	upstream.HandleFunc("/prompt", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "prompt should not be hit by subdomain test", http.StatusInternalServerError)
	})
	h.FakeContainers.RegisterAgent(agentID, upstream, "")

	// Register a public route for the agent.
	if err := dbq.New(h.DB.Pool()).UpsertRoute(t.Context(), dbq.UpsertRouteParams{
		AgentID:     pgtype.UUID{Bytes: agentID, Valid: true},
		Path:        "/api/hello",
		Method:      http.MethodGet,
		Access:      "public",
		Description: "apitest hello route",
	}); err != nil {
		t.Fatalf("UpsertRoute: %v", err)
	}

	t.Run("registered route forwards to upstream", func(t *testing.T) {
		req := h.NewSubdomainRequest(http.MethodGet, "subdom", "/api/hello", "", nil)
		resp := h.Do(req)
		body := h.ReadBody(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Test-Upstream") != "1" {
			t.Fatalf("X-Test-Upstream missing; response not from upstream. body=%s", body)
		}
		if string(body) != "hi from upstream" {
			t.Errorf("body = %q; want %q", body, "hi from upstream")
		}
	})

	t.Run("unregistered path returns 404", func(t *testing.T) {
		req := h.NewSubdomainRequest(http.MethodGet, "subdom", "/no/such/path", "", nil)
		resp := h.Do(req)
		body := h.ReadBody(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}
		// The subdomain proxy wrote {"error":"route not found"...}; the
		// platform router would have written {"error":"not found"} via
		// chi's default. Distinguishing by body keeps this assertion
		// future-proof against status-code drift on chi-side 404s.
		if !strings.Contains(string(body), "route not found") {
			t.Errorf("expected proxy 404 body, got: %s", body)
		}
	})

	t.Run("unknown slug returns 404", func(t *testing.T) {
		req := h.NewSubdomainRequest(http.MethodGet, "no-such-agent", "/anything", "", nil)
		resp := h.Do(req)
		body := h.ReadBody(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "agent not found") {
			t.Errorf("expected agent-not-found body, got: %s", body)
		}
	})
}
