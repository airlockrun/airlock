package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// seedProvider inserts an enabled providers row for a given provider_id.
// Cleans itself up via t.Cleanup so tests can share testDB without leaks.
func seedProvider(t *testing.T, providerID, displayName string) {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	_, err := q.CreateProvider(ctx, dbq.CreateProviderParams{
		ProviderID:  providerID,
		DisplayName: displayName,
		ApiKey:      "test-encrypted",
		BaseUrl:     "",
		IsEnabled:   true,
	})
	if err != nil {
		t.Fatalf("seedProvider(%s): %v", providerID, err)
	}
	t.Cleanup(func() {
		_, _ = testDB.Pool().Exec(ctx, `DELETE FROM providers WHERE provider_id = $1`, providerID)
	})
}

func testCapabilitiesHandler() *capabilitiesHandler {
	return &capabilitiesHandler{db: testDB, logger: zap.NewNop()}
}

// TestListCapabilitiesShape runs the real handler against the in-process
// overlay + whatever models.dev snapshot is cached. It asserts the gross
// invariants without pinning every modality to a specific provider (since
// upstream data can shift): the response is non-empty, overlay-only
// providers appear, configured flags track the DB, and the response is
// sorted so configured providers come first.
func TestListCapabilitiesShape(t *testing.T) {
	skipIfNoDB(t)
	_, userID := testAgentAndUser(t)

	// Seed one configured LLM provider (openai) — we know it's in models.dev.
	seedProvider(t, "openai", "OpenAI")

	h := testCapabilitiesHandler()
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/catalog/capabilities", h.ListCapabilities)
	})

	req := userRequestJSON(t, "GET", "/api/v1/catalog/capabilities", userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.ListCapabilitiesResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(resp.Providers) == 0 {
		t.Fatal("expected at least one provider in the response")
	}

	// Find openai, brave.
	byID := map[string]*airlockv1.ProviderCapabilityInfo{}
	for _, p := range resp.Providers {
		byID[p.ProviderId] = p
	}

	openai, ok := byID["openai"]
	if !ok {
		t.Fatal("openai missing from capability response")
	}
	if !openai.Configured {
		t.Error("openai should be Configured after seedProvider")
	}
	if openai.CatalogOnly {
		t.Error("openai.CatalogOnly = true, expected false (it exists in models.dev)")
	}
	// The overlay contributes STT/TTS models and the Responses API
	// web_search tool (via ExtraCapabilities + SearchBackend="openai"), so
	// all three must be present on openai.
	for _, want := range []string{"stt", "tts", "search"} {
		found := false
		for _, c := range openai.Capabilities {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("openai capabilities missing %q; got %v", want, openai.Capabilities)
		}
	}

	brave, ok := byID["brave"]
	if !ok {
		t.Fatal("brave missing from capability response (should be synthesized from overlay)")
	}
	if !brave.CatalogOnly {
		t.Error("brave.CatalogOnly should be true (not in models.dev)")
	}
	if brave.Configured {
		t.Error("brave should not be Configured in this test")
	}
	if len(brave.Capabilities) != 1 || brave.Capabilities[0] != "search" {
		t.Errorf("brave capabilities = %v, want [search]", brave.Capabilities)
	}

	// Sort invariant: configured providers (openai) come before
	// non-configured ones.
	sawConfigured := false
	sawNonConfigured := false
	for _, p := range resp.Providers {
		if p.Configured {
			if sawNonConfigured {
				t.Errorf("configured=%s appeared after a non-configured entry — sort order broken", p.ProviderId)
			}
			sawConfigured = true
		} else {
			sawNonConfigured = true
		}
	}
	_ = sawConfigured
}
