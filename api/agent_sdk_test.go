package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

func TestGetAgentSDKInfoIncludesAirlockURL(t *testing.T) {
	const publicURL = "https://airlock.example.com"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-sdk", nil)

	getAgentSDKInfo(publicURL).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp airlockv1.GetAgentSDKInfoResponse
	decodeProtoResp(t, rec, &resp)
	if resp.AirlockUrl != publicURL {
		t.Fatalf("airlock URL = %q, want %q", resp.AirlockUrl, publicURL)
	}
}
