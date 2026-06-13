package agentapi

import (
	"net/http"

	"github.com/airlockrun/agentsdk"
)

var (
	readJSON  = func(r *http.Request, v any) error { return nil }
	writeJSON = func(w http.ResponseWriter, status int, v any) {}
)

// Forbidden: locally declared wire shape.
type localSealRequest struct {
	Plaintext string `json:"plaintext"`
}

func badRead(r *http.Request) {
	var req localSealRequest
	_ = readJSON(r, &req) // want `readJSON body uses type localSealRequest declared in agentapi/.*`
}

func badWrite(w http.ResponseWriter) {
	writeJSON(w, 200, localSealRequest{Plaintext: "x"}) // want `writeJSON body uses type localSealRequest declared in agentapi/.*`
}

// OK: type from agentsdk.
func okRead(r *http.Request) {
	var req agentsdk.SealRequest
	_ = readJSON(r, &req)
}

func okWrite(w http.ResponseWriter) {
	writeJSON(w, 200, agentsdk.SealResponse{Sealed: "x"})
}

// OK: anonymous shape — error envelopes, ad-hoc acks, etc.
func okAnonymous(w http.ResponseWriter) {
	writeJSON(w, 400, map[string]string{"error": "no"})
}

// OK: opt-out annotation.
func allowedLocal(r *http.Request) {
	var req localSealRequest
	// airlockvet:allow-agentwire reason: vendored handler with a one-off body shape
	_ = readJSON(r, &req)
}
