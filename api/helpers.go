package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/apihelpers"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/trigger"
)

// Aliases keep the existing camelCase call sites compiling unchanged
// after the wire/db plumbing moved to apihelpers/. Both api/ and
// agentapi/ alias the same exports — the underlying behaviour is
// identical; only the namespace shifted.
var (
	writeProto              = apihelpers.WriteProto
	writeError              = apihelpers.WriteError
	writeJSON               = apihelpers.WriteJSON
	writeJSONError          = apihelpers.WriteJSONError
	decodeProto             = apihelpers.DecodeProto
	readJSON                = apihelpers.ReadJSON
	parseUUID               = apihelpers.ParseUUID
	pgUUID                  = apihelpers.PgUUID
	toPgUUID                = apihelpers.ToPgUUID
	pgText                  = apihelpers.PgText
	pgInt4                  = apihelpers.PgInt4
	parseOptionalProviderID = apihelpers.ParseOptionalProviderID
	truncate                = apihelpers.TruncateUTF8
	protoMarshal            = apihelpers.ProtoMarshal
	protoUnmarshal          = apihelpers.ProtoUnmarshal
)

// writeServiceError translates a service-layer error into an HTTP
// response. Detail-wrapped errors surface their message; bare
// sentinels collapse to a generic per-status string. fallback is the
// message used when the error is neither a known sentinel nor
// detail-wrapped — typically the per-endpoint "failed to do X" line.
func writeServiceError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrNotFound), errors.Is(err, service.ErrConflict):
		if m := err.Error(); m != "invalid input" && m != "not found" && m != "conflict" {
			writeError(w, status, m)
			return
		}
	}
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "unauthorized")
	case errors.Is(err, service.ErrForbidden):
		writeError(w, status, "access denied")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "not found")
	case errors.Is(err, service.ErrInvalidInput):
		writeError(w, status, "invalid input")
	default:
		writeError(w, status, fallback)
	}
}

// notRunnableResponse maps a dispatcher "agent not in a runnable state"
// sentinel to a 409 + user-facing message. ok is false for any other
// error, so callers fall through to their generic 500 path. Shared by
// every operator-side HTTP surface that forwards a prompt/trigger to an
// agent. The A2A surface uses notRunnableMCPMessage in agentapi/ for a
// JSON-RPC-shaped variant.
func notRunnableResponse(err error) (status int, msg string, ok bool) {
	switch {
	case errors.Is(err, trigger.ErrAgentStopped):
		return http.StatusConflict, "This agent is stopped. An admin needs to start it before it can be used.", true
	case errors.Is(err, trigger.ErrAgentNoImage):
		return http.StatusConflict, "This agent hasn't finished building yet.", true
	default:
		return 0, "", false
	}
}
