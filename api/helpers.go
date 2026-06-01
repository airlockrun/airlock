package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/apihelpers"
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
