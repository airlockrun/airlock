package agentapi

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/apihelpers"
	"github.com/airlockrun/airlock/trigger"
)

// Aliases keep the moved handlers' camelCase call sites compiling
// unchanged after the wire/db plumbing moved to apihelpers/. Mirrors
// the same block in api/helpers.go.
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

// notRunnableMCPMessage is the A2A/MCP surface's counterpart to
// api.notRunnableResponse — a caller-facing JSON-RPC error message
// naming the target agent when its container can't accept traffic.
// notRunnable is false for any other error.
func notRunnableMCPMessage(err error, targetSlug string) (msg string, notRunnable bool) {
	switch {
	case errors.Is(err, trigger.ErrAgentStopped):
		return "target agent \"" + targetSlug + "\" is stopped; an admin must start it before it can be called", true
	case errors.Is(err, trigger.ErrAgentNoImage):
		return "target agent \"" + targetSlug + "\" has not finished building yet", true
	default:
		return "", false
	}
}

// Silence go vet's "imported and not used" warning when no agent
// handler in this file references http directly — the var block
// above hides the http types behind aliases. The `_` keeps the
// import in the build graph even on stripped-down toolchains that
// would otherwise prune it.
var _ = http.StatusOK
