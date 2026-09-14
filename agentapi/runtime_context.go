package agentapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/service/execution"
)

func callbackContext(r *http.Request) context.Context {
	// Ambiguous credentials never select one of several possible authorities.
	for _, name := range []string{wire.InvocationTokenHeader, "X-Airlock-Job-ID", "X-Airlock-Job-Attempt", "X-Airlock-Job-Lease-Token"} {
		if len(r.Header.Values(name)) > 1 {
			return execution.WithInvocationProof(r.Context(), execution.InvocationProof{})
		}
	}
	attempt, _ := strconv.ParseInt(r.Header.Get("X-Airlock-Job-Attempt"), 10, 32)
	return execution.WithInvocationProof(r.Context(), execution.InvocationProof{
		Token: r.Header.Get(wire.InvocationTokenHeader), JobID: r.Header.Get("X-Airlock-Job-ID"),
		Attempt: int32(attempt), LeaseToken: r.Header.Get("X-Airlock-Job-Lease-Token"),
	})
}
