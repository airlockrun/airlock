package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
)

// InvocationProof is untrusted input until an invocation gate validates it.
// A job delivery may supply its exact attempt fence instead of a receipt.
type InvocationProof struct {
	Token      string
	JobID      string
	Attempt    int32
	LeaseToken string
}

type invocationProofKey struct{}

// Covers the supported 24-hour job deadline plus bounded delivery cleanup.
const maxInvocationLifetime = 25 * time.Hour

func WithInvocationProof(ctx context.Context, proof InvocationProof) context.Context {
	return context.WithValue(ctx, invocationProofKey{}, proof)
}

func InvocationProofFromContext(ctx context.Context) InvocationProof {
	proof, _ := ctx.Value(invocationProofKey{}).(InvocationProof)
	return proof
}

// IssueInvocation is host-only. Call it immediately before dispatch and close
// the receipt when delivery finishes. The plaintext never enters shared storage.
func IssueInvocation(ctx context.Context, q *dbq.Queries, agentID, runID, ownerToken uuid.UUID, expiresAt time.Time) (wire.RuntimeContext, error) {
	if !expiresAt.After(time.Now()) || expiresAt.After(time.Now().Add(maxInvocationLifetime)) {
		return wire.RuntimeContext{}, service.ErrInvalidInput
	}
	admitted, err := Resolve(ctx, q, agentID, runID)
	if err != nil {
		return wire.RuntimeContext{}, err
	}
	if admitted.Run.RuntimeOwnerToken != pgID(ownerToken) {
		return wire.RuntimeContext{}, service.ErrConflict
	}
	app, err := q.GetAgentByID(ctx, pgID(agentID))
	if err != nil {
		return wire.RuntimeContext{}, err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return wire.RuntimeContext{}, err
	}
	hash := sha256.Sum256(secret[:])
	n, err := q.CreateExecutionInvocation(ctx, dbq.CreateExecutionInvocationParams{
		TokenHash: hash[:], RunID: pgID(runID), AgentID: pgID(agentID),
		RuntimeGeneration: app.AgentTokenVersion, ExpiresAt: timestamp(expiresAt),
		OwnerToken: pgID(ownerToken),
	})
	if err != nil {
		return wire.RuntimeContext{}, err
	}
	if n != 1 {
		return wire.RuntimeContext{}, service.ErrConflict
	}
	admitted.Runtime.InvocationToken = hex.EncodeToString(secret[:])
	return admitted.Runtime, nil
}

func invocationHash(token string) ([]byte, error) {
	secret, err := hex.DecodeString(token)
	if err != nil || len(secret) != 32 || hex.EncodeToString(secret) != token {
		return nil, service.ErrUnauthorized
	}
	hash := sha256.Sum256(secret)
	return hash[:], nil
}

// CloseInvocation uses an independent bounded context so cancelled dispatches
// still close their receipt on every replica. Expiry also fences crashed hosts.
func CloseInvocation(q *dbq.Queries, token string) error {
	hash, err := invocationHash(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return q.CloseExecutionInvocation(ctx, hash)
}

// ResolveInvocation requires both the current app credential generation and a
// dispatch-bound proof before restoring any human authority from the run.
func ResolveInvocation(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID, generation int64, proof InvocationProof) (Context, error) {
	var live bool
	var err error
	if proof.Token != "" {
		hash, hashErr := invocationHash(proof.Token)
		if hashErr != nil {
			return Context{}, hashErr
		}
		live, err = q.ExecutionInvocationLive(ctx, dbq.ExecutionInvocationLiveParams{
			TokenHash: hash, AgentID: pgID(agentID), RunID: pgID(runID), RuntimeGeneration: generation,
		})
		if err == nil && live {
			owner, ownerErr := q.GetExecutionInvocationOwner(ctx, hash)
			if ownerErr != nil {
				return Context{}, ownerErr
			}
			if owner.Valid {
				ctx = WithRuntimeOwner(ctx, runID, uuid.UUID(owner.Bytes))
			}
		}
	} else {
		jobID, jobErr := uuid.Parse(proof.JobID)
		lease, leaseErr := uuid.Parse(proof.LeaseToken)
		if jobErr != nil || leaseErr != nil || jobID == uuid.Nil || lease == uuid.Nil || proof.Attempt <= 0 {
			return Context{}, service.ErrUnauthorized
		}
		live, err = q.ExecutionCallbackJobLive(ctx, dbq.ExecutionCallbackJobLiveParams{
			AgentID: pgID(agentID), RunID: pgID(runID), RuntimeGeneration: generation,
			JobID: pgID(jobID), AttemptNumber: proof.Attempt, LeaseToken: pgID(lease),
		})
	}
	if err != nil {
		return Context{}, err
	}
	if !live {
		return Context{}, service.ErrUnauthorized
	}
	return Resolve(ctx, q, agentID, runID)
}

// AuthorizeInvocationCompletion permits terminal telemetry for active nonhosted
// work, including closed delivery receipts until expiry. It returns no authority
// and does not require the initiating human credential to remain live. Callers
// must lock the run and retain the terminal update's cancellation/attempt fences.
func AuthorizeInvocationCompletion(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID, generation int64, proof InvocationProof) error {
	var hash []byte
	var err error
	if proof.Token != "" {
		hash, err = invocationHash(proof.Token)
		if err != nil {
			return err
		}
	}
	jobID, lease := uuid.Nil, uuid.Nil
	if proof.JobID != "" || proof.Attempt != 0 || proof.LeaseToken != "" {
		var jobErr, leaseErr error
		jobID, jobErr = uuid.Parse(proof.JobID)
		lease, leaseErr = uuid.Parse(proof.LeaseToken)
		if jobErr != nil || leaseErr != nil || jobID == uuid.Nil || lease == uuid.Nil || proof.Attempt <= 0 {
			return service.ErrUnauthorized
		}
	}
	allowed, err := q.ExecutionInvocationCompletionAllowed(ctx, dbq.ExecutionInvocationCompletionAllowedParams{
		AgentID: pgID(agentID), RunID: pgID(runID), RuntimeGeneration: generation,
		TokenHash: hash, JobID: pgID(jobID), AttemptNumber: proof.Attempt, LeaseToken: pgID(lease),
	})
	if err != nil {
		return err
	}
	if !allowed {
		return service.ErrUnauthorized
	}
	return nil
}
