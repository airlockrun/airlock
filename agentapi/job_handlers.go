package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	errInvalidJobHandler    = jobssvc.ErrInvalidHandler
	errJobContractConflict  = jobssvc.ErrContractConflict
	errStaleJobManifest     = errors.New("stale job handler manifest")
	errCandidateJobManifest = errors.New("candidate job manifest does not match candidate build")
)

func (h *Handler) reconcileJobHandlers(ctx context.Context, agentID uuid.UUID, tokenVersion int64, definitions []wire.JobHandlerDef) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin job handler reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := h.reconcileJobHandlersTx(ctx, dbq.New(tx), agentID, tokenVersion, definitions); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit job handler reconciliation: %w", err)
	}
	return nil
}

func (h *Handler) reconcileJobManifest(ctx context.Context, agentID uuid.UUID, tokenVersion int64, handlers []wire.JobHandlerDef, crons []wire.JobCronDef) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin job manifest reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := verifyCandidateJobManifest(ctx, q, agentID, tokenVersion, handlers, crons); err != nil {
		return err
	}
	if err := h.reconcileJobHandlersTx(ctx, q, agentID, tokenVersion, handlers); err != nil {
		return err
	}
	if err := h.scheduler.ReconcileAgentTx(ctx, tx, agentID, tokenVersion, crons); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit job manifest reconciliation: %w", err)
	}
	h.scheduler.Wake()
	return nil
}

func verifyCandidateJobManifest(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, tokenVersion int64, handlers []wire.JobHandlerDef, crons []wire.JobCronDef) error {
	pgAgentID := toPgUUID(agentID)
	agent, err := q.GetAgentByIDForUpdate(ctx, pgAgentID)
	if err != nil {
		return fmt.Errorf("lock agent for candidate job manifest verification: %w", err)
	}
	if tokenVersion <= 0 || agent.AgentTokenVersion != tokenVersion || (agent.Status != "active" && agent.Status != "building") {
		return fmt.Errorf("%w: authenticated runtime generation is no longer active", errStaleJobManifest)
	}
	if !agent.JobDispatchPausedBuildID.Valid {
		return nil
	}
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{
		BuildID: agent.JobDispatchPausedBuildID, AgentID: pgAgentID,
	})
	if err != nil {
		return fmt.Errorf("load paused deployment: %w", err)
	}
	if build.DeploymentPhase != "starting" {
		return nil
	}
	_, digest, err := jobssvc.NormalizeJobManifest(wire.JobManifest{JobHandlers: handlers, JobCrons: crons})
	if err != nil {
		return err
	}
	if !build.JobManifestDigest.Valid {
		return errors.New("starting candidate build is missing its job manifest digest")
	}
	if digest != build.JobManifestDigest.String {
		return errCandidateJobManifest
	}
	return nil
}

func (h *Handler) reconcileJobHandlersTx(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, tokenVersion int64, definitions []wire.JobHandlerDef) error {
	normalized, err := jobssvc.NormalizeHandlerDefinitions(definitions)
	if err != nil {
		return err
	}
	pgAgentID := toPgUUID(agentID)
	agent, err := q.GetAgentByIDForUpdate(ctx, pgAgentID)
	if err != nil {
		return fmt.Errorf("lock agent for job handler reconciliation: %w", err)
	}
	if tokenVersion <= 0 || agent.AgentTokenVersion != tokenVersion || (agent.Status != "active" && agent.Status != "building") {
		return fmt.Errorf("%w: authenticated runtime generation is no longer active", errStaleJobManifest)
	}
	nonterminal, err := q.ListNonterminalJobHandlerVersions(ctx, pgAgentID)
	if err != nil {
		return fmt.Errorf("list nonterminal job handler versions: %w", err)
	}
	declared := make(map[string]struct{}, len(normalized))
	for _, definition := range normalized {
		declared[fmt.Sprintf("%s@v%d", definition.Name, definition.Version)] = struct{}{}
	}
	for _, outstanding := range nonterminal {
		key := fmt.Sprintf("%s@v%d", outstanding.HandlerName, outstanding.HandlerVersion)
		if _, ok := declared[key]; !ok {
			return fmt.Errorf("%w: %s has queued or running jobs", errJobContractConflict, key)
		}
	}
	if err := q.DeactivateJobHandlersByAgent(ctx, pgAgentID); err != nil {
		return fmt.Errorf("deactivate job handlers: %w", err)
	}
	for _, definition := range normalized {
		updated, err := q.UpsertJobHandler(ctx, dbq.UpsertJobHandlerParams{
			AgentID:           pgAgentID,
			Name:              definition.Name,
			Version:           definition.Version,
			Description:       definition.Description,
			TimeoutMs:         definition.TimeoutMs,
			MaxAttempts:       definition.MaxAttempts,
			MaxConcurrency:    definition.MaxConcurrency,
			InputSchema:       definition.InputSchema,
			OutputSchema:      definition.OutputSchema,
			InputSchemaHash:   definition.InputSchemaHash,
			OutputSchemaHash:  definition.OutputSchemaHash,
			AgentTokenVersion: tokenVersion,
		})
		if err != nil {
			return fmt.Errorf("upsert job handler %s@v%d: %w", definition.Name, definition.Version, err)
		}
		if updated == 0 {
			return fmt.Errorf("%w: %s@v%d changed its immutable contract", errJobContractConflict, definition.Name, definition.Version)
		}
	}
	return nil
}

func (h *Handler) preflightJobHandlers(ctx context.Context, agentID uuid.UUID, definitions []wire.JobHandlerDef) ([]wire.JobHandlerDef, error) {
	normalized, err := jobssvc.NormalizeHandlerDefinitions(definitions)
	if err != nil {
		return nil, err
	}
	existing, err := dbq.New(h.db.Pool()).ListJobHandlersByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		return nil, fmt.Errorf("list existing job handlers: %w", err)
	}
	contracts := make(map[string]dbq.AgentJobHandler, len(existing))
	for _, handler := range existing {
		contracts[fmt.Sprintf("%s@v%d", handler.Name, handler.Version)] = handler
	}
	for _, definition := range normalized {
		key := jobssvc.HandlerKey(definition.Name, definition.Version)
		if handler, ok := contracts[key]; ok && (handler.InputSchemaHash != definition.InputSchemaHash ||
			handler.OutputSchemaHash != definition.OutputSchemaHash || handler.TimeoutMs != definition.TimeoutMs ||
			handler.MaxAttempts != definition.MaxAttempts) {
			return nil, fmt.Errorf("%w: %s changed its immutable contract", errJobContractConflict, key)
		}
	}
	return normalized, nil
}

func normalizeJobHandlerDefinitions(definitions []wire.JobHandlerDef) ([]wire.JobHandlerDef, error) {
	return jobssvc.NormalizeHandlerDefinitions(definitions)
}

func hashJobHandlerSchema(value json.RawMessage) string {
	return jobssvc.HashHandlerSchema(value)
}

func (h *Handler) writeJobHandlerSyncError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidJobHandler):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, jobssvc.ErrInvalidJobCron):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errJobContractConflict):
		writeJSONError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errCandidateJobManifest):
		writeJSONError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errStaleJobManifest):
		writeJSONError(w, http.StatusUnauthorized, err.Error())
	default:
		h.logger.Error("reconcile job handlers failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to reconcile job handlers")
	}
}
