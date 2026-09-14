package appruntime

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/airlockrun/airlock/apperr"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func envVarRef(id, slug string) string { return "agent/env-var/" + id + "/" + slug }

func (h *Service) UpsertEnvVar(ctx context.Context, slug string, req wire.EnvVarDef) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agentID, admissionErr := h.admit(ctx, q)
	if admissionErr != nil {
		return admissionErr
	}
	if slug == "" {
		return apperr.Detail(apperr.ErrInvalidInput, "slug is required")
	}
	if req.Pattern != "" {
		if _, err := regexp.Compile(req.Pattern); err != nil {
			return apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("invalid pattern: %s", err.Error()))
		}
	}
	if _, err := q.UpsertAgentEnvVar(ctx, dbq.UpsertAgentEnvVarParams{
		AgentID:      toPgUUID(agentID),
		Slug:         slug,
		Description:  req.Description,
		IsSecret:     req.Secret,
		DefaultValue: req.Default,
		Pattern:      req.Pattern,
	}); err != nil {
		h.logger.Error("upsert env var failed", zap.Error(err))
		return errors.New("failed to register env var")
	}
	return tx.Commit(ctx)
}

func (h *Service) GetEnvVarValue(ctx context.Context, slug string) (wire.EnvVarValueResponse, error) {
	agentID, admissionErr := h.admit(ctx, dbq.New(h.db.Pool()))
	if admissionErr != nil {
		return wire.EnvVarValueResponse{}, admissionErr
	}
	if slug == "" {
		return wire.EnvVarValueResponse{}, apperr.Detail(apperr.ErrInvalidInput, "slug is required")
	}
	q := dbq.New(h.db.Pool())
	row, err := q.GetAgentEnvVarBySlug(ctx, dbq.GetAgentEnvVarBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return wire.EnvVarValueResponse{}, apperr.Detail(apperr.ErrNotFound, "env var not registered")
		}
		h.logger.Error("get env var failed", zap.Error(err))
		return wire.EnvVarValueResponse{}, errors.New("failed to load env var")
	}
	if row.ValueRef == "" {
		return wire.EnvVarValueResponse{}, apperr.Detail(apperr.ErrNotFound, "env var has no configured value")
	}
	value, err := h.encryptor.Get(ctx, envVarRef(uuid.UUID(row.ID.Bytes).String(), slug), row.ValueRef)
	if err != nil {
		h.logger.Error("decrypt env var failed", zap.Error(err))
		return wire.EnvVarValueResponse{}, errors.New("decryption failed")
	}
	return wire.EnvVarValueResponse{Value: value}, nil
}
