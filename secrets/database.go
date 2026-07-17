package secrets

import (
	"context"
	"fmt"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const rewrapAdvisoryLockSeed int64 = 0x736563726574

// RewrapDatabase upgrades persisted Store values to the ref-bound envelope
// under the active key. It is an explicit stop-all migration and must not be
// called during normal startup.
//
// The transaction makes the scan atomic, and its advisory lock serializes
// accidental concurrent migration replicas before either can serve.
func RewrapDatabase(ctx context.Context, pool *pgxpool.Pool, store Store) (int64, error) {
	if pool == nil || store == nil {
		panic("secrets: RewrapDatabase requires a pool and store")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin secret rewrap: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('airlock-secret-envelope-v1', $1))`, rewrapAdvisoryLockSeed); err != nil {
		return 0, fmt.Errorf("acquire secret rewrap lock: %w", err)
	}

	q := dbq.New(tx)
	rows, err := q.ListStoredSecrets(ctx)
	if err != nil {
		return 0, fmt.Errorf("list stored secrets: %w", err)
	}
	var changed int64
	for _, row := range rows {
		var next string
		var needsUpdate bool
		if row.Kind == "agent" && row.Field == "git_webhook_secret" && !IsEnvelope(row.Stored) {
			// This field's unenveloped schema is plaintext. No other secret field
			// receives plaintext compatibility behavior.
			next, err = store.Put(ctx, row.Ref, row.Stored)
			needsUpdate = err == nil
		} else {
			next, needsUpdate, err = store.Rewrap(ctx, row.Ref, row.Stored)
		}
		if err != nil {
			return 0, fmt.Errorf("rewrap %s %s %s: %w", row.Kind, row.RowKey, row.Field, err)
		}
		if !needsUpdate {
			continue
		}
		n, err := persistRewrapped(ctx, q, row, next)
		if err != nil {
			return 0, fmt.Errorf("persist rewrapped %s %s %s: %w", row.Kind, row.RowKey, row.Field, err)
		}
		changed += n
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit secret rewrap: %w", err)
	}
	return changed, nil
}

// IsEnvelope reports whether stored uses the ref-bound Store format.
func IsEnvelope(stored string) bool {
	return len(stored) >= len(localEnvelopePrefix) && stored[:len(localEnvelopePrefix)] == localEnvelopePrefix
}

func persistRewrapped(ctx context.Context, q *dbq.Queries, row dbq.ListStoredSecretsRow, next string) (int64, error) {
	var pgID pgtype.UUID
	if row.Kind != "oauth_state" {
		id, err := uuid.Parse(row.RowKey)
		if err != nil {
			return 0, fmt.Errorf("invalid %s row key %q: %w", row.Kind, row.RowKey, err)
		}
		pgID = pgtype.UUID{Bytes: id, Valid: true}
	}
	params := dbq.RewrapAgentSecretParams{
		NewStored: next,
		Field:     row.Field,
		RowKey:    pgID,
		OldStored: row.Stored,
	}
	switch row.Kind {
	case "provider":
		return q.RewrapProviderSecret(ctx, dbq.RewrapProviderSecretParams{NewStored: next, RowKey: pgID, OldStored: row.Stored})
	case "agent":
		return q.RewrapAgentSecret(ctx, params)
	case "webhook":
		return q.RewrapWebhookSecret(ctx, dbq.RewrapWebhookSecretParams{NewStored: next, RowKey: pgID, OldStored: row.Stored})
	case "bridge":
		return q.RewrapBridgeSecret(ctx, dbq.RewrapBridgeSecretParams{NewStored: next, RowKey: pgID, OldStored: row.Stored})
	case "connection":
		return q.RewrapConnectionSecret(ctx, dbq.RewrapConnectionSecretParams{NewStored: next, Field: row.Field, RowKey: pgID, OldStored: row.Stored})
	case "mcp":
		return q.RewrapMCPSecret(ctx, dbq.RewrapMCPSecretParams{NewStored: next, Field: row.Field, RowKey: pgID, OldStored: row.Stored})
	case "git_credential":
		return q.RewrapGitCredentialSecret(ctx, dbq.RewrapGitCredentialSecretParams{NewStored: next, RowKey: pgID, OldStored: row.Stored})
	case "exec":
		return q.RewrapExecSecret(ctx, dbq.RewrapExecSecretParams{NewStored: pgtype.Text{String: next, Valid: true}, RowKey: pgID, OldStored: pgtype.Text{String: row.Stored, Valid: true}})
	case "oauth_state":
		return q.RewrapOAuthStateSecret(ctx, dbq.RewrapOAuthStateSecretParams{NewStored: next, RowKey: row.RowKey, OldStored: row.Stored})
	case "env_var":
		return q.RewrapEnvVarSecret(ctx, dbq.RewrapEnvVarSecretParams{NewStored: next, RowKey: pgID, OldStored: row.Stored})
	default:
		return 0, fmt.Errorf("unknown secret kind %q", row.Kind)
	}
}
