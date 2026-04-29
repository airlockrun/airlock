package lockout

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Status struct {
	Locked      bool
	LockedUntil time.Time
	Tier        int
}

// Check returns the active lockout for (email, ip), if any.
func (p Policy) Check(ctx context.Context, pool *pgxpool.Pool, email, ip string) (Status, error) {
	row, err := dbq.New(pool).GetActiveLockout(ctx, dbq.GetActiveLockoutParams{Email: email, Ip: ip})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Status{}, nil
		}
		return Status{}, err
	}
	return Status{
		Locked:      true,
		LockedUntil: row.LockedUntil.Time,
		Tier:        int(row.Tier),
	}, nil
}

// RecordFailure logs an auth failure for (email, ip) and applies an
// escalating lockout when the rolling-window threshold is reached. The whole
// thing runs in one transaction so concurrent triggers agree on the next
// tier.
func (p Policy) RecordFailure(ctx context.Context, pool *pgxpool.Pool, email, ip string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := dbq.New(pool).WithTx(tx)

	if err := q.RecordAuthFailure(ctx, dbq.RecordAuthFailureParams{Email: email, Ip: ip}); err != nil {
		return err
	}

	count, err := q.CountRecentFailures(ctx, dbq.CountRecentFailuresParams{
		Email:         email,
		Ip:            ip,
		WindowMinutes: int32(p.WindowMinutes),
	})
	if err != nil {
		return err
	}
	if int(count) < p.Threshold {
		return tx.Commit(ctx)
	}

	newTier := 0
	prev, err := q.GetLockoutForUpdate(ctx, dbq.GetLockoutForUpdateParams{Email: email, Ip: ip})
	switch {
	case err == nil:
		// Tier escalates only if the previous lockout is recent. After 24h
		// of quiet a fresh lockout starts at tier 0 again.
		if time.Since(prev.LastLockedAt.Time) < 24*time.Hour {
			newTier = int(prev.Tier) + 1
		}
	case errors.Is(err, pgx.ErrNoRows):
		// First-ever lockout for this (email, ip).
	default:
		return err
	}

	lockedUntil := time.Now().Add(p.CooldownFor(newTier))
	if err := q.UpsertLockout(ctx, dbq.UpsertLockoutParams{
		Email:       email,
		Ip:          ip,
		LockedUntil: pgtype.Timestamptz{Time: lockedUntil, Valid: true},
		Tier:        int32(newTier),
	}); err != nil {
		return err
	}
	// Drop the failure rows that triggered this lockout so the next attempt
	// after expiry doesn't immediately re-trigger.
	if err := q.ClearAuthFailures(ctx, dbq.ClearAuthFailuresParams{Email: email, Ip: ip}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ClearOnSuccess wipes failure history + lockout state for a successful
// login. Best-effort: the caller logs errors but does not block the
// successful login response on this.
func (p Policy) ClearOnSuccess(ctx context.Context, pool *pgxpool.Pool, email, ip string) error {
	q := dbq.New(pool)
	if err := q.ClearAuthFailures(ctx, dbq.ClearAuthFailuresParams{Email: email, Ip: ip}); err != nil {
		return err
	}
	return q.ClearAuthLockout(ctx, dbq.ClearAuthLockoutParams{Email: email, Ip: ip})
}
