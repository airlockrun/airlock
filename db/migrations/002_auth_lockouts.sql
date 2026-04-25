-- +goose Up
-- Per-account login lockout, keyed on (email, ip).
-- See airlock/auth/lockout/ for the policy + IP normalization that produces
-- the `ip` value (IPv6 is collapsed to its /64 prefix; unparseable peers
-- bucket to the sentinel "unknown").

CREATE TABLE auth_failures (
    email         text NOT NULL,
    ip            text NOT NULL,
    attempted_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_failures_lookup ON auth_failures (email, ip, attempted_at DESC);
CREATE INDEX idx_auth_failures_prune  ON auth_failures (attempted_at);

CREATE TABLE auth_lockouts (
    email           text NOT NULL,
    ip              text NOT NULL,
    locked_until    timestamptz NOT NULL,
    tier            int NOT NULL DEFAULT 0,
    last_locked_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (email, ip)
);

-- +goose Down
DROP TABLE IF EXISTS auth_lockouts;
DROP INDEX IF EXISTS idx_auth_failures_prune;
DROP INDEX IF EXISTS idx_auth_failures_lookup;
DROP TABLE IF EXISTS auth_failures;
