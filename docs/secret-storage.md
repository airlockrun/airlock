# Secret storage and key rotation

Airlock stores credential material in a versioned `airlock-secret:v1` envelope.
AES-256-GCM authenticates the canonical resource ref, so moving ciphertext from
one row or field to another fails decryption. The inner ciphertext identifies
its encryption key by a stable digest ID rather than by key-ring position.

Normal startup with `ENCRYPTION_KEY_REWRAP=false` does not scan or rewrite
persisted secrets. It can read ref-bound envelopes and compatibility ciphertext
using the configured key ring. The `agents.git_webhook_secret` column also has a
schema-specific unenveloped plaintext read path so GitHub and GitLab webhook
verification continues to work until the coordinated migration. Generic secret
reads never accept plaintext.

`ENCRYPTION_KEY_REWRAP=true` is a maintenance mode. Before HTTP serving begins,
Airlock migrates every persisted secret to the ref-bound envelope under the
active key. The scan and updates run in one transaction under a PostgreSQL
advisory lock. Concurrent maintenance replicas serialize on that lock, and any
invalid value rolls back the complete scan.

## Migrate the envelope format

The format migration is a coordinated stop-all operation because replicas that
do not understand the envelope cannot read migrated values.

1. Back up the database and `ENCRYPTION_KEY`.
2. Stop every Airlock replica that shares the database and verify none remain
   running.
3. Keep `ENCRYPTION_KEY` unchanged and set `ENCRYPTION_KEY_REWRAP=true`.
   `ENCRYPTION_KEY_OLD` is not needed for a format-only migration.
4. Start the maintenance release. Startup fails before serving if any persisted
   value cannot be migrated. The log reports `rewrap_enabled=true`, the active
   key ID, and the migrated count without logging key material.
5. Set `ENCRYPTION_KEY_REWRAP=false` and restart every replica on the maintenance
   release. Do not add replicas running a release that cannot read envelopes.

Run this procedure explicitly and independently from release upgrades. Every
deployment topology, including Compose, must verify that all replicas sharing
the database are stopped before enabling maintenance mode.

## Rotate the key

Key rotation is a coordinated stop-all operation. Do not roll replicas with
different active keys: a replica writing with the new key would produce values
that a replica holding only the prior key cannot read.

1. Complete the envelope format migration above.
2. Back up the database and both key values.
3. Generate a new key with `openssl rand -hex 32`.
4. Stop every Airlock replica. For Compose, run `docker compose stop airlock` and
   verify `docker compose ps airlock` shows no running container. For an
   orchestrator, scale the Airlock workload to zero and verify all pods stopped.
5. Set `ENCRYPTION_KEY` to the new value, `ENCRYPTION_KEY_OLD` to the prior value,
   and `ENCRYPTION_KEY_REWRAP=true` on every replica.
6. Start the maintenance release and require healthy startup. Startup fails if the old key
   is missing or any persisted value cannot be decrypted. The log reports the
   active key ID and rewrapped count, never key material.
7. Set `ENCRYPTION_KEY_REWRAP=false` while retaining both keys, then restart all
   replicas on the same release with identical configuration.
8. Values returned by the agent `/seal` API live in agent-owned storage and are
   not part of the database scan. Each agent must open and seal those values
   again under the new active key before the prior key can be removed. If those
   values cannot be inventoried, retain the prior key.
9. Remove `ENCRYPTION_KEY_OLD` only after every replica is healthy, every
   agent-owned sealed value is re-sealed, and no rollback to a database snapshot
   containing prior-key ciphertext is required.

Restoring a database snapshot requires every key that snapshot references.
