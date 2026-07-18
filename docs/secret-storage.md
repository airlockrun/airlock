# Secret storage and key rotation

Airlock stores credential material in a versioned `airlock-secret:v1` envelope.
AES-256-GCM authenticates the canonical resource ref, so moving ciphertext from
one row or field to another fails decryption. The inner ciphertext identifies
its encryption key with the `airlock-crypto:v2` format and a stable digest ID.
Stored database secrets that do not match both formats are invalid.

Normal startup with `ENCRYPTION_KEY_REWRAP=false` does not scan or rewrite
persisted secrets. It decrypts current-format envelopes with `ENCRYPTION_KEY` or
`ENCRYPTION_KEY_OLD` according to the inner stable key ID. Plaintext, unwrapped
ciphertext, and ciphertext without a stable key ID are rejected.

`ENCRYPTION_KEY_REWRAP=true` is a maintenance mode. Before HTTP serving begins,
Airlock re-encrypts every persisted database secret under `ENCRYPTION_KEY`. The
scan and updates run in one transaction under a PostgreSQL advisory lock.
Concurrent maintenance replicas serialize on that lock, and any invalid value
or missing key rolls back the complete scan.

## Rotate the key

Key rotation is a coordinated stop-all operation. Do not roll replicas with
different active keys: a replica writing with the new key would produce values
that a replica holding only the prior key cannot read.

1. Back up the database and current `ENCRYPTION_KEY`.
2. Generate a new key with `openssl rand -hex 32`.
3. Stop every Airlock replica. For Compose, run `docker compose stop airlock` and
   verify `docker compose ps airlock` shows no running container. For an
   orchestrator, scale the Airlock workload to zero and verify all pods stopped.
4. Set `ENCRYPTION_KEY` to the new value, `ENCRYPTION_KEY_OLD` to the prior value,
   and `ENCRYPTION_KEY_REWRAP=true` on every replica.
5. Start Airlock and require healthy startup. Startup fails if the old key is
   missing or any persisted value cannot be decrypted. The log reports the
   active key ID and rewrapped count, never key material.
6. Set `ENCRYPTION_KEY_REWRAP=false` while retaining both keys, then restart all
   replicas on the same release with identical configuration.
7. Values returned by the agent `/seal` API live in agent-owned storage and are
   not part of the database scan. Each agent must open and seal those values
   again under the new active key before the prior key can be removed. If those
   values cannot be inventoried, retain the prior key.
8. Remove `ENCRYPTION_KEY_OLD` only after every replica is healthy, every
   agent-owned sealed value is re-sealed, and no rollback to a database snapshot
   containing prior-key ciphertext is required.

Restoring a database snapshot requires every key that snapshot references.
