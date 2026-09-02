# Hosts

Every connector installation is owned and executed by `airlock-host`. Airlock
does not accept direct connector enrollment or connector installation
credentials.

Connector artifacts are trusted native code. They execute as the same OS user
as `airlock-host`; framed child I/O is a process protocol, not a security
sandbox. A connector can inspect same-user files, including host state and its
credential. Operators must install only artifacts from trusted Airlock builds
and treat the host account and all installed connectors as one trust domain.

## Enrollment

1. The host calls `POST /api/hosts/v1/enroll/device-code` with its name,
   platform, architecture, version, protocol version, and local-access mode.
2. An authenticated operator visits `/hosts/connect`, inspects the one-time
   code, and approves or denies it.
3. The host polls `POST /api/hosts/v1/enroll/complete`. Approval is consumed
   once and returns an opaque host credential. Airlock stores only the
   credential selector and SHA-256 hash.
4. The host uses `Authorization: Bearer <credential>` for sync, polling,
   inventory, progress, and completion requests.

Each enrollment creates a distinct host identity. Re-enrolling a machine does
not infer or adopt connector installations from another host.

## Local Access

The host reports one mode on every sync:

| Mode | Shell | Install | Update | Rollback | Remove | Connector commands |
| --- | --- | --- | --- | --- | --- | --- |
| `full` | yes | yes | yes | yes | yes | yes |
| `update_only` | no | no | yes | yes | no | yes |
| `none` | no | no | no | no | no | yes |

The mode is host policy and cannot be changed from Airlock. Management admission
and claim require a heartbeat within the same two-minute freshness window used
for hosted connectors. A queued management job is rechecked against the current
mode and host artifact platform when claimed. Connector domain
commands are not local-management operations and remain available in every
mode.

## Management Work

Shell, install, update, rollback, and removal requests are durable jobs. Claims use
`FOR UPDATE SKIP LOCKED`; attempts carry expiring leases and unguessable fencing
tokens. Hosts report explicit active job/token pairs to renew leases. Progress
sequences are monotonic and retry-idempotent, and stale completions are rejected.
The latest management attempt may replay an identical terminal completion after
its deadline so Airlock can reconcile lifecycle changes that already committed
on the host.

Connector install and update requests reference retained server-issued artifact
file IDs. Airlock checks agent, need, platform, interface compatibility, and
successful build provenance. Nonterminal jobs pin their artifact set. Delivery
contains a short-lived exact-object URL, digest, size, filename, settings, and
the configured storage origins; it never contains storage credentials or an
operator-supplied URL.

Successful updates retain the previous artifact set as the connector's rollback
slot. A rollback swaps the active and rollback slots, so repeated rollback
requests provide A/B switching without downloading another artifact.

## Connector Work

`POST /api/hosts/v1/connectors/inventory` transactionally acknowledges one
monotonic full-manifest upsert or removal tombstone. Exact mutation replays are
idempotent; stale revisions and revisions reused with different content are
rejected. Exact successful-build artifacts for the host platform retain Airlock
provenance even when installed locally. Unknown or invalid active bytes remain
visible but lose bindings, bound-group membership, reservations, and nonterminal
work. Compact host sync reports acknowledged installations' digest, readiness,
and active connector attempts. Airlock compares that report with the reconciled
observation and marks drift unhealthy. The host long poll
returns management jobs, connector command jobs, and connector cancellation
notices through one typed protocol. Connector events and completions are scoped
by both host and installation before the existing connector-job fencing rules
are applied.
