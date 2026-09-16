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
4. The host opens one outbound WSS connection at `/api/hosts/v1/connect` with
   `Authorization: Bearer <credential>` and the `airlock.host.v2` subprotocol.
   HTTPS enrollment is separate from the runtime transport.

Each enrollment creates a distinct host identity. Re-enrolling a machine does
not infer or adopt connector installations from another host.

## Local Access

The host reports one mode on every sync and heartbeat:

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

The WebSocket `inventory` message transactionally acknowledges one
monotonic full-manifest upsert or removal tombstone. Exact mutation replays are
idempotent; stale revisions and revisions reused with different content are
rejected. Exact successful-build artifacts for the host platform retain Airlock
provenance even when installed locally. Unknown or invalid active bytes remain
visible but lose bindings, bound-group membership, reservations, and nonterminal
work. Compact host sync reports acknowledged installations' digest, readiness,
and active connector attempts. Airlock compares that report with the reconciled
observation and marks drift unhealthy. Capacity-driven WebSocket demand
delivers management jobs, connector command jobs, and connector cancellation
notices through one typed protocol. Connector events and completions are scoped
by both host and installation before the existing connector-job fencing rules
are applied.

## Session Lifecycle

Envelopes carry `protocol: "airlock.host.v2"`, a bounded correlation `id`, and
exactly one typed payload. Replies reuse that ID. Acknowledgements follow service
commit. Unknown fields and unsupported versions fail closed. Each session permits
16 in-flight messages and at most one outstanding work demand. A demand consumes
at most one claim; database serialization limits each host to 32 live connector
claims and one management attempt, including across replicas and reconnects.
Cancellation notices alternate with claim opportunities; an unresponsive child
cannot monopolize delivery. Admitted management runs follow the host lifetime
and job deadline, independently of WebSocket reconnection.

Heartbeat and explicit attempt renewal run every ten seconds, independently of
twenty-second inventory sync and work dispatch. Host policy and liveness remain
current while management work runs. A shared notification subscription wakes
dispatch and cancellation checks without holding a request-pool connection.
Live credential checks run on messages, before dispatch and delivery, and every
five seconds while idle. Router shutdown cancels and drains upgraded sockets
explicitly before service dependencies are closed.

Connector child output enters a bounded durable local queue without network I/O
on the stdout reader. The host retries unacknowledged events and completions after
reconnect and restart. Migration `010_host_contract_singleton.sql` records
the submitted terminal receipt on the attempt in the same statement as completion.
An exact latest-attempt replay is acknowledged after lease/deadline expiry; changed
payloads and superseded attempts cannot modify results. Explicit rejections retain
the local payload for inspection and emit an error log. Rejected local retention
is separate from pending capacity and bounded to 128 files and 16 MiB, with
warning-logged removal of the oldest payloads. Inventory revision
tombstones and management outcome journals remain durable independently.

Remote update and rollback activation atomically records a full inventory upsert
on the host, including the active and rollback manifests and management attempt.
Successful completion commits that inventory revision with the job. The host
replays completion until acknowledged before sending the inventory mutation and
excludes the new artifact from compact sync until inventory acknowledgement.
Airlock checks the completed latest attempt, exact revision, requested update
artifact or authorized rollback slot, and retained previous active slot before
adopting canonical artifact metadata. Matching heartbeat then establishes readiness.

Migration `010_host_contract_singleton.sql` persists the completion revision
and inventory acknowledgement. Unreconciled successful jobs and their artifact
pins survive retention. Follow-up management on that installation waits for
reconciliation; shell work and explicit removal remain available. A newer local
inventory revision can supersede a transition and durably release its pending
reconciliation obligation. Inventory and completion replays cannot change their
recorded content.

Deploy matching host and server builds and apply migrations before accepting
sessions. Runtime HTTP sync, inventory, work polling, progress, and completion
routes are not exposed. The child-process framed protocol is independent of the
host WebSocket protocol.
