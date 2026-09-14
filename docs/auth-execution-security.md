# Authentication And Execution Security

## Runtime Contract

Airlock hosts app chat through `agentsdk/chatruntime` and Sol. Apps expose their
own tools and runtime capabilities through the authenticated SDK listener.
The capability broker exposes the current app, platform operations and bound
external resources. Application-to-application calls, sibling discovery and
delegated reasoning tasks are not supported. External MCP exposes declared tools
and resources, not a model-prompt meta-tool.

Complete manifests, sync and capability invocation require
`wire.AppRuntimeProtocol = "airlock.app-runtime.v2"`. The synchronized manifest is
bound to the app token generation. Missing or incompatible protocol identities
fail admission independently of SDK semver. Rebuild each incompatible app with a
compatible SDK and verify its manifest sync before admitting work. There is no
rolling mixed v1/v2 compatibility mode.

## Credential Boundaries

| Surface | Required Authority |
| --- | --- |
| Browser/operator API | Profile-validated user access credential and live session/account checks; services resolve current role and app grants. |
| App subdomain | Authenticated requests use an agent-bound subdomain credential and its originating live user session, followed by route/storage policy. Anonymous routes/assets require explicit public exposure and matching public access. |
| External MCP | Its configured exposure policy; authenticated calls use user access or audience-bound OAuth MCP credentials and live grants, never an app JWT. Anonymous access requires explicit public MCP exposure and a public capability. |
| Telegram bridge | Airlock's authenticated poller supplies bridge, sender and private-chat coordinates; admission resolves the exact live platform identity link, account and bridge binding. |
| Builder integrations | Active build's opaque integration token, hash and expiry in `agent_builds`; this token is not accepted as a user or runtime app credential. |
| Host protocol | Opaque enrolled host credential, stored as a hash and selector; host/connector work also carries exact delivery fences. |
| Webhook ingress | The webhook's configured verification policy; delivery uses app authority and carries no human identity. A `none` policy provides no sender authentication. |
| SDK app listener | Exactly one target-app bearer credential on every request except built-in `GET`/`HEAD /health`, including public routes, assets, jobs and runtime invocation. |
| App-to-host API | Current app JWT generation plus the operation's service gate. Borrowing run authority additionally requires a dispatch receipt or exact current job-attempt proof. |

JWT profiles require exact HS256 and their own issuer, audience and `token_use`.
Possession of one profile does not authorize another surface. The app credential
authenticates host-to-app delivery and app-to-host requests; it is not evidence of
a human caller. User/app credential admission rejects duplicate or ambiguous
authentication headers, and browser admission rejects ambiguous cookies.
Public/member access and tenant role are separate authorization axes:
public exposure is not membership, and a tenant role does not implicitly grant
app access. `externalAuth` and external identity attributes/providers are not
implemented; these contracts do not provide a general external-user
authentication feature.

## SDK Caller Snapshot

Go app handlers use `agentsdk.CallerFromContext(ctx)`. `Caller` has private state
and exposes `Kind()`, `Access()`, `User() (User, bool)`,
`Initiator() (User, bool)`, and `Origin()`. It contains attribution for app logic,
not credentials or an independently transferable proof of host authority.
The nested `wire.Caller` arrives through authenticated host delivery. Its source
header is not a standalone signed identity token. Invocation receipts, job lease
tokens, session coordinates, and other callback credentials are not exposed by
the public caller snapshot.

`CallerAnonymous`, `CallerUser`, and `CallerApplication` distinguish the actor
from app access. `User` exposes `ID`, `Email`, `DisplayName`, and
`PlatformMember`; the ID scopes user-owned app data, while email and display name
are display claims. Every admitted human is a platform member, including a user
with public app access. Neither an access tier nor a platform label establishes
membership. No external-user attribute map or identity-provider API is exposed.

`Origin` distinguishes HTTP, chat, MCP, schedule, and application interfaces,
with unknown available for injected tests. `Platform` and `ClientID` describe
source metadata, not authority. Execution distinguishes request, job, background,
and startup. User jobs preserve the initiating user and source interface while
executing as jobs. App-owned webhooks, crons, and native work have no human user
or initiator. There is no app-owned launch-with-human-initiator feature, and the
app owner is never synthesized as the initiator.

`CallerFromContext` requires framework-supplied or explicitly injected test
state; missing context panics rather than representing anonymous access. Startup
hooks receive an application caller with startup execution. Direct app background
API calls create their own execution context without mutating the input context;
that does not make a caller available on arbitrary contexts. Reading a caller
never materializes a run or performs network I/O. Pass handler contexts through
to SDK operations so private callback proof remains attached.

Source migration is explicit: human call sites use
`agentsdk.CallerFromContext(ctx).User()` and handle the returned bool. There is no
`UserFromContext` compatibility API. Unit tests supply caller state through
`agenttest.WithUser` or `agenttest.WithCaller(ctx, user, access)` for human cases,
and `agenttest.WithCallerInfo(ctx, agenttest.CallerInfo)` for anonymous/application
cases. Test state does not grant host authority or cross a network boundary.
JavaScript's read-only `user` binding remains separate; no JavaScript caller API
is exposed.

## Immutable Origins

`service/execution` admits a verified principal and atomically persists an
`execution_origins` record with the run, execution kind, single-use resume
binding and any hosted conversation lease. Origins hold credential coordinates,
not reusable bearer tokens: user/session IDs, account epoch, credential expiry,
OAuth client/audience/scope, bridge/link/sender/chat coordinates, and app runtime
generation where applicable. Database triggers protect origin and run/job
bindings from mutation. A job retains its initiating ingress separately from its
`job` execution kind.

Broker, model, file, route and lease operations restore the exact run's origin
and recheck live authority. Current grants can narrow the admitted access; they
cannot elevate it beyond the run's admitted ceiling. Run input, caller-supplied
user IDs, access assertions, conversation display fields and `Platform` metadata
cannot authorize an operation. `Caller.Origin().Interface` identifies a surface
such as chat; `Origin.Platform` may display `telegram`. Trusted bridge identity
comes from the authenticated transport and persisted link, not either label.

System chat stores private immutable `system_run_origins` bound to the exact
user and conversation. `auth.RestoreSystemRunIdentity` restores their live proof.
Build, upgrade, rollback and managed-bot work can carry an immutable
`async_chat_origins` reference to the initiating app or system run. Completion
notifications and follow-up model turns revalidate that exact origin. Neither a
build correlation UUID nor the newest run in a conversation establishes it.
Absent or unknown provenance cannot authorize resumed work or a follow-up turn.

## Callbacks And Revocation

Airlock issues a cryptographically random 256-bit invocation receipt immediately
before dispatch. `execution_invocations` stores only its SHA-256 hash, exact run,
app and runtime generation, creation/expiry times, and closure/revocation state.
The receipt lifetime is bounded to 25 hours, covering the supported 24-hour job
deadline plus cleanup. Dispatch closure denies further operational callbacks;
expiry fences a crashed dispatcher. Run termination or owner-token change and
app-generation rotation or inactive app status revoke open receipts in the
database. Receipts are credentials and must not enter logs or app payloads.

Operational callbacks require a live, open, unrevoked receipt and the current app
credential, then restore the run's live authority. Job callbacks may use the
exact live job ID, attempt number and lease token bound to that run and runtime
generation. A run UUID alone is never a callback credential. The SDK propagates
callback proof from its admitted handler context; application code should pass
that context to SDK operations.

Terminal completion has a narrower gate. A closed but unrevoked receipt remains
eligible until expiry only for terminal telemetry of a still-running,
nonhosted, non-prompt run. The current app generation and run binding must match;
jobs also require their exact running, unexpired attempt and no cancellation
request. Completion locks the run and preserves cancellation/attempt fencing.
It does not restore human operational authority or require the initiating human
credential to remain live. An app cannot complete a hosted run borrowed for a
capability invocation.

Interactive user/subdomain/OAuth execution honors initiating token expiry and
live credential checks. Durable user jobs ignore that token lifetime, but check
the live account and auth epoch, secured-account state, originating session's
existence and revocation, OAuth grant scope/expiry/revocation, exact bridge link,
and current app grants. Session expiry alone is not the durable-job revocation
gate. Logout revokes its session, so jobs initiated through that session can be
cancelled at admission or live revalidation. Closing a browser without session
revocation does not have that effect. A transient lookup failure stops in-flight
I/O but is not treated as authoritative durable cancellation; lease recovery
owns retries. App-owned webhooks, crons and native work have no human identity.

## Native Code Trust

Native app code is trusted with its own database schema, bound resources and
runtime credentials. The app protocol is not a native-code sandbox: it cannot
prevent that code from accessing its own resources or reading credentials in its
process. Host-side identity and capability checks protect host-mediated access
and cross-app boundaries. They do not make user-attributed app data inaccessible
to the app that owns it. See [agent isolation](agent-isolation.md) for container
and network controls and [JavaScript executor release](js-executor-release.md)
for the separate network-none executor recipe.

## Process Shutdown

`api.NewRouter` returns a concrete HTTP handler with `Shutdown(ctx)`. Owners must
stop HTTP ingress and other prompt producers and drain both `http.Server` and the
router before closing the database, PubSub, executor manager or logger. Router
shutdown rejects prompt and upgrade-follow-up admission, interrupts hosted chat,
and waits for runtime cleanup, lease heartbeats, in-progress settlement and event
publishers. Stream EOF is not proof that the host has finished settlement.

Hosted interruption is not user cancellation or credential revocation. Owners
interrupted before settlement stop renewing their conversation leases; the shared
lease recovery transaction settles history after expiry. Durable job workers use
their separate attempt-interruption and retry lifecycle, not chat shutdown.

Production allows 30 seconds for HTTP, chat and background-worker drain. A drain
deadline is an error, not permission to close shared dependencies under live work:
the process exits and surviving replicas or restart recover expired ownership.
Embedded owners may keep dependencies open and call `Shutdown` again to wait.

## Deployment And Migrations

The planned cutover starts at Goose version 7 and applies
`008_auth_execution.sql` to reach version 8. Migrations `001` through `007` are
the applied baseline and remain unchanged. This is a coordinated cutover, not a
rolling mixed-protocol deployment.

1. Quiesce ingress, scheduling and dispatch, drain active work, and stop every
   incompatible replica and app runtime before applying migration 008. Do not
   allow an originless writer to reconnect after migration.
2. Take a restorable database backup and retain matching application images,
   configuration and encryption keys under the normal secret-backup controls.
   Verify restoration before proceeding; do not put secrets in source exports.
3. Verify the applied Goose version is 7, then apply migration 008 with all
   incompatible writers stopped and verify the applied version is 8.
   Review the effects below, including cancellation of queued originless jobs.
4. Start compatible replicas, rebuild apps with the compatible SDK, and verify
   v2 generation-bound manifest sync. Confirm checkpoint repair, stale lease
   rejection, callback closure and live revocation before reopening ingress.
5. If rollback across 008 is necessary, stop writers and restore the backup with
   matching binaries. Migration 008 is irreversible: its single Down raises an
   exception requiring backup restoration. It cannot recover cancelled work,
   dropped tables' contents, or discarded provenance.

| Migration | Effect And Down Behavior |
| --- | --- |
| `008_auth_execution.sql` | In order: locks leases/runs/delegations, identifies A2A/delegated runs and descendants, cancels active affected work, clears checkpoints, queues session repair, rotates owner fences and removes leases/MCP reservations; drops `hosted_delegations`, `agent_siblings`, the settlement function and `agents.tools_hash`, retaining runs/conversations for audit without exposing transport-only conversations as interactive threads. Creates immutable execution origins and run/job binding guards; runs/jobs without admitted provenance receive explicit `unknown` attribution, not inferred user credentials; cancels running/suspended originless app runs and queued/running jobs, interrupts attempts, rotates fences, removes conversation leases and queues checkpoint repair. Adds an independent owner token to every MCP reservation, then drops the backfill default. Creates private immutable system-run provenance with exact user/conversation guards, without synthesizing proofs for runs without provenance. Creates immutable initiating-run references and guarded build/managed-bot bindings; work without a reference cannot derive authority from display/correlation fields. Creates hash-only callback receipts with bounded expiry and database run/app revocation triggers. The entire migration is irreversible: its single Down raises an exception requiring backup restoration. |

System runs without provenance fail identity restoration; no user identity is
inferred from history. Preserve migration regression tests and test against a
restored production-shaped database before release.

## Packaging Gates

Private CI and release run `go run ./cmd/airlockvet check`, which explicitly scans
the core and nested enterprise modules. The public release gate runs
`GOWORK=off go run ./cmd/airlockvet ./...` over the complete public core before
image verification and tag creation; it must not invoke the private enterprise
check or fetch private source.

Public candidates select an explicit committed revision through `git archive`
and the HQ `automation/airlock-public.json` allowlist. The
`service/execution/executiontest/` helper subtree is explicitly excluded because
its test-only fixtures use ordinary `.go` filenames within the broad `service/`
include. Production execution services and migrations remain included. A dirty
manifest can change selection rules, not the committed source bytes: dirty and
untracked app source must never enter a candidate through a working-tree copy.
