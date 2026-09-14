# Application Task Agents

Application task agents are app-owned model loops hosted by Airlock through
`agentsdk/agentruntime`. App containers execute authenticated capabilities, not
the agent loop. Each registered definition declares its instructions, text model
slot, typed input/output schemas, private tools, MCP handles, optional subagents,
budget and concurrency limits. The complete declaration is bound by its shared
`wire.AgentDefinitionHash` contract identity.
Runtime manifests and definition snapshots use PostgreSQL JSON to preserve
schema/example number spellings covered by that shared hash. Request payloads,
checkpoints and replies use JSONB; idempotency compares numerical values exactly.

## Native API

The agent-internal routes require the current app JWT:

| Method | Path | Wire Request |
| --- | --- | --- |
| POST | `/api/agent/agents/{definition}/runs` | `StartAgentRequest` |
| GET | `/api/agent/agents/{definition}/runs` | `limit`, `cursor`, `status`, `sessionId`, `contractHash` |
| GET | `/api/agent/agents/{definition}/runs/{id}` | None |
| DELETE | `/api/agent/agents/{definition}/runs/{id}` | None |
| POST | `/api/agent/agents/{definition}/sessions/{sessionID}/continue` | `ContinueAgentRequest` |

Start creates a fresh logical session and application conversation. Native
launches are deliberately application-owned even when called by trusted Go code
handling a human request. Neither source-run headers nor input metadata borrow
human authority. Reads do not materialize background SDK runs. Run and session
IDs are app-and-definition-scoped selectors, not bearer capabilities.
Typed SDK lists supply their exact contract hash. Filtering happens before
pagination; omitting the hash permits raw historical results across revisions.
Malformed or ambiguous hash filters are rejected.

`RequestID` is stable across source executions and scoped to the app and
definition. An exact replay returns the existing call with `Created: false`;
changed input, continuation prompt, target session, or contract hash conflicts.
Start never attaches to another session. Continue requires the session's latest
run to be `completed` and creates a new run in that same session. A database
unique index permits only one queued, running, or waiting call per session;
competing continuations fail rather than enter a continuation queue.

Replies are either `{kind: "output", output: ...}` or
`{kind: "needs_input", question: ...}`. Both complete the run. There is no input
suspension or yield state. Output is validated against the admitted output
schema. Replies become visible through the native API only after terminal
completion commits. Cancelling is asynchronous: the DELETE response can still report a
nonterminal status while an owner stops. Poll/Get reports authoritative terminal
state. Stopping an SDK Wait only stops polling and never cancels the call.

## Durable Execution

`agent_task_sessions` binds each logical session to an application-owned
`agent_conversations` row with no human user. These conversations do not enter
the browser's web/bridge conversation queries. `agent_task_calls` records logical
runs, definition snapshots, request identities, hierarchy, attempts, checkpoints,
usage and terminal replies. Existing `runs` rows retain immutable app execution
origins and normal usage/audit linkage.

Every replica runs workers. A transaction advisory lock serializes global
capacity, per-definition capacity, child admission and budget updates. Running
calls hold global capacity through database claims; waiting calls release that
capacity but retain their per-definition active-call slot. Local goroutines are
only worker capacity and lifecycle management, never the source of ownership.
Each claim acquires the exact session's existing conversation lease with a fresh
owner token. Checkpoint, transcript, callback and completion writes are fenced
against that token. Receipt issuance requires the expected owner token, and
internal ownership ceilings prevent nested model/broker operations from borrowing
a replacement worker's lease. Leases last 30 seconds and workers renew once per second.

`agent_task_claims` preserves each run/session/owner binding. Model usage is
recorded once per host-generated request ID in `agent_task_usage`, atomically
with local/root counters. A known expired owner may settle late reported usage;
it cannot issue another model request, dispatch a tool, mint a callback receipt,
or write a checkpoint. Conflicting usage retries and unknown owners are rejected.
Usage records distinguish unreported counters from reported zero usage. A
streaming model that omits input/output usage fails the affected token-limited
call or root instead of silently treating its token budget as unlimited.

`Store.SaveCheckpoint` atomically appends `Checkpoint.Append` through the existing
conversation codec and replaces the checkpoint at the next revision. Exact
committed retries do not append twice; conflicting or stale revisions fail.
Compaction advances the existing conversation context checkpoint while retaining
audit history. There is no JavaScript heap checkpoint or alternate transcript.
Per-response input/output observations persist at their transcript boundary and
are restored for compaction, independently of root/billing totals. Retired
observations do not survive a context-window reset. Task store transactions take
the scheduler advisory lock before lease, run, conversation and checkpoint rows,
so cancellation cannot invert their lock order.
JavaScript executors are allocated lazily through the production executor
manager and destroyed on each attempt's exit, including waits.

Interrupted attempts recover only within `MaxAttempts`. A timestamped persisted
notice identifies the interrupted activity and recovery time. The runtime
resumes the ordered checkpointed batch. Spawn, child continuation, wait and
completion are idempotent controls. Interrupted generic tools, including a
partially executed `run_js`, have unknown external effects and are not replayed.
The model must use safe reads or request clarification instead of blindly
repeating them. Provider/model failures are terminal unless execution itself was
interrupted. There is no external-state reconciliation service.
An expired owner's valid completed checkpoint settles its reply without another
attempt, including at `MaxAttempts = 1`. Token/time exhaustion, recorded failures
and cancellation retain their settlement precedence; reaching a step limit does
not invalidate its final reserved turn. Executor cleanup errors are logged
separately and do not turn a completed runtime result into a failure.

## Subagents And Budgets

Only declared same-app children can be spawned, and children cannot spawn a
second level. Spawn and child continuation are keyed by parent run plus model
tool-call ID. Each call snapshots its referenced child contracts as well as its
own definition. A changed child contract makes that admitted parent incompatible;
recovery cannot silently reinterpret a checkpointed spawn using a new schema.
Child handles can be read, waited on, continued or cancelled only
by their admitted parent controller. Native continuation cannot detach a child
session from its parent. `MaxSubagentCalls` counts child calls including
continuations; `MaxConcurrentSubagents` counts nonterminal child calls. A parent
cannot complete while any child remains active. Parent cancellation or failed
termination requests cancellation of all outstanding children.

`wait_calls` supports `any` and `all`, an explicit zero-duration poll, a default
timeout and a configured maximum. Wait records and dependencies live in
PostgreSQL. Retrying the same wait retains its original deadline; it cannot
extend the timeout. Ready dependencies or timeout requeue the parent without
consuming an interruption attempt. Controller read/wait/cancel batches accept
1-100 distinct child IDs.
Every requeue receives a durable enqueue timestamp. An expired parent wait joins
behind already queued children, including with one global worker slot. A new
positive wait yields once even if admission consumes its timeout; an explicit
zero-duration poll does not park.

The SDK's omitted budget defaults to 150 steps. Each individual zero limit
disables that limit; an explicitly all-zero budget is invalid. Airlock persists
the admitted limits, not process defaults:

- Steps reserve model turns before dispatch, including child reasoning and
  automatic compaction. Root counters include descendants.
- Tokens count cumulative input and output usage reported by hosted models,
  including child reasoning, compaction, native callback models and token-priced
  media operations attributed to the task. In-flight requests may overshoot;
  this is not a hard token reservation mechanism.
- Timeout is an absolute wall-clock deadline from admission, including queueing,
  waits and recovery. Child deadlines cannot exceed the root deadline.
- Child continuations retain the root budget. Independent top-level Start or
  Continue calls get a fresh budget.

## Capability Boundary

Execution resolves a task's persisted definition slug/hash and current app
generation before granting its private app-run principal. Ordinary trigger
principals do not gain hosted storage authority. The broker uses
`capability.DefinitionCatalog`: only the admitted definition's private tools and
declared MCP handles are available. Empty MCP access means no chat exposure but
does not prevent explicit definition binding or trusted native Go use.

Authenticated app callbacks carry `RuntimeContext.Definition`, the admitted
caller snapshot and a short-lived invocation receipt. Receipts bind the run,
app, credential generation and owner token. Rotating a lease denies old receipts
even within the same app generation. Compatible recovery selects the current
app generation without rewriting the original execution origin; incompatible
definitions or runtime protocols fail closed. Deployment-paused apps are not
claimed until cutover completes.

Hosted file operations restore the exact app run rather than requiring an
inbound app JWT on a worker. Task fixed file tools resolve model-selected paths
before native dispatch and enforce conversation/run directory scope; user-scoped
files cannot borrow an absent human identity. File-list calls require a declared
directory path. Trusted native Go handlers retain access to their app's own
resources and credentials; the callback protocol is not a native-code sandbox.

Agent controls are direct model tools, not JavaScript bindings. Task runs are not
exposed as browser chat, external MCP prompt tools, app-to-app calls, a shared
board or `bash_async`. Conversation-output and app-upgrade controls are omitted
from task catalogs.

## Operations

Production configuration:

| Environment Variable | Default |
| --- | --- |
| `AGENT_TASK_GLOBAL_CONCURRENCY` | `32` |
| `AGENT_TASK_LOCAL_CONCURRENCY` | `4` |
| `AGENT_TASK_DEFAULT_WAIT_SECONDS` | `30` |
| `AGENT_TASK_MAX_WAIT_SECONDS` | `300` |

Concurrency must be positive. Wait settings must satisfy
`0 < default <= max <= 86400` seconds. Replicas sharing a database must use the
same global concurrency and wait policy. Definition-level limits remain in the
admitted immutable contract snapshot.

The production router starts the worker pool and owns its shutdown. Stop ingress
and other producers, call `Router.Shutdown`, and keep the database, executor
manager and logger alive until drain completes. Shutdown interrupts workers
without requesting user cancellation; unfinished leases expire for shared
recovery. Scheduling passes and an independent maintenance loop reconcile expired
claims, cancellations, deadlines and ready waits, including after process restart
and while every local execution worker is occupied.

Apply the forward migration `009_agent_runs.sql` through the normal deployment
migration process after draining incompatible replicas and taking a restorable
backup. It adds task state and owner-token callback fencing. Down refuses to
discard durable execution provenance; restoration requires the matching database
backup and binaries. No SDK/Sol schema migration or live manual repair is part of
normal recovery.

## Verification

`go test ./...` exercises core behavior, including the native routes and the
production router-owned worker against an OpenAI-compatible HTTP test model.
`go test -race ./service/agentruns` runs PostgreSQL concurrency, idempotency,
scope, budget, wait, recovery, checkpoint, compaction and lease-fencing tests.
`go run ./cmd/airlockvet check` checks both core and enterprise architecture.
Set `AIRLOCK_TEST_JS_IMAGE` to a compatible production executor image when
running `go test ./apitest` to include the real SDK app/private-tool/isolated-Deno
task integration test and the existing production executor scenarios.
