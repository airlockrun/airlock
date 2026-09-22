# MCP execution

Airlock's inbound MCP endpoints require protocol `2026-07-28`. The official Go
MCP SDK serves stateless HTTP requests. Clients send the protocol and routing
headers and per-request metadata required by that revision. Discovery uses
`server/discover`; no session ID or sticky routing is required.

Authentication runs before protocol dispatch. Every tool and resource operation
uses the live Airlock principal and service authorization. Discovery is private
with a zero TTL. Tools create server-owned execution runs with credential
provenance and exact-run file access. HTTP cancellation propagates to execution;
credential revocation and permission changes are checked during execution.
Cancellation cannot undo external effects. Retrying a mutation requires an
application-defined idempotency key; a JSON-RPC ID is not such a key.

Outbound connections use `goai/mcp`, backed by the official Go MCP SDK. They
support modern discovery and compatible initialization-era servers. Airlock
supplies its network-policy HTTP client and credentials. Tool errors, ordered
content, embedded resources, audio, and structured content remain explicit in
the SDK wire response. Input-required calls return an incomplete-call error
without automatic replay or approval.

## Deployment

Deploy matching GoAI, Sol, Agent SDK, and Airlock builds in dependency order.
Committed module requirements must reference published library versions.
Inbound clients must support `2026-07-28` before cutover.

Drain and stop incompatible Airlock replicas before applying migration
`011_codegen_limits_and_stateless_mcp.sql`. It removes the request-ID cancellation reservation
table. Rollback requires a database restore and matching binaries.
