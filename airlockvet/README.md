# Architecture Checks

Run `go run ./cmd/airlockvet check` from the private Airlock module root.
HQ workspace validation, CI, and the release gate use this same command. It
analyzes every core package and then explicitly runs in the nested enterprise
module, including tests. Either scan failing fails the command; the enterprise
scan still runs after core diagnostics. The command accepts no package overrides
or analyzer-disable flags. Standalone core consumers can run
`go run ./cmd/airlockvet ./...` without the private enterprise module.

## Rules

- `serviceauthz`: references to `authz.Authorize*`, effective agent access,
  resource capability resolution, and the named access/policy helpers belong
  only in core or enterprise `service/` packages and core `authz`. Calls, function
  values, method expressions, promoted methods, import aliases, and dot imports
  resolve through Go objects. There is no suppression for this boundary.
- `nodbq`: query method references on `dbq.Queries` and `dbq.Querier` are prohibited
  in core `api`, `agentapi`, `hostapi`, `sysagent`, and enterprise `api`, `agentapi`,
  `hostapi`, including their subpackages. Services own capabilities. A narrow
  plumbing exception requires a local `allow-dbq` directive with its reason.
  Query construction and row/parameter types are not query operations.
- `noinlinerole`: tenant role constants, `Role.AtLeast`, and `RequireTenantRole`
  belong in `auth` or `authz`. Only constant serialization in `convert` and fixture
  construction in `apitest` have package exemptions; comparator references do
  not. Other non-policy uses require a local `allow-inline-role` reason.
- `policy`: every declared `authz.Action` has a unique nonempty value and an
  explicit policy entry. Each entry declares a valid axis and exactly that
  axis's valid access field. Outside `authz`, `RequiredTenantRole` and
  `AuthorizeOwnedResource` require direct calls with declared tenant-axis Action
  constants. Cross-package axis checks use analysis facts, not spelling.
- `checkedaccess`: callers use `EffectiveAgentAccessChecked`, not
  helpers that discard lookup failures. Checked calls must be direct; blank error
  assignments and discarded results (including `go` and `defer`) fail.
- `origins`: `auth.RestoreRunIdentity` belongs only in `auth` and
  `service/execution`; `RestoreSystemRunIdentity` belongs only in `auth` and
  `service/systemchat`. References, not just calls, are checked.
- `origins`: `authz.UserPrincipal` is restricted to `authz`, `service/execution`,
  `service/connections`, and `service/inboundoauth`. These services restore durable
  job or single-use OAuth authority. Other callers preserve verified admission
  through `authz.PrincipalFromClaims`. Populated Principal literals, conversions,
  field mutations, and field-address aliases belong only in `authz`, not arbitrary
  services. Empty error-return values are permitted. Identity construction belongs
  only in `auth`; Identity fields and factories remain private. The verified
  `Claims.Identity` accessor is permitted.
- `origins`: `authz.AppRunPrincipal` belongs only in `authz` and
  `service/execution`. `wire.RuntimeAgentDefinition` construction and mutation
  belong only in execution admission, alongside the other runtime authority types.
- `origins`: populated `wire.RuntimeContext`, `RuntimeOrigin`, and
  `RuntimeJobContext` values, conversions, and field writes belong only in
  `service/execution`. Direct JSON decoding into principal/identity/runtime
  authority is prohibited. Reading or forwarding already admitted values is allowed.
- `origins`: `CreateExecutionOrigin`, `CreateExecutionInvocation`, and `InsertAgentJobFromCron` belong in
  `service/execution`; `CreateRun` belongs in execution or `service/appruntime`;
  `CreateSystemRun`, `CreateSystemRunOrigin`, and `CreateAsyncChatOrigin` belong in
  `service/systemchat`; `AdmitAppRunGeneration` belongs in `service/appruntime`.
  The exact `service/execution/executiontest` helper package may create app runs
  and origins, but production files may not import it. These are exact package
  permissions, not subtree exemptions, and have no suppression tags.
- `writeproto` and `agentwire`: core browser handlers use proto wire helpers;
  agent wire bodies must not introduce local named protocol types.
- `suppressions`: directives use exactly
  `// airlockvet:<known-tag> reason: <nonempty reason>`. Known tags are
  `allow-dbq`, `allow-inline-role`, `allow-writejson`, and `allow-agentwire`.
  A directive applies only to its own line or the next line. Unknown tags,
  malformed directives, and unused directives fail, including directives in
  packages outside a rule's scope. Prose containing an example is not a directive.

Production boundary rules exclude `_test.go` fixture operations. Malformed
directives are rejected in tests as well.

## Limits

These checks enforce package boundaries and policy declarations, not control-flow
proof that a service authorizes before every effect. Counting `Authorize` calls
does not establish that property. Behavioral service authorization tests remain
necessary. Custom interfaces that erase a query receiver's package identity,
raw SQL, hand-written string role comparisons, and arbitrary wrappers require
review; this is not a whole-program taint analysis.

The origin rules protect the named primitive APIs and direct typed construction,
not arbitrary data flow through interfaces, reflection, decoder aliases, nested
request payloads, or forwarding wrappers. A RuntimeContext received inside a wire
request still needs service-owned re-resolution before use. Checked-access rules
detect explicit error discard, not a stored error subsequently ignored or replaced.
Review new SQL writers and exported service factories against these contracts;
the analyzer does not parse SQL to discover new authority-writing methods.

Run analyzer fixtures with `go test ./airlockvet ./cmd/airlockvet`. Fixture tests
exercise prohibited references and permitted service calls, not call-count proofs.
