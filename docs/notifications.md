# Topic Notifications

Topics declare access and default enrollment. An omitted enrollment is
`default_off`. `default_on` enrolls eligible authenticated users, including public
app users when access is public. A topic/user override takes precedence over the
default and survives conversation deletion. Directory presence does not enroll
a user or establish app authority.

`GET /api/agent/members` uses the current app credential and returns humans with
actual direct or inherited role-group app grants, including public grants.
Groups expand to humans; each human appears once with maximum access
(`admin > user > public`). Humans without grants are excluded. Each `members`
entry contains `user` (ID, email, display name, `platformMember: true`) and
`access`. App-owned callers do not borrow the owner's identity.
This native Go API is not a JavaScript or anonymous endpoint. `limit` defaults
to 100 (including zero) and allows at most 1000; negative, empty, repeated, and
malformed limits fail. `nextCursor` continues via `cursor`, ordered by immutable
user creation time and ID. Cursors are app-bound; malformed, empty, repeated, or
cross-app cursors fail. Pages reflect live grants, not a frozen snapshot.

## Routing

Only bridge conversations are durable notification routes. An enrolled user
without a usable explicit route gets one automatic route, chosen by the most
recent bridge user activity. Notifications never advance that timestamp. A new
conversation does not displace an existing usable route. First bridge messages
resolve routes; publishing also resolves routes so newly declared default-on
topics can use existing conversations.

Bridge subscribe enables the user preference and adds or promotes the current
conversation to an explicit route. It removes automatic routing and preserves
other explicit routes. Bridge unsubscribe removes only the current route; when
no route remains it disables enrollment. Web subscribe enables the preference
without adding a destination. Web unsubscribe is global: it disables enrollment
and removes all routes. An explicit subscribe is required to undo that opt-out.

Topic row locks serialize route selection, preference writes, and topic sync
across replicas. A partial unique index bounds automatic routes to one per
topic/user. Live account state, topic access including role-group grants, bridge
binding, and platform identity are checked before send. Permanent database-side
route loss permits repair. An existing bridge in an error state keeps its route
reserved; send errors, timeouts, rate limits, and ambiguous outcomes do not switch
destinations. Publish reports delivery errors and does not automatically retry.
A caller retry can duplicate already delivered parts or explicit routes.

Definitive Telegram blocked-user, deactivated-user, and missing-chat responses
mark the destination unavailable in PostgreSQL. Repair happens on the next
publication, not after a possibly partial send. A new inbound bridge message
clears that marker; a send failure observed before newer user activity cannot
mark the recovered route unavailable.

Broadcast selects enrolled users with valid routes. `PerUser` topics reject
broadcast and require an internal UUID target. Bridge transcript messages are
UI-visible but excluded from LLM context.

## Live Web Mirror

`topic.notification` uses the typed `NotificationEvent` payload with no
conversation ID. It is addressed to one app and one user and published once per
recipient, irrespective of the number of bridge routes. The open chat attaches
it only to its active conversation. No web conversation or web message row is
created. The bounded shared realtime log relays it across replicas but excludes
it from reconnect replay. Offline web users do not receive it later. Direct
conversation output retains its separate persisted `notification` semantics.

## Migration 010

`010_host_contract_singleton.sql` includes topic enrollment, user preferences, route
metadata, and bridge user activity alongside host policy changes. Stop
incompatible replicas and take a database backup before applying it. Existing
bridge subscriptions become explicit routes with enabled preferences. Existing
web subscriptions become enabled preferences without web routes. No recorded
subscription means inheritance; a historical opt-out cannot be inferred from an
absent subscription row. Existing transcript rows remain intact. Downgrading
discards the new preference and route metadata, so restoring that state requires
the pre-downgrade backup.
