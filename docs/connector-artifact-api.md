# Connector Artifact Operator API

Same-repository connector artifacts are addressed through an agent's connector
need. Operator clients use the following authenticated routes:

```text
GET  /api/v1/agents/{agentID}/needs/connector/{slug}/artifacts
POST /api/v1/agents/{agentID}/needs/connector/{slug}/artifacts/{artifactFileID}/download
```

Both routes require agent-admin access. The list response is
`ListConnectorArtifactsResponse`; clients read `artifactSets`, then select a
platform entry from `ConnectorArtifactSetInfo.files`. The file's server-issued
`id` is the only download selector. Artifact version and platform strings are
display metadata and are not download authorization identifiers. The deprecated
`versions` field is not populated. `ConnectorArtifactSetInfo.serviceMode` is the
immutable `user` or `system` service mode reported by the inspected connector
manifest and persisted with the build. Rows without that metadata return an
empty value; clients must not infer a mode or generate elevation commands for
them.

Artifact platforms are `linux-amd64`, `linux-arm64`, `linux-armv7`,
`windows-amd64`, `windows-arm64`, `darwin-amd64`, and `darwin-arm64`.
`linux-armv7` uses `GOARCH=arm` and `GOARM=7`. Linux and macOS artifacts are
extensionless pure-Go executables; Windows artifacts use `.exe`. The API
persists, lists, and authorizes downloads by file ID without applying an
OS-specific filter.

The download request is `DownloadConnectorArtifactRequest`. Set `notices` to
download that file's third-party notices instead of the executable. The response
is `DownloadConnectorArtifactResponse`; its `downloadUrl` is short-lived and scoped to
the selected content-addressed object. Clients display `filename`, `sha256`,
`sizeBytes`, and `expiresAt` from the same response.

Operator clients verify the displayed SHA-256 before execution and apply
elevation only when `serviceMode` is `system`. Darwin artifacts require `user`
service mode and install as per-user launchd LaunchAgents without `sudo`. macOS
clients also mark the file executable and explain that artifacts are unsigned
and not notarized. Quarantine removal is never part of install or update
commands. After successful verification, a separate recovery action may remove
only the selected file's `com.apple.quarantine` attribute; it must not disable
Gatekeeper or clear attributes recursively. TCC can independently require or
deny access to protected files, folders, and services.

Presigned executable and notices URLs sign a safe `Content-Disposition`
attachment filename. Cross-origin downloads therefore retain the exact
filename shown by the API and referenced by checksum and lifecycle commands.

Connector interface publication and heartbeat accept `artifactDigest` as the
required lowercase SHA-256 of the installed executable. Airlock uses an exact match
against `ConnectorArtifactFileInfo.sha256` to retain installed binaries. An
invalid or missing protocol digest is rejected.

Connector operator detail first resolves the reported executable digest to a
successful artifact file to determine its platform. It then selects the newest
retained successful artifact set with the same kind and contract. `current`
means the newest set contains the exact reported executable digest for that
platform. A different executable with the same interface hash is
`update_available`; a different interface that still structurally satisfies
the installed interface is `update_recommended`. An unresolvable installed
digest, missing target for the resolved platform, incompatible interface, or
other unresolved comparison is `manual_update_required`. A connector reporting
an unsupported protocol major is `unsupported_protocol`.
