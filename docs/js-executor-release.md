# JavaScript Executor Distribution

`config.DefaultJSExecutorImage` is
`ghcr.io/airlockrun/airlock-js-executor:v` plus `airlock.Version`.
`JS_EXECUTOR_IMAGE` is an explicit deployment override, not a separate release
version. Agent-base and agent-builder images do not contain Deno.

## Sources And Identities

`Dockerfile.js-executor` builds `agentsdk/cmd/jsexecutor` and packages the
controller and worker from `agentsdk/jsexec/runtime/`, using the canonical SDK
runtime layout. Its default SDK source is the published requirement in Airlock's
`go.mod`, resolved with `GOWORK=off`. A release requires a published SDK version
containing these packages and assets; a sibling development checkout cannot
satisfy that dependency.

The source identities are distinct:

- Deno: `jsexec.DenoImage`, the canonical registry manifest digest. The verified
  digest `sha256:2014dc167ece617ef7e7ba40631ac2234c59e75ce693e7cc2dc2602b3c87859d`
  runs Deno 2.9.6. The build smoke compares the complete installed version output
  to that exact base image, not to an independently maintained version pin.
- Executor protocol: the SHA-256 of the SDK's actual `jsexec/protocol.go` source.
  This is a source identity, not a separately released compatibility version.
- Airlock: its release version and the exact gated Git revision. The tag job
  checks out the gate's revision rather than resolving a moving branch again.

Publication records these identities in OCI labels. HQ and the public release
workflow share the standard-library-only checker at
`scripts/js-executor-check/release/main.go`. It checks the candidate Version,
every community image referenced by its compose file, the internal source
repository label, and the executor's Deno digest, protocol source, and SDK version
against the exact published SDK pin. An absent executor fails the gate.

HQ supplies `--internal-revision` with the exact archived private commit before
making public Git mutations. The public workflow uses `--public`: every image
must declare the same nonempty full internal Git revision. That revision is
reported as image provenance, not equated with the public merge commit. Public
and internal commits have different trees and identities; consistent image
metadata alone does not prove a public-to-private tree mapping.

The checker resolves registry tags to immutable manifest digests before inspecting
metadata. After all metadata passes, it pulls and tests those exact artifacts:
the installed Deno version must match the SDK's digest-pinned base, the packaged
protocol fingerprint must match SDK source, and the packaged supervisor smoke
must succeed. Containers have no network, credentials, or host mounts, run as a
non-root user with a read-only root filesystem, and have finite resource limits.
The checker does not build or push images and needs no private HQ source or
credentials. There is no separately maintained Deno version pin.

The public workflow is exported as `public-release.yml`; internal workflows are
not exported. Its read-only `gate` job validates ancestry/version and runs the
checker. Only the dependent `tag` job can create a release App token and tag the
exact public merge commit. Direct workflow dispatch is subject to the same gate.

## Bootstrap And Release Gate

Compose's `js-executor-image` service runs `/usr/local/bin/js-executor-check`
without networking, credentials, writable root, or elevated capabilities, with
finite memory, CPU, PID, and temporary-storage limits. The check launches the
packaged supervisor, executes an async host callback, verifies retained state,
and requires filesystem denial. Airlock depends on successful completion.
Install and upgrade pull the image; upgrades remove the previous release's
executor tag only after Airlock becomes healthy.

The internal release workflow must build and smoke the executor before creating
the release tag. The existing publication matrix publishes the executor under
the same Airlock release tag as the other community images. This packaging gate
does not replace the SDK's hostile-runtime tests or certify untested security
properties.

## Development

From Airlock, build a local SDK source snapshot explicitly:

```sh
bash scripts/build-js-executor.sh ../agentsdk
```

The command freezes the selected source inputs, builds the release Dockerfile
with an explicit `sdk-source` build context, smoke-tests it, and prints a
content-addressed `airlock-js-executor:dev-<hash>` tag. It does not pull an
unpublished Airlock image. Without the argument it selects the published SDK.
`make dev` prepares this image from `AGENT_LIBS_PATH/agentsdk` when configured,
and exports its tag as `JS_EXECUTOR_IMAGE`; an explicit image override is honored.
`make dev-prepare` prepares the image alone. HQ provides the same workspace
operation through `hq dev prepare --root DIR`.

## Notices

The image contains `/usr/local/share/jsexec/THIRD_PARTY_NOTICES.md`, generated
from the supervisor's compiled Go module graph and the build toolchain's actual
Go license. Module LICENSE and NOTICE files are copied verbatim; missing files
fail the build. `scripts/check-licenses.sh` scans the supervisor dependency graph.

`scripts/js-executor-check/DENO_LICENSE` is the verbatim Deno 2.9.6 MIT license
from `https://raw.githubusercontent.com/denoland/deno/v2.9.6/LICENSE.md`.
The build smoke compares it with the upstream license at the version reported
by the digest-pinned Deno executable. The stock base image retains its operating
system notices under `/usr/share/doc`.
