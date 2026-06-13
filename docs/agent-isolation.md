# Agent isolation & host hardening

How airlock contains the agent containers it launches, and what's left to
the operator. For reporting vulnerabilities, see [SECURITY.md](../SECURITY.md).

## Threat model (self-host)

Airlock is self-hosted. The **operator** owns and trusts the host. The
**users** of an instance author agents, and **an agent is arbitrary
code** — Go the LLM/codegen wrote, plus whatever `setup.sh` installs —
that runs in a container on the operator's machine. So users are the
threat source, and the assets to protect are: the **host**, **other
users' data**, and the **operator's secrets** (encryption key, DB
credentials, provider keys).

The container is the trust boundary. The design assumes an agent may try
to escape to the host, fork-bomb / OOM / disk-fill it, reach the cloud
metadata endpoint, or pivot to infra (postgres, object store) and sibling
agents.

Two facts shape everything below:
- **An agent can be root *inside* its container.** `setup.sh` runs as root
  at image build to install deps, so the image can contain a setuid binary
  or `sudo`. We don't try to prevent in-container root; we make it
  harmless.
- **Containers share the host kernel.** Namespace hardening raises the bar
  to "needs a kernel 0-day"; only a sandboxed runtime (gVisor) shrinks
  that surface materially.

## Controls

### Tier 1 — shipped by default (invisible to legitimate agents)

Applied to every agent runtime container by
`container.buildAgentHostConfig` (`container/docker.go`). These strip only
what no honest agent uses, so there is no usability cost:

- **`CapDrop: ALL`** — the agent serves HTTP on `:8080` and shells out to
  nothing (exec runs in the separate toolserver), so it needs no Linux
  capabilities. Even container-root is then powerless — no `NET_RAW`
  (ARP-spoof/sniff), no `SYS_*`.
- **`no-new-privileges`** — `execve` ignores setuid bits / file caps, so a
  setuid binary or `sudo` baked by a malicious `setup.sh` at build **can't
  re-elevate** at runtime. Build-time root is unaffected.
- **`PidsLimit` (1024)** — fork-bomb cap; environment-independent.
- **`CPUShares` (512)** — relative weight below infra's default (1024) so
  an agent can't starve airlock/postgres. No host sizing needed.
- **`OomScoreAdj` (500)** — under host memory pressure the kernel kills an
  agent *before* infra, so the host survives collective overcommit
  **without** capping how many agents run (which would break usability).
- **Default seccomp** — left in place (not `unconfined`).
- **host-gateway dropped in prod** — `host.docker.internal:host-gateway`
  is added only in dev (`AgentLibsPathExplicit`, where airlock runs on the
  host and agents reach it that way). In prod, agents reach airlock by
  service DNS (`API_URL_AGENT`), so the alias — and the host reachability
  it grants — is omitted.

### Tier 2 — operator-configurable (generous / off by default)

- **`AGENT_MEMORY_LIMIT`** (e.g. `512m`, `2g`; default unset = unlimited) —
  per-agent hard memory cap (swap pinned to the limit). Off by default
  because the host's size is unknown and `OomScoreAdj` already protects the
  host; operators on small VPSes set it to scope a leaker cleanly.

### Tier 3 — opt-in strong isolation

- **`AGENT_SANDBOX=gvisor`** → agent containers run under the `runsc`
  (gVisor) runtime instead of `runc`. gVisor is a userspace kernel that
  intercepts the agent's syscalls, so an escape attempt hits the sandbox
  rather than the host kernel — VM-grade-ish containment without a VM (some
  perf cost on syscall/IO-heavy agents). Tier-1 hardening still applies on
  top. Requires `runsc` installed and registered as a Docker runtime on the
  host (`AGENT_SANDBOX` unset → default `runc`).

## Residual risk & deploy-level follow-ups (not in code)

Tier 1 gets you to "an agent needs a kernel 0-day to touch the host, and
can't reach infra/siblings." Closing the rest is deployment topology the
operator owns — **recommended, not enforced by airlock**:

- **Network segmentation** — *partially shipped.* Agent runtime containers
  attach to a dedicated `AGENT_NETWORK` (`AGENT_NETWORK` env; prod compose
  sets it to `airlock-agents`) carrying only **airlock + postgres** —
  rustfs, caddy, the frontend, and build containers are excluded, so an
  agent can't reach them. Postgres reachability is by design (scoped
  per-agent schema + role via `AIRLOCK_DB_URL`); S3 goes through airlock's
  storage API and presigned public URLs, never direct. Agents keep internet
  egress (bridge NAT). **Residual:** agents on the shared `agents` network
  can still reach *each other* — accepted, because A2A is proxied through
  airlock and an agent's `:8080` is JWT-gated; full sibling isolation would
  need a network per agent. Dev leaves `AGENT_NETWORK` unset (agents stay on
  the single dev network — the dev box is the trusted operator's).
- **Metadata egress firewall** — dropping the host-gateway alias removes
  the convenient host route, but a hard block of `169.254.169.254` (cloud
  credential endpoint) needs a host iptables/nftables rule or IMDSv2
  hop-limit=1.
- **Rootless BuildKit** — *shipped (prod, opt-in via `BUILDKIT_HOST`).* The
  prod compose runs a `moby/buildkit:rootless` daemon, and airlock builds
  agent images through it via a remote buildx builder (`builder.buildImage`)
  rather than the host's root `dockerd`. So an agent's untrusted `setup.sh`
  runs as root *inside buildkitd* (an unprivileged host uid), closing the
  build-time escape-to-host-root path (cf. CVE-2024-21626). `BUILDKIT_HOST`
  unset → legacy host `docker build` (dev). **Bound:** airlock still mounts
  the docker socket for `docker run`/`pull`/`cp` + agent lifecycle, so
  airlock itself remains root-equivalent — what this removes is *untrusted
  agent code running as root on the host daemon*, not airlock's own
  privilege. Registry mode (`AGENT_REGISTRY_URL`) uses buildx `--push`,
  which needs buildkitd to hold registry creds. **Host prerequisites:**
  unprivileged user namespaces + `/dev/fuse`. On Ubuntu 23.10+ set
  `kernel.apparmor_restrict_unprivileged_userns=0` (sysctl) or install the
  `rootlesskit` AppArmor profile, or buildkitd won't start. The compose
  passes `--oci-worker-no-process-sandbox` so it also works on container/LXC
  hosts that can't nest namespaces (drop it on bare-metal/VM for stricter
  per-step isolation).
- **`userns-remap` / rootless Docker** — daemon-level remap of
  container-root → an unprivileged host uid, covering builds, the
  toolserver, and runtime agents in one setting. The low-effort
  defense-in-depth if you don't run gVisor.

For deployments that run **untrusted third-party** agents (not the current
target), prefer a VM-isolated runtime (gVisor everywhere, or
Kata/Firecracker) — namespaces alone are not a boundary against a
determined attacker hunting a kernel bug.
