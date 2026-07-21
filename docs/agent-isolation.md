# Agent isolation & host hardening

How airlock contains the agent containers it launches, and what's left to
the operator. For reporting vulnerabilities, see [SECURITY.md](../SECURITY.md).

## Threat model (self-host)

Airlock is self-hosted. The **operator** owns and trusts the host. The
**users** of an instance author agents, and **an agent is arbitrary
code** - Go the LLM/codegen wrote, plus whatever `setup.sh` installs -
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

### Tier 1 - shipped by default (invisible to legitimate agents)

Runtime hardening is assembled in `container/docker.go`; brokered destination
checks live in `networkpolicy`, and Compose supplies trusted dependency labels.
These controls remove paths no honest runtime agent needs:

- **`CapDrop: ALL`** - the agent serves HTTP on `:8080` and shells out to
  nothing (exec runs in the separate toolserver), so it needs no Linux
  capabilities. Even container-root is then powerless - no `NET_RAW`
  (ARP-spoof/sniff), no `SYS_*`.
- **`no-new-privileges`** - `execve` ignores setuid bits / file caps, so a
  setuid binary or `sudo` baked by a malicious `setup.sh` at build **can't
  re-elevate** at runtime. Build-time root is unaffected.
- **`PidsLimit` (1024)** - fork-bomb cap; environment-independent.
- **`CPUShares` (512)** - relative weight below infra's default (1024) so
  an agent can't starve airlock/postgres. No host sizing needed.
- **`OomScoreAdj` (500)** - under host memory pressure the kernel kills an
  agent *before* infra, so the host survives collective overcommit
  **without** capping how many agents run (which would break usability).
- **Default seccomp** - left in place (not `unconfined`).
- **host-gateway is explicit** - `AGENT_HOST_GATEWAY=true` adds
  `host.docker.internal:host-gateway` when Airlock runs natively and agents
  call it through the host. Container deployments omit the alias and its host
  reachability; agents use service DNS through `API_URL_AGENT`.
- **Brokered HTTP destination policy** - agent `httpRequest`, connection, MCP,
  and outbound OAuth calls are dialed by the Airlock process through one
  transport. Public HTTPS addresses are always allowed; `AGENT_HTTP_PRIVATE_CIDRS`
  controls non-public destinations. An unset value is public-only; installer-generated
  configuration allows RFC1918 IPv4, Tailscale/CGNAT, and IPv6 ULA networks.
  Every DNS result and redirect is checked. Link-local
  addresses (including cloud metadata), multicast, and unspecified addresses
  are always blocked. Loopback HTTP is available only when `PUBLIC_URL`
  explicitly configures a localhost development instance.
- **Codegen workspace isolation** - each ephemeral toolserver mounts only its
  own subdirectory from the named codegen volume. It cannot read activation
  data, cached libraries, agent repositories, or another build workspace from
  Airlock's persistent volume.
- **Per-agent internal networks** - with `AGENT_NETWORK_PER_AGENT=true`, Airlock
  creates a Docker `Internal` bridge for each runtime and attaches only trusted
  dependency containers carrying the instance-scoped
  `run.airlock.agent-network-access` label. Runtime containers never join the
  shared `AGENT_NETWORK`; that internal network is only a dependency-discovery
  seed. Each agent can reach the `airlock` API alias and its scoped Postgres
  endpoint, but has no route to the host, cloud metadata, private networks, the
  public internet, infrastructure services, or sibling agents. Legitimate
  outbound HTTP uses Airlock's brokered APIs and destination policy.
- **Replica-safe network lifecycle** - deterministic network names and labels
  make creation idempotent. Start, stop, idle reap, and reconciliation hold a
  per-agent PostgreSQL advisory lock before attaching or detaching endpoints,
  so multiple Airlock replicas sharing the Docker daemon cannot race cleanup.
  Startup and periodic reconciliation attach replacement dependency containers
  after replica/Postgres restarts. Networks are removed after the runtime exits;
  a network with an unexpected endpoint is retained rather than destructively
  pruned.
- **External Postgres relay** - the `external-db` Compose profile runs a
  fixed-destination TCP relay. It is the only external-DB endpoint attached to
  each internal agent network, and it forwards bytes only to `DB_HOST:DB_PORT`.
  TLS and the per-agent Postgres role remain end-to-end; agents connect to
  `postgres-agent-relay:5432` through `DB_HOST_AGENT` / `DB_PORT_AGENT`.

### Tier 2 - operator-configurable (generous / off by default)

- **`AGENT_MEMORY_LIMIT`** (e.g. `512m`, `2g`; default unset = unlimited) -
  per-agent hard memory cap (swap pinned to the limit). Off by default
  because the host's size is unknown and `OomScoreAdj` already protects the
  host; operators on small VPSes set it to scope a leaker cleanly.

### Tier 3 - opt-in strong isolation

- **`AGENT_SANDBOX=gvisor`** → agent containers run under the `runsc`
  (gVisor) runtime instead of `runc`. gVisor is a userspace kernel that
  intercepts the agent's syscalls, so an escape attempt hits the sandbox
  rather than the host kernel - VM-grade-ish containment without a VM (some
  perf cost on syscall/IO-heavy agents). Tier-1 hardening still applies on
  top. Requires `runsc` installed and registered as a Docker runtime on the
  host (`AGENT_SANDBOX` unset → default `runc`).

## Residual risk and deployment prerequisites

The Compose deployment requires a Docker daemon that supports dynamic container
attachment to local bridge networks and allows Airlock to use its Docker API socket.
Docker Engine and Docker Desktop provide these capabilities.

- **Native development** - a host process cannot be attached to a Docker
  internal bridge. `.env.dev.example` therefore sets
  `AGENT_NETWORK_PER_AGENT=false`; runtime agents use the shared development
  network and host gateway. Do not use native mode for mutually untrusted
  agents. Run Airlock through Compose to enforce runtime network isolation.
- **Non-Compose deployments** - containers that agents must reach need both the
  instance-valued `run.airlock.agent-network-access` label and a comma-separated
  `run.airlock.agent-network-aliases` label, and must join the internal
  `AGENT_NETWORK` seed. Airlock fails agent startup when no trusted dependency
  is available or a managed network does not match the required internal
  bridge/labels. Managed isolation is the application default; explicitly set
  `AGENT_NETWORK_PER_AGENT=false` only for trusted native development.
- **Other server-side egress** - `AGENT_HTTP_PRIVATE_CIDRS` governs Airlock's
  brokered HTTP, connection, MCP, outbound OAuth, and credential-test clients.
  Build toolservers, Git, LLM provider clients, and exec endpoints run on
  separate trusted-server paths; apply deployment egress policy to those paths
  when required.
- **Rootless BuildKit** - *shipped (prod, opt-in via `BUILDKIT_HOST`).* The
  prod compose runs a `moby/buildkit:rootless` daemon, and airlock builds
  agent images through it via a remote buildx builder (`builder.buildImage`)
  rather than the host's root `dockerd`. So an agent's untrusted `setup.sh`
  runs as root *inside buildkitd* (an unprivileged host uid), closing the
  build-time escape-to-host-root path (cf. CVE-2024-21626). `BUILDKIT_HOST`
  unset → legacy host `docker build` (dev). **Bound:** airlock still mounts
  the docker socket for `docker run`/`pull`/`cp` + agent lifecycle, so
  airlock itself remains root-equivalent - what this removes is *untrusted
  agent code running as root on the host daemon*, not airlock's own
  privilege. Registry mode (`AGENT_REGISTRY_URL`) uses buildx `--push`,
  which needs buildkitd to hold registry creds. **Host prerequisites:**
  unprivileged user namespaces + `/dev/fuse`. On Ubuntu 23.10+ set
  `kernel.apparmor_restrict_unprivileged_userns=0` (sysctl) or install the
  `rootlesskit` AppArmor profile, or buildkitd won't start. The compose
  passes `--oci-worker-no-process-sandbox` so it also works on container/LXC
  hosts that can't nest namespaces (drop it on bare-metal/VM for stricter
  per-step isolation).
- **`userns-remap` / rootless Docker** - daemon-level remap of
  container-root → an unprivileged host uid, covering builds, the
  toolserver, and runtime agents in one setting. The low-effort
  defense-in-depth if you don't run gVisor.

For deployments that run **untrusted third-party** agents (not the current
target), prefer a VM-isolated runtime (gVisor everywhere, or
Kata/Firecracker) - namespaces alone are not a boundary against a
determined attacker hunting a kernel bug.

## Multiple instances on one Docker daemon

Airlock identifies the Docker resources it owns by the `run.airlock.instance`
label (value = `AIRLOCK_INSTANCE_ID`), and prefixes container, image-cache, and
buildx-builder names with the same id. Every container/image **list and prune**
call filters on that label, so an instance only ever sees and only ever reaps
its own resources. This is what makes it safe to run, e.g., a prod stack
alongside a dev one on the same host Docker daemon. Compose mounts
`DOCKER_SOCKET_PATH` at `/var/run/docker.sock` inside Airlock; native processes
use their configured Docker client endpoint directly.

**The contract:** `AIRLOCK_INSTANCE_ID` is required (the compose/.env files
supply it; default `airlock`). The default is fine for a *single* instance.
**Co-locating instances on one daemon means giving each a DISTINCT value** -
otherwise they share a namespace and the prune sweep of one removes the other's
agent containers and images.

Namespacing the agent layer (containers / images / build caches / buildx
builder) is handled in code. Running a full second *stack* additionally needs
its own infra so it doesn't collide on Docker's other shared namespaces:
`COMPOSE_PROJECT_NAME`, distinct Docker networks (`DOCKER_NETWORK` /
`AGENT_NETWORK`), and a distinct codegen volume (`AGENT_CODEGEN_VOLUME`).
`install.sh --instance-id <id>` writes those values together. The id must use
lowercase letters, numbers, underscores, or dashes, and start with a letter or
number:

```env
COMPOSE_PROJECT_NAME=<id>
AIRLOCK_INSTANCE_ID=<id>
DOCKER_NETWORK=<id>
AGENT_NETWORK=<id>-agents
AGENT_CODEGEN_VOLUME=<id>-data
```

Published Caddy installs also need distinct host ports (`HTTP_PORT` /
`HTTPS_PORT`). Local installs publish only `HTTP_PORT` through the `caddy-local`
profile and bind it to 127.0.0.1. Tunnel installs use the
`caddy-private,cloudflared` profiles and do not publish Caddy host ports. Their
Cloudflare ingress uses a fixed-address internal bridge so Caddy can trust only
the cloudflared peer. Co-located tunnel instances must use non-overlapping
subnets and addresses, for example:

```env
TUNNEL_INGRESS_NETWORK=<id>-tunnel-ingress
TUNNEL_INGRESS_SUBNET=172.31.254.0/29
TUNNEL_CLOUDFLARED_IP=172.31.254.2
TUNNEL_CADDY_IP=172.31.254.3
```

Export these variables in the shell before running `install.sh` to have the
generated `.env` carry them through. Set them directly in `.env` before
upgrading an existing co-located tunnel. Each tunnel's Cloudflare
public-hostname routes target `http://caddy:80`; cloudflared resolves that name
only on the internal ingress bridge. Caddy remains on the infrastructure
network for outbound access to Airlock, the frontend, and bundled S3, but its
tunnel listener binds only to `TUNNEL_CADDY_IP`.
Bundled Postgres and RustFS stay on the Docker network in normal deployments.
`make dev` applies `docker-compose.dev.yml` to publish loopback ports for the
native development process.

Each installed instance is its own git checkout and `.env`. This lets instances
run and upgrade on separate release tracks. Run `install.sh` and `upgrade.sh`
from the checkout for the instance you are changing.

The Kubernetes path solves the same problem natively with a namespace per
instance behind the same `container.ContainerManager` interface;
`AIRLOCK_INSTANCE_ID` maps onto that namespace.
