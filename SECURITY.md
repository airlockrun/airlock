# Security

## Reporting a vulnerability

**Preferred:** use GitHub's [Private Vulnerability Reporting](https://github.com/airlockrun/airlock/security/advisories/new). The disclosure tracks as a draft advisory and ties cleanly into CVE issuance.

**Fallback:** email `security@airlock.run`. Use this if you don't have a GitHub account or PVR isn't reachable.

**Don't** open a public issue, post to Discussions, or mention vulnerabilities in PRs.

## What to include

- Affected version(s) and how you confirmed the issue is present.
- Reproducer or proof-of-concept (steps, code, video — whatever makes it reproducible).
- Impact assessment — what an attacker can actually do.
- Optional: a suggested fix.

## What you can expect

- **Acknowledgment within 72 hours** of receipt.
- **Initial triage and severity assessment within 7 days.**
- **Fix targeted within 30 days for High/Critical, 90 days for Low/Medium.**
- Regular status updates while we work on the fix.
- Credit in the security advisory unless you ask to remain anonymous.

## Supported versions

- **Pre-1.0:** only the latest minor version receives security fixes.
- **Post-1.0:** the current major and one previous major receive fixes.

## In scope

- airlock backend (`api/`, `auth/`, `builder/`, `container/`, etc.).
- airlock frontend (XSS, CSRF, auth flow flaws).
- Default `Caddyfile` and `docker-compose.yml` as shipped in this repo.
- Per-`(email, ip)` lockout bypass.
- AES-256-GCM key handling, JWT signing/validation, RBAC enforcement.
- Container escape via the agent build pipeline.
- SQL injection (we use sqlc; if you find one, it's a real bug).

## Out of scope

- DDoS / volumetric attacks — this is the operator's reverse proxy / CDN job, not airlock's.
- Distributed brute force across many IPs against the lockout — **known gap**, will be addressed by MFA. See the [README](README.md) Security section.
- Vulnerabilities in user-written agent code — that's the agent author's responsibility.
- Vulnerabilities in upstream dependencies — report to the upstream project first; we'll bump once they patch.
- Issues requiring physical access to the host or local privilege.
- Self-XSS where the victim pastes malicious content into their own browser console.
- Missing CSP / HSTS / security headers without a concrete exploitable impact.
- Issues only reproducible on outdated browsers or operating systems.
- Social-engineering attacks against maintainers.

## Safe harbor

Good-faith research conducted under this policy will not trigger legal action from us. We will not refer you to law enforcement or pursue civil claims for actions that:

- Test against your own self-hosted airlock instance.
- Use automated tools, but consider resource consumption.
- View, copy, or store data only to the extent needed to demonstrate the issue.
- Don't access data belonging to other users without permission.

This safe harbor does **not** cover:

- Testing against airlock instances you don't own (no probing of other operators' deployments).
- Public disclosure before we've patched the issue, or 90 days from your initial report — whichever comes first.
- Demanding payment or other consideration as a condition of disclosure.

## Bug bounty

We don't currently run a paid bug bounty program. We do offer credit in the security advisory and public thanks. If that ever changes, this section will be the first to know.
