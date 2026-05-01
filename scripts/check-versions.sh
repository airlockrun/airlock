#!/usr/bin/env bash
# Validate version invariants across the repo.
#
# Always (intracommit invariant — runs in pre-commit hook + CI):
#   - Dockerfile.agent-builder ARG defaults match go.mod for the libs
#     we own (agentsdk, goai, sol). Drift here ships a published image
#     with stale lib source baked into /libs/, even though the image
#     tag claims the latest version.
#   - All ghcr image tags in docker-compose.yml are equal to each other.
#     Catches "bumped one line, forgot the others".
#
# Release-only (RELEASE_TAG env set — runs in CI on tag push):
#   - Compose ghcr image tags equal $RELEASE_TAG. Catches "bumped to
#     wrong number" or "forgot to bump compose entirely before tagging".
#
# Exit status: 0 on pass, 1 on any failure. All failures reported, not
# fail-fast — one run surfaces every drift.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
err() {
	echo "ERROR: $*" >&2
	fail=1
}

# --- 1. Dockerfile.agent-builder ARGs vs go.mod ---

for lib in agentsdk goai sol; do
	upper=$(printf '%s' "$lib" | tr '[:lower:]' '[:upper:]')
	expected=$(awk -v m="airlockrun/$lib " '$0 ~ m {print $2; exit}' go.mod)
	actual=$(awk -v p="^ARG ${upper}_VERSION=" '$0 ~ p {sub(p, ""); print; exit}' Dockerfile.agent-builder)
	if [ -z "$expected" ]; then
		err "go.mod: no require entry for github.com/airlockrun/$lib"
		continue
	fi
	if [ -z "$actual" ]; then
		err "Dockerfile.agent-builder: missing ARG ${upper}_VERSION"
		continue
	fi
	if [ "$actual" != "$expected" ]; then
		err "Dockerfile.agent-builder ${upper}_VERSION=$actual doesn't match go.mod $expected"
	fi
done

# --- 2. docker-compose.yml ghcr tags are internally consistent ---

# Match any ghcr.io/airlockrun/airlock(-something):vX.Y.Z occurrence.
tags=$(grep -oE 'ghcr\.io/airlockrun/airlock[a-z-]*:v[0-9.]+' docker-compose.yml | sed 's/.*://' | sort -u || true)
n=$(printf '%s\n' "$tags" | grep -c . || true)
if [ "$n" -eq 0 ]; then
	err "docker-compose.yml: no ghcr image tags found (expected at least one)"
elif [ "$n" -gt 1 ]; then
	err "docker-compose.yml: inconsistent ghcr tags: $(printf '%s ' $tags)"
fi

# --- 3. Release-only: compose tag equals $RELEASE_TAG ---

if [ -n "${RELEASE_TAG:-}" ]; then
	if [ "$n" -eq 1 ] && [ "$tags" != "$RELEASE_TAG" ]; then
		err "docker-compose.yml: ghcr tag $tags doesn't match release tag $RELEASE_TAG"
	fi
fi

if [ $fail -eq 0 ]; then
	echo "version invariants: OK"
fi
exit $fail
