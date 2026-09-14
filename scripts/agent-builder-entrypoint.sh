#!/bin/sh
# agent-builder toolserver entrypoint.
#
# The toolserver runs as the airlock host UID so files it writes into
# the bind-mounted workspace are host-owned. That UID has no entry in
# the image's account databases — sudo refuses an unresolvable UID
# ("you do not exist in the passwd database"), and PAM account
# validation fails without a matching /etc/shadow line. Self-register
# the UID into both (made world-writable in the Dockerfile) before
# exec'ing whatever Cmd airlock supplied.
#
# The shadow entry uses '*' (password login disabled) — sudo is
# NOPASSWD so no password is ever needed; the entry exists purely so
# PAM's account phase sees a valid, non-expired account.
set -e
uid=$(id -u)
gid=$(id -g)
if ! getent passwd "$uid" >/dev/null 2>&1; then
    echo "builder:x:${uid}:${gid}::/tmp/sol-home:/bin/bash" >> /etc/passwd
    echo "builder:*:20000:0:99999:7:::" >> /etc/shadow
fi

# Compose also starts this image with `true` as an image-carrier dependency.
# Toolserver startup and runtime warmup share the same preparation and Go settings.
if [ "${1##*/}" = "toolserver" ] || [ "$1" = "--warm-runtime-caches" ]; then
    phase=workspace
    trap 'status=$?; if [ "$status" -ne 0 ]; then echo "agent-builder: phase=$phase failed status=$status" >&2; fi' EXIT
    if [ ! -f go.mod ]; then
        echo "agent-builder: workspace has no go.mod" >&2
        exit 1
    fi
    # Reconcile the module first so module-local tools resolve on a fresh
    # scaffold, then project the version-matched frontend cache.
    phase=mod-tidy
    echo "agent-builder: phase=$phase starting" >&2
    go mod tidy
    phase=air-toolchain-install
    echo "agent-builder: phase=$phase starting" >&2
    go tool air toolchain install
    echo "agent-builder: preparation complete" >&2
    if [ "$1" = "--warm-runtime-caches" ]; then
        phase=stub-build
        echo "agent-builder: phase=$phase starting" >&2
        go build -o /tmp/agent .
        echo "agent-builder: runtime warmup complete" >&2
        exit 0
    fi
    phase=toolserver-exec
    echo "agent-builder: phase=$phase starting (awaiting listener)" >&2
fi

exec "$@"
