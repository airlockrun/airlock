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

# The container starts in the mounted agent repo. Reconcile the module first so
# module-local tools resolve on a fresh scaffold, then project the image's
# version-matched frontend cache before tool execution.
go mod tidy
go tool air toolchain install

exec "$@"
