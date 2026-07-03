#!/usr/bin/env bash
# check-notices.sh — fail if the committed THIRD_PARTY_NOTICES files are stale
# relative to the current dependency graph (a dep added/removed/bumped without
# regenerating). Regenerates against backups and diffs; never leaves the working
# tree modified, so it's safe in a pre-commit hook.
#
# The scaffold (agent) notices are only checked when ../agentsdk is present;
# in an airlock-only checkout just the server notices are verified.
set -euo pipefail

AIRLOCK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HQ="$(cd "$AIRLOCK/.." && pwd)"

files=("$AIRLOCK/THIRD_PARTY_NOTICES.md")
[ -d "$HQ/agentsdk" ] && files+=("$HQ/agentsdk/scaffold/templates/THIRD_PARTY_NOTICES.generated.md")

tmp=$(mktemp -d)
# Back up by index so the restore mapping is unambiguous.
for i in "${!files[@]}"; do cp "${files[$i]}" "$tmp/orig.$i"; done
restore() {
	for i in "${!files[@]}"; do cp "$tmp/orig.$i" "${files[$i]}"; done
	rm -rf "$tmp"
}
trap restore EXIT

if ! bash "$AIRLOCK/scripts/gen-notices.sh" >/dev/null 2>"$tmp/err"; then
	echo "ERROR: gen-notices.sh failed:" >&2
	cat "$tmp/err" >&2
	exit 1
fi

fail=0
for i in "${!files[@]}"; do
	if ! diff -q "$tmp/orig.$i" "${files[$i]}" >/dev/null 2>&1; then
		echo "ERROR: ${files[$i]#"$HQ"/} is out of date." >&2
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo >&2
	echo "Regenerate and commit:  bash scripts/gen-notices.sh" >&2
	exit 1
fi
echo "notices: OK"
