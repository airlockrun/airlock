#!/usr/bin/env bash
# check-licenses.sh — fail the build if any dependency compiled into a
# distributed binary carries a license that isn't on the permissive allowlist.
#
# Guards against a copyleft (GPL/AGPL/LGPL/MPL/EPL/CDDL) or source-available
# (BSL/SSPL/Commons Clause/Elastic) dependency sneaking in via `go get` — which
# would block a closed/commercial build or force source disclosure — and against
# unlicensed code (legally unusable). Fails closed: anything the matcher can't
# positively identify as allowed is a failure until vetted.
#
# Scans the airlock server binary's module graph always; the agent (agentsdk)
# graph when ../agentsdk is checked out (local/full monorepo). The frontend npm
# tree is gated separately by frontend/scripts/licenses.mjs. The enterprise
# (OIDC) build lives in its own repo and is gated there. Pure bash — resolves
# module dirs from `go list` + the module cache; no external tooling.
set -euo pipefail

AIRLOCK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HQ="$(cd "$AIRLOCK/.." && pwd)"

# Modules whose license text the matcher can't auto-identify but which have been
# manually vetted as permissive. One module path per line.
VETTED="github.com/davecgh/go-spew"

violations=$(mktemp)
trap 'rm -f "$violations"' EXIT

# classify LICENSE_FILE → prints "ALLOW <id>" | "DENY <id>" | "UNKNOWN".
# Denials are checked first so an AGPL/LGPL text isn't misread as plain GPL.
classify() {
	local f="$1"
	grep -qiE "Affero General Public" "$f" && { echo "DENY AGPL"; return; }
	grep -qiE "Lesser General Public" "$f" && { echo "DENY LGPL"; return; }
	grep -qiE "GNU GENERAL PUBLIC LICENSE" "$f" && { echo "DENY GPL"; return; }
	grep -qiE "Mozilla Public License" "$f" && { echo "DENY MPL"; return; }
	grep -qiE "Eclipse Public License" "$f" && { echo "DENY EPL"; return; }
	grep -qiE "Common Development and Distribution|CDDL" "$f" && { echo "DENY CDDL"; return; }
	grep -qiE "Business Source License|\bBUSL\b" "$f" && { echo "DENY BSL"; return; }
	grep -qiE "Server Side Public License|\bSSPL\b" "$f" && { echo "DENY SSPL"; return; }
	grep -qiE "Commons Clause" "$f" && { echo "DENY Commons-Clause"; return; }
	grep -qiE "Elastic License" "$f" && { echo "DENY Elastic"; return; }
	grep -qiE "Apache License" "$f" && grep -qiE "Version 2\.0" "$f" && { echo "ALLOW Apache-2.0"; return; }
	grep -qiE "Permission is hereby granted, free of charge" "$f" && { echo "ALLOW MIT"; return; }
	grep -qiE "Redistribution and use in source and binary forms" "$f" && { echo "ALLOW BSD"; return; }
	grep -qiE "Permission to use, copy, modify, and distribute" "$f" && { echo "ALLOW ISC"; return; }
	grep -qiE "free and unencumbered software released into the public domain" "$f" && { echo "ALLOW Unlicense"; return; }
	grep -qiE "Blue Oak Model License" "$f" && { echo "ALLOW BlueOak"; return; }
	echo "UNKNOWN"
}

# scan LABEL LISTDIR PKGS — classify every compiled dep module; append failures
# to $violations. First-party airlockrun modules are skipped (your own code).
scan() {
	local label="$1" listdir="$2" pkgs="$3" n=0
	echo "scanning $label …" >&2
	while IFS='|' read -r path dir; do
		[ -z "$dir" ] && continue
		case "$path" in github.com/airlockrun/*) continue ;; esac
		n=$((n + 1))
		local lic res kind id
		lic=$(ls "$dir"/LICENSE* "$dir"/COPYING* "$dir"/LICENCE* 2>/dev/null | head -1 || true)
		if [ -z "$lic" ]; then
			echo "  $path — NO LICENSE FILE" >>"$violations"
			continue
		fi
		res=$(classify "$lic"); kind=${res%% *}; id=${res#* }
		case "$kind" in
		ALLOW) ;;
		DENY) echo "  $path — DENIED ($id)" >>"$violations" ;;
		UNKNOWN)
			if ! printf '%s\n' "$VETTED" | grep -qxF "$path"; then
				echo "  $path — UNRECOGNISED license ($(basename "$lic"))" >>"$violations"
			fi
			;;
		esac
	done < <(cd "$listdir" && go list -deps -f '{{with .Module}}{{.Path}}|{{.Dir}}{{end}}' $pkgs | sort -u | awk -F'|' 'NF==2 && $2!=""')
	echo "  $label: $n third-party modules checked" >&2
}

scan "airlock server binary" "$AIRLOCK" "./cmd/airlock"
if [ -d "$HQ/agentsdk" ]; then
	scan "agent (agentsdk graph)" "$HQ/agentsdk" "./..."
else
	echo "note: ../agentsdk not checked out — agent-side scan skipped (covered where agentsdk is present)" >&2
fi

if [ -s "$violations" ]; then
	echo "ERROR: disallowed or unrecognised dependency licenses:" >&2
	cat "$violations" >&2
	echo >&2
	echo "Permissive deps only (MIT/BSD/ISC/Apache-2.0/Unlicense/BlueOak). If a flagged" >&2
	echo "module is genuinely permissive but its text isn't recognised, add it to VETTED" >&2
	echo "in scripts/check-licenses.sh after confirming. Never allowlist copyleft/source-available." >&2
	exit 1
fi
echo "licenses: OK"
