#!/usr/bin/env bash
# Migration immutability guard.
#
# goose tracks applied migrations by version number and does NOT checksum
# them. So editing a migration that already ran somewhere is silent: goose
# sees the version recorded, skips the file, and that database keeps the
# old schema forever while fresh databases get the new one. Once a
# migration ships in a release, it is frozen — every later schema change
# goes in a NEW db/migrations/NNN_*.sql.
#
# This enforces exactly that: every migration present in the latest final
# release tag must be byte-identical in the working tree. A changed or
# deleted shipped migration is a hard error. Migrations not yet in any
# release tag (in-development) are unrestricted — squash/edit them freely
# until the release that ships them is tagged.
#
# Freeze point = a FINAL release tag matching ^v[0-9]+\.[0-9]+\.[0-9]+$
# (the same definition release-airlock.sh uses). vX.Y.Z-rc.N is NOT a
# freeze point on purpose: an rc is a candidate, still mutable.
#
# Runs in pre-commit and CI. CI must check out full history + tags
# (fetch-depth: 0) or this finds no tags and passes vacuously.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

mig_dir="db/migrations"

latest_tag=$(git tag --list 'v*' \
	| grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
	| sort -V \
	| tail -1 || true)

if [ -z "$latest_tag" ]; then
	# No final release tag visible: feature branch before the first tag,
	# or a shallow clone without tags. Nothing is frozen yet.
	echo "migration immutability: no final release tag visible — skipping"
	exit 0
fi

# --- Baseline reset (0.4 clean slate) ---
# 0.4 squashed the migration history into a single schema, deliberately
# abandoning the 0.3.x lineage (there is no in-place 0.3 -> 0.4 upgrade). The
# migrations tagged in v0.3.4 no longer exist, so there is nothing valid to
# freeze against while the latest FINAL tag still predates the reset. Once the
# first 0.4 final tag ships it becomes the latest final tag (sort -V) and normal
# freezing resumes against the new baseline — this guard self-heals; the marker
# can be deleted then.
BASELINE_RESET_AFTER="v0.3.4"
if [ -n "$BASELINE_RESET_AFTER" ] \
	&& [ "$(printf '%s\n%s\n' "$latest_tag" "$BASELINE_RESET_AFTER" | sort -V | tail -1)" = "$BASELINE_RESET_AFTER" ]; then
	echo "migration immutability: baseline reset after $BASELINE_RESET_AFTER; latest final tag $latest_tag is at/before it — freeze suspended (resumes at the next final tag)"
	exit 0
fi

fail=0
while IFS= read -r path; do
	[ -z "$path" ] && continue
	tagged_blob=$(git rev-parse "$latest_tag:$path")
	if [ ! -f "$path" ]; then
		echo "ERROR: $path shipped in $latest_tag but is missing — shipped migrations cannot be deleted." >&2
		fail=1
		continue
	fi
	if [ "$tagged_blob" != "$(git hash-object "$path")" ]; then
		echo "ERROR: $path shipped in $latest_tag and cannot be modified." >&2
		echo "       goose keys applied migrations by number with no checksum;" >&2
		echo "       editing it silently diverges every DB that ran the old one." >&2
		echo "       Put the schema change in a new $mig_dir/NNN_*.sql instead." >&2
		fail=1
	fi
done < <(git ls-tree -r --name-only "$latest_tag" -- "$mig_dir" | grep -E '\.sql$' || true)

if [ "$fail" -eq 0 ]; then
	echo "migration immutability: OK (frozen at $latest_tag)"
fi
exit $fail
