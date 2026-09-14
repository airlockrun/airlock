#!/usr/bin/env bash
# Build the release recipe, smoke it, and print its local content-addressed tag.
# An explicit SDK source directory enables development without a published SDK.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ "$#" -le 1 ] || { printf 'usage: build-js-executor.sh [SDK_SOURCE]\n' >&2; exit 1; }
if [ "$#" = 1 ]; then
	sdk=$(realpath "$1")
	[ -f "$sdk/jsexec/runtime/Dockerfile" ] && [ -f "$sdk/cmd/jsexecutor/main.go" ]
else
	pin=$(awk '$1 == "github.com/airlockrun/agentsdk" {print $2}' go.mod)
	[ -n "$pin" ]
	GOWORK=off go mod download "github.com/airlockrun/agentsdk@$pin"
	sdk=$(GOWORK=off go list -m -f '{{.Dir}}' "github.com/airlockrun/agentsdk@$pin")
	[ -n "$sdk" ]
fi
# Freeze exactly the SDK inputs that enter the build, including embedded assets.
stage=$(mktemp -d)
trap 'chmod -R u+w "$stage"; rm -rf "$stage"' EXIT
mkdir "$stage/sdk" "$stage/airlock"
sdk_files=(jsexec cmd/jsexecutor go.mod go.sum LICENSE)
for notice in "$sdk"/NOTICE*; do
	[ ! -f "$notice" ] || sdk_files+=("${notice##*/}")
done
tar -C "$sdk" -cf - "${sdk_files[@]}" | tar -C "$stage/sdk" -xf -
tar -cf - Dockerfile.js-executor scripts/js-executor-check go.mod go.sum | tar -C "$stage/airlock" -xf -
# Only source inputs enter the hash, never checkout metadata or local secrets.
hash=$({
	tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$stage/airlock" -cf - \
		Dockerfile.js-executor scripts/js-executor-check go.mod go.sum
	tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$stage/sdk" -cf - \
		"${sdk_files[@]}"
} | sha256sum | cut -d' ' -f1)
image="airlock-js-executor:dev-$hash"
canonical=$(awk -F'"' '/^const DenoImage =/ {print $2}' "$stage/sdk/jsexec/assets.go")
[[ "$canonical" =~ ^denoland/deno@sha256:[0-9a-f]{64}$ ]]
for recipe in "$stage/airlock/Dockerfile.js-executor" "$stage/sdk/jsexec/runtime/Dockerfile"; do
	[ "$(awk '/^FROM denoland\/deno/ {print $2}' "$recipe")" = "$canonical" ] \
		|| { printf 'executor recipe Deno digest drift: %s\n' "$recipe" >&2; exit 1; }
done
runtime_recipe=$(awk '/^FROM denoland\/deno/ {runtime=1} runtime {gsub(/--from=build /, ""); gsub(/\/out\//, ""); print}' "$stage/airlock/Dockerfile.js-executor")
while IFS= read -r instruction; do
	case "$instruction" in ''|'#'*) continue;; esac
	printf '%s\n' "$runtime_recipe" | grep -Fxq "$instruction" \
		|| { printf 'executor runtime recipe drift: %s\n' "$instruction" >&2; exit 1; }
done < "$stage/sdk/jsexec/runtime/Dockerfile"
docker build --build-context "sdk-source=$stage/sdk" -f "$stage/airlock/Dockerfile.js-executor" -t "$image" "$stage/airlock" >&2
base_version=$(docker run --rm --network none --entrypoint /usr/bin/deno "$canonical" --version)
built_version=$(docker run --rm --network none --entrypoint /usr/bin/deno "$image" --version)
[ "$built_version" = "$base_version" ] || { printf 'executor Deno version drift\n' >&2; exit 1; }
expected_protocol=$(sha256sum "$stage/sdk/jsexec/protocol.go" | cut -d' ' -f1)
actual_protocol=$(docker run --rm --network none --entrypoint /bin/cat "$image" /usr/local/share/jsexec/protocol.sha256)
[ "$actual_protocol" = "$expected_protocol  jsexec/protocol.go" ] \
	|| { printf 'executor protocol source drift\n' >&2; exit 1; }
deno_version=$(printf '%s\n' "$base_version" | awk 'NR==1 && $1=="deno" {print $2}')
[[ "$deno_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
curl -fsSL --connect-timeout 10 --max-time 60 "https://raw.githubusercontent.com/denoland/deno/v$deno_version/LICENSE.md" \
	| cmp - "$stage/airlock/scripts/js-executor-check/DENO_LICENSE"
docker run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --memory 256m --memory-swap 256m \
	--cpus 1 --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=32m \
	--entrypoint /usr/local/bin/js-executor-check "$image" >&2
printf '%s\n' "$image"
