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
#   - The set of images published by .github/workflows/publish-images.yml
#     equals the set of images referenced (by basename) in
#     docker-compose.yml. Catches "added image to workflow but forgot
#     compose", and the regression of "removed `image:` from a compose
#     service so it silently went back to local-build only".
#   - README.md's `git checkout vX.Y.Z` install step matches the
#     compose ghcr tag. Operators clone + checkout the version the
#     README documents; if it drifts from compose, they pull a tag
#     that doesn't exist or whose images don't match the compose file.
#   - install.sh's pinned RELEASE_TAG default (and the README curl|bash
#     URLs that embed it) match the compose tag. The installer clones
#     this tag and pulls its images; a stale pin would fetch a tag whose
#     images don't exist or don't match.
#   - The README documents only STABLE releases. Pre-release tags
#     (-rc/-alpha/-beta/-dev) are rejected anywhere in the README, and
#     while compose pins a pre-release the README carries no install
#     quickstart at all (deferred to the stable release — proper
#     migrations aren't maintained for pre-releases). install.sh still
#     pins the pre-release verbatim; its own guard refuses to install one
#     without --pre-release.
#
# Release-only (RELEASE_TAG env set — runs in CI on tag push):
#   - Compose ghcr image tags equal $RELEASE_TAG. Catches "bumped to
#     wrong number" or "forgot to bump compose entirely before tagging".
#   - README.md's checkout version equals $RELEASE_TAG (stable tags only;
#     a pre-release tag has no README checkout line to match).
#   - install.sh RELEASE_TAG equals $RELEASE_TAG.
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

# --- 1b. Tailwind toolchain ARGs match between toolserver and scaffold ---
#
# The toolserver (Dockerfile.agent-builder) runs the iterative LLM-driven
# build; the scaffold's Dockerfile.tmpl is the final image-build the agent
# gets compiled into. Both ADD the same tailwindcss/daisyui artefacts;
# drift means the LLM iterates against one Tailwind and ships another.
for tool in TAILWIND DAISYUI; do
	tool_lc=$(printf '%s' "$tool" | tr '[:upper:]' '[:lower:]')
	toolserver=$(awk -v p="^ARG ${tool}_VERSION=" '$0 ~ p {sub(p, ""); print; exit}' Dockerfile.agent-builder)
	scaffold=$(awk -v p="^ARG ${tool}_VERSION=" '$0 ~ p {sub(p, ""); print; exit}' scaffold/templates/Dockerfile.tmpl)
	if [ -z "$toolserver" ]; then
		err "Dockerfile.agent-builder: missing ARG ${tool}_VERSION"
		continue
	fi
	if [ -z "$scaffold" ]; then
		err "scaffold/templates/Dockerfile.tmpl: missing ARG ${tool}_VERSION"
		continue
	fi
	if [ "$toolserver" != "$scaffold" ]; then
		err "${tool_lc} version drift: Dockerfile.agent-builder=$toolserver, scaffold/templates/Dockerfile.tmpl=$scaffold"
	fi
done

# --- 1c. templ version consistency ---
#
# templ generates *_templ.go against its runtime library, so the generator
# (CLI) and the linked library MUST be the same version — otherwise generated
# code calls runtime symbols the library lacks (e.g. `undefined:
# templ.JoinURLErrs`). The scaffold's go.mod.tmpl pin is the source of truth
# (it's what shipped agents build against); the agent-builder image, the CI/
# release workflows that install the CLI, and the build/scaffold test fixtures
# must all match it.
templ_canonical=$(grep -oE 'github.com/a-h/templ v[0-9]+\.[0-9]+\.[0-9]+' scaffold/templates/go.mod.tmpl | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$templ_canonical" ]; then
	err "scaffold/templates/go.mod.tmpl: missing 'github.com/a-h/templ vX.Y.Z' pin"
else
	for f in Dockerfile.agent-builder builder/gomod_test.go scaffold/scaffold_integration_test.go .github/workflows/ci.yml .github/workflows/release.yml; do
		# Every templ version token on a line that names templ or TEMPL_VERSION.
		while IFS= read -r v; do
			[ -z "$v" ] && continue
			[ "$v" != "$templ_canonical" ] && err "$f: templ $v doesn't match scaffold pin $templ_canonical"
		done < <(grep -hE 'a-h/templ|TEMPL_VERSION' "$f" 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -u || true)
	done
fi

# --- 2. docker-compose.yml ghcr tags are internally consistent ---

# Match any ghcr.io/airlockrun/airlock(-something):vX.Y.Z[-pre] occurrence.
# Pre-release suffix (e.g. -rc.1, -alpha.2) is required during the rc cycle
# leading up to a stable tag.
tags=$(grep -oE 'ghcr\.io/airlockrun/airlock[a-z-]*:v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?' docker-compose.yml | sed 's/.*://' | sort -u || true)
n=$(printf '%s\n' "$tags" | grep -c . || true)
if [ "$n" -eq 0 ]; then
	err "docker-compose.yml: no ghcr image tags found (expected at least one)"
elif [ "$n" -gt 1 ]; then
	err "docker-compose.yml: inconsistent ghcr tags: $(printf '%s ' $tags)"
fi

# Is the compose tag a pre-release (rc/alpha/beta/dev)? During the rc cycle the
# README intentionally documents no install version (deferred to the stable
# release), so the README↔compose checks below relax to "README has no install
# tag" instead of "README tag == compose tag". install.sh still pins it.
is_prerelease() { [[ "$1" =~ -(rc|alpha|beta|dev)\.[0-9]+$ ]]; }
compose_prerelease=0
if [ "$n" -eq 1 ] && is_prerelease "$tags"; then
	compose_prerelease=1
fi

# --- 3. Workflow matrix ↔ compose image set ---

published=$(grep -oE '^[[:space:]]+-[[:space:]]name:[[:space:]]airlock[a-z-]*$' \
	.github/workflows/publish-images.yml | awk '{print $3}' | sort -u)
referenced=$(grep -oE 'ghcr\.io/airlockrun/airlock[a-z-]*' docker-compose.yml \
	| sed 's|.*/||' | sort -u)

only_published=$(comm -23 <(printf '%s\n' "$published") <(printf '%s\n' "$referenced"))
only_referenced=$(comm -13 <(printf '%s\n' "$published") <(printf '%s\n' "$referenced"))

if [ -n "$only_published" ]; then
	err "publish-images.yml builds these but docker-compose.yml doesn't reference them: $(printf '%s ' $only_published)"
fi
if [ -n "$only_referenced" ]; then
	err "docker-compose.yml references these but publish-images.yml doesn't build them: $(printf '%s ' $only_referenced)"
fi

# --- 4. README install checkout version matches compose tag ---

# Pull the version out of the install step, e.g. `git checkout v0.2.16` or
# `git checkout v0.4.0-rc.1`. Match only inside fenced code blocks to avoid
# prose hits like `git checkout vX.Y.Z` in the Updating section (placeholder,
# not literal). Pre-release suffix optional.
readme_ver=$(grep -oE '^git checkout v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' README.md | head -1 | awk '{print $3}' || true)
if [ -n "$readme_ver" ] && is_prerelease "$readme_ver"; then
	err "README.md: pre-release tag $readme_ver in 'git checkout' step — the README documents stable releases only"
fi
if [ "$compose_prerelease" -eq 1 ]; then
	# Pre-release cycle: the README has no pinned install version (deferred to
	# the stable release). A stable readme_ver here would be wrong too — it
	# wouldn't match the pre-release images — so require its absence.
	if [ -n "$readme_ver" ]; then
		err "README.md: 'git checkout $readme_ver' present while compose pins pre-release $tags — drop the install step until the stable release"
	fi
elif [ -z "$readme_ver" ]; then
	err "README.md: missing literal 'git checkout vX.Y.Z' install step"
elif [ "$n" -eq 1 ] && [ "$readme_ver" != "$tags" ]; then
	err "README.md checkout $readme_ver doesn't match compose tag $tags"
fi

# --- 5. version.go constant matches compose tag ---

# The Version constant in version.go is the source of truth that the in-code
# DefaultAgentBuilderImage / DefaultAgentBaseImage interpolate. Drift here
# means a `go run` from this commit would default to a different agent-builder
# than the released compose pins.
version_go=$(awk -F'"' '/^const Version =/ {print $2; exit}' version.go)
if [ -z "$version_go" ]; then
	err "version.go: missing 'const Version = \"X.Y.Z\"'"
elif [ "$n" -eq 1 ] && [ "v$version_go" != "$tags" ]; then
	err "version.go Version=v$version_go doesn't match compose tag $tags"
fi

# --- 6. install.sh pinned tag + README curl URLs match compose tag ---

# install.sh clones + pulls this tag: RELEASE_TAG="${AIRLOCK_TAG:-vX.Y.Z}".
# Always enforced — the installer must pin exactly what compose ships, whether
# that's a stable or pre-release tag.
install_tag=$(sed -nE 's/.*AIRLOCK_TAG:-(v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?).*/\1/p' install.sh | head -1)
if [ -z "$install_tag" ]; then
	err "install.sh: missing pinned RELEASE_TAG default (\${AIRLOCK_TAG:-vX.Y.Z})"
elif [ "$n" -eq 1 ] && [ "$install_tag" != "$tags" ]; then
	err "install.sh RELEASE_TAG $install_tag doesn't match compose tag $tags"
fi

# The README curl|bash one-liners embed the tag in the raw.githubusercontent URL.
# Like the checkout step, these document stable releases only: pre-release tags
# are rejected, and during the rc cycle there should be none at all (deferred
# with the rest of the install quickstart).
readme_curl_tags=$(grep -oE 'raw\.githubusercontent\.com/airlockrun/airlock/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?/install\.sh' README.md \
	| sed -E 's#.*/airlock/(v[^/]+)/install\.sh#\1#' | sort -u || true)
if [ -n "$readme_curl_tags" ]; then
	while IFS= read -r u; do
		[ -z "$u" ] && continue
		if is_prerelease "$u"; then
			err "README.md: pre-release tag $u in install.sh curl URL — the README documents stable releases only"
		elif [ "$compose_prerelease" -eq 1 ]; then
			err "README.md: install.sh curl URL pins $u while compose pins pre-release $tags — drop the installer one-liner until the stable release"
		elif [ "$n" -eq 1 ] && [ "$u" != "$tags" ]; then
			err "README.md install.sh curl URL tag $u doesn't match compose tag $tags"
		fi
	done <<< "$readme_curl_tags"
fi

# --- 7. Release-only: compose + README + version.go + install.sh equal $RELEASE_TAG ---

if [ -n "${RELEASE_TAG:-}" ]; then
	if [ "$n" -eq 1 ] && [ "$tags" != "$RELEASE_TAG" ]; then
		err "docker-compose.yml: ghcr tag $tags doesn't match release tag $RELEASE_TAG"
	fi
	# The README documents stable releases only — a pre-release tag has no
	# checkout line to match (deferred to the stable release).
	if ! is_prerelease "$RELEASE_TAG" && [ -n "$readme_ver" ] && [ "$readme_ver" != "$RELEASE_TAG" ]; then
		err "README.md checkout $readme_ver doesn't match release tag $RELEASE_TAG"
	fi
	if [ -n "$version_go" ] && [ "v$version_go" != "$RELEASE_TAG" ]; then
		err "version.go Version=v$version_go doesn't match release tag $RELEASE_TAG"
	fi
	if [ -n "$install_tag" ] && [ "$install_tag" != "$RELEASE_TAG" ]; then
		err "install.sh RELEASE_TAG $install_tag doesn't match release tag $RELEASE_TAG"
	fi
fi

if [ $fail -eq 0 ]; then
	echo "version invariants: OK"
fi
exit $fail
