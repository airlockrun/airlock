package airlock

// Version is the airlock release version. The release tag in git is "v"+Version
// (e.g. "v0.3.4"). Bumped manually before tagging; check-versions.sh enforces
// that this constant, the docker-compose.yml ghcr tags, and the README install
// step all agree.
//
// Consumed at the module level so the default AGENT_BUILDER_IMAGE / AGENT_BASE_IMAGE
// in config tracks airlock's own version — drift between airlock and its
// matched toolserver/runtime images becomes a build-time error.
const Version = "0.4.0-rc.53"
