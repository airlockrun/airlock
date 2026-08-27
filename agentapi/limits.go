package agentapi

// MaxBufferedResponseBytes is the hard cap for any response a buffered SDK
// method accumulates fully in memory before returning to the caller. Overflow
// surfaces as agentsdk.ErrOutputTooLarge with no partial result.
//
// The cap also applies Airlock-side as defense in depth on integration proxies,
// so a misbehaving SDK cannot exhaust Airlock memory.
//
// Sized so structured small responses (JSON API replies, HTML pages, CLI
// tool summaries) pass through and larger data uses streaming storage.
const MaxBufferedResponseBytes = 20 << 20 // 20 MiB

// ActionStringPreviewBytes caps verbose stream-like fields kept in the
// runs.actions audit log.
const ActionStringPreviewBytes = 8 * 1024 // 8 KiB
