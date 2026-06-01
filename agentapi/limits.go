package agentapi

// MaxBufferedResponseBytes is the hard cap for any response the buffered
// SDK methods (ConnectionHandle.Request, ExecHandle.Run) accumulate fully
// in memory before returning to the caller. Overflow surfaces as
// agentsdk.ErrOutputTooLarge with no partial result — agents that need
// larger responses use the *Stream variant and pipe straight into storage.
//
// The cap also applies airlock-side as defense in depth on the connection
// proxy (replacing the previously uncapped io.Copy) and on the exec NDJSON
// writer, so a misbehaving SDK can't OOM airlock either.
//
// Sized so structured small responses (JSON API replies, HTML pages, CLI
// tool summaries) pass through and "actual data" (tarballs, dumps, logs)
// is forced onto the streaming primitive — which is the right ergonomic
// nudge for both Go authors and the LLM.
const MaxBufferedResponseBytes = 20 << 20 // 20 MiB

// ExecRecordPreviewBytes caps the per-stream head kept in runs.actions
// JSONB for the audit log. Distinct from MaxBufferedResponseBytes — the
// caller of Run still receives the full data; only the audit-log preview
// is truncated.
const ExecRecordPreviewBytes = 8 * 1024 // 8 KiB
