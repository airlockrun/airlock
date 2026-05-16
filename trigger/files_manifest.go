package trigger

import (
	"context"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

// FilesManifestSource tags the attached-files manifest message: a
// user-role message that IS sent to the model (non-ephemeral, so
// SessionStore.Load returns it) but is hidden from the human UI (the
// frontend drops source=="llm"). The human already sees the attachments
// via the separate upload echo / their chat platform, so rendering the
// manifest too would be noise.
const FilesManifestSource = "llm"

// PostFilesManifest writes the attached-files manifest as its own
// conversation message — the single, canonical way file attachments are
// described to the model. agentsdk no longer inlines a manifest into the
// prompt; every files-bearing ingress (web / bridge / A2A) calls this
// instead, BEFORE dispatch, so the row is in history when the agent's
// SessionStore loads. No-op when there are no files.
//
// Persist-only (q.CreateMessage) — deliberately NOT postToConversation:
// the manifest is model-only and must never reach a human WS or bridge
// channel. Sol's same-role coalescer folds it together with the user's
// actual message for providers that reject consecutive user turns.
func PostFilesManifest(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, files []agentsdk.FileInfo) error {
	if len(files) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("[Attached files:\n")
	for _, f := range files {
		fmt.Fprintf(&b, "- %s (%s, %d bytes) — path: %q\n", f.Filename, f.ContentType, f.Size, f.Path)
	}
	b.WriteString("Use readFile(path) in run_js to read text contents, readBytes(path) for binary, or attachToContext(path) to load images/files into your visual context for the next turn.]")
	_, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: convID,
		Role:           "user",
		Content:        b.String(),
		Source:         FilesManifestSource,
	})
	return err
}
