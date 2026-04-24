// Package attachref resolves S3-backed attachment references (`s3ref:K`)
// emitted by agentsdk.attachToContext into storage-ready or LLM-ready forms.
//
// Two entry points share a canonicalize helper:
//
//   - ResolveForStorage: invoked at SessionAppend time on []session.Message.
//     For any part whose Image/Data carries an `s3ref:K` sentinel, we
//     canonicalize to a derived blob at `llm/agents/<agentID>/K` (fetching,
//     preprocessing and PUTting if missing), and stamp the canonical key
//     into Source. The sentinel stays in Image/Data so future loads can
//     re-resolve without reading Source.
//
//   - ResolveForLLM: invoked on the LLM-bound goai []message.Message before
//     the provider stream call. Overwrites the Image/Data sentinel with
//     either a presigned URL (URL mode) or base64 bytes (inline mode),
//     governed by the provider's AttachmentPolicy. Enforces a request-wide
//     inline cap — excess inline parts are evicted to text placeholders
//     that preserve the re-attach path.
//
// Providers never see `s3ref:` — the resolver always overwrites before
// handing the message off.
package attachref

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/goai/message"
	solprovider "github.com/airlockrun/sol/provider"
	solsession "github.com/airlockrun/sol/session"
	"github.com/google/uuid"
)

// Sentinel is the prefix that marks an Image/Data field as an S3 reference
// rather than base64 or a URL. Value after the colon is the agent-facing
// key (no `agents/<id>/` scope — airlock adds that).
const Sentinel = "s3ref:"

// urlExpiry is the TTL on presigned URLs handed to LLM providers. Kept
// short because OpenAI fetches images server-side during the request —
// they don't need long-lived URLs.
const urlExpiry = 10 * time.Minute

// ResolveForStorage canonicalizes s3ref sentinels on session.Messages and
// writes canonical derived keys into Source. Leaves the sentinel in
// Image/Data (tiny, enables re-resolution without reading Source).
//
// Mutates msgs in place. Returns the first error encountered — callers
// should treat the whole batch as failed (don't persist partial state).
func ResolveForStorage(ctx context.Context, s3 *storage.S3Client, agentID uuid.UUID, msgs []solsession.Message) error {
	for i := range msgs {
		for j := range msgs[i].Parts {
			p := &msgs[i].Parts[j]
			switch p.Type {
			case "image":
				if p.Image == nil {
					continue
				}
				key, ok := strings.CutPrefix(p.Image.Image, Sentinel)
				if !ok {
					continue
				}
				canonical, mime, err := canonicalize(ctx, s3, agentID, key, p.Image.MimeType)
				if err != nil {
					return fmt.Errorf("attachref: canonicalize image %q: %w", key, err)
				}
				p.Image.Source = canonical
				if mime != "" {
					p.Image.MimeType = mime
				}
			case "file":
				if p.File == nil {
					continue
				}
				key, ok := strings.CutPrefix(p.File.Data, Sentinel)
				if !ok {
					continue
				}
				canonical, mime, err := canonicalize(ctx, s3, agentID, key, p.File.MimeType)
				if err != nil {
					return fmt.Errorf("attachref: canonicalize file %q: %w", key, err)
				}
				p.File.Source = canonical
				if mime != "" {
					p.File.MimeType = mime
				}
			}
		}
	}
	return nil
}

// ResolveForLLM resolves s3ref sentinels on goai messages, rewriting
// Image/Data with presigned URLs (URL mode) or base64 bytes (inline mode)
// per policy. Enforces the request-wide inline cap by evicting oldest
// parts to text placeholders.
//
// Mutates msgs in place.
func ResolveForLLM(ctx context.Context, s3 *storage.S3Client, agentID uuid.UUID, policy solprovider.AttachmentPolicy, msgs []message.Message) error {
	// Collect every s3ref-bearing image/file part with its position so we
	// can (a) canonicalize, (b) apply policy, (c) evict if over cap. We
	// index parts by (message index, part index) because message.Parts
	// holds interface values and mutation requires write-back.
	type ref struct {
		msgIdx, partIdx int
		kind            string // "image" | "file"
		agentKey        string // pre-sentinel K (for placeholder text)
		mime            string
		bytesLen        int // populated once we know (post-resolve)
	}

	var refs []ref
	for mi := range msgs {
		parts := msgs[mi].Content.Parts
		for pi, p := range parts {
			switch v := p.(type) {
			case message.ImagePart:
				if key, ok := strings.CutPrefix(v.Image, Sentinel); ok {
					refs = append(refs, ref{mi, pi, "image", key, v.MimeType, 0})
				}
			case message.FilePart:
				if key, ok := strings.CutPrefix(v.Data, Sentinel); ok {
					refs = append(refs, ref{mi, pi, "file", key, v.MimeType, 0})
				}
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}

	// Canonicalize first. HEAD the derived blob; if missing, create it.
	type resolved struct {
		ref
		canonicalKey string
		mode         string // "url" | "inline"
		inlineBytes  int
	}
	resolvedRefs := make([]resolved, len(refs))

	for i, r := range refs {
		canonical, mime, err := canonicalize(ctx, s3, agentID, r.agentKey, r.mime)
		if err != nil {
			return fmt.Errorf("attachref: canonicalize %s %q: %w", r.kind, r.agentKey, err)
		}
		if mime != "" {
			r.mime = mime
		}
		resolvedRefs[i] = resolved{ref: r, canonicalKey: canonical}
	}

	// Pass: decide URL vs inline per policy. Track totals for cap enforcement.
	urlCount := 0
	inlineTotal := 0

	for i := range resolvedRefs {
		rr := &resolvedRefs[i]
		urlCapable := (rr.kind == "image" && policy.SupportsURL) ||
			(rr.kind == "file" && policy.SupportsFileURL)
		useURL := urlCapable &&
			policy.MaxURLImages > 0 &&
			urlCount < policy.MaxURLImages

		if useURL {
			// HEAD to verify size before committing to URL mode.
			info, _, err := s3.HeadObject(ctx, rr.canonicalKey)
			if err != nil {
				return fmt.Errorf("attachref: head %q: %w", rr.canonicalKey, err)
			}
			if policy.MaxURLBytesPerImage > 0 && int(info.Size) > policy.MaxURLBytesPerImage {
				useURL = false
			}
			if useURL {
				url, err := s3.PublicPresignGetURL(ctx, rr.canonicalKey, urlExpiry)
				if err != nil {
					return fmt.Errorf("attachref: presign %q: %w", rr.canonicalKey, err)
				}
				rr.mode = "url"
				writeResolved(msgs, rr.msgIdx, rr.partIdx, rr.kind, rr.mime, url, "")
				urlCount++
				continue
			}
		}

		// Inline mode — fetch bytes, base64 encode.
		rc, err := s3.GetObject(ctx, rr.canonicalKey)
		if err != nil {
			return fmt.Errorf("attachref: get %q: %w", rr.canonicalKey, err)
		}
		raw, err := readAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("attachref: read %q: %w", rr.canonicalKey, err)
		}
		encoded := base64.StdEncoding.EncodeToString(raw)
		rr.mode = "inline"
		rr.inlineBytes = len(encoded)
		inlineTotal += rr.inlineBytes
		writeResolved(msgs, rr.msgIdx, rr.partIdx, rr.kind, rr.mime, "", encoded)
	}

	// Enforce MaxInlineBytesTotal. Evict oldest (earliest msgIdx) inline
	// parts until we're under the cap. Replace evicted parts with text
	// placeholders that tell the LLM how to re-attach.
	if policy.MaxInlineBytesTotal > 0 && inlineTotal > policy.MaxInlineBytesTotal {
		// Walk in order (oldest first). Pre-compute last message index —
		// that's the "current turn"; attachments there can't be silently
		// dropped.
		lastMsgIdx := len(msgs) - 1
		currentTurnInlineBytes := 0
		for _, rr := range resolvedRefs {
			if rr.mode == "inline" && rr.msgIdx == lastMsgIdx {
				currentTurnInlineBytes += rr.inlineBytes
			}
		}
		if currentTurnInlineBytes > policy.MaxInlineBytesTotal {
			return fmt.Errorf(
				"current request attachments (%d bytes) exceed size cap (%d bytes) — reduce attachments or use a model with URL support",
				currentTurnInlineBytes, policy.MaxInlineBytesTotal,
			)
		}

		for i := range resolvedRefs {
			if inlineTotal <= policy.MaxInlineBytesTotal {
				break
			}
			rr := &resolvedRefs[i]
			if rr.mode != "inline" || rr.msgIdx == lastMsgIdx {
				continue
			}
			placeholder := evictionPlaceholder(rr.kind, rr.agentKey)
			replacePartWithText(msgs, rr.msgIdx, rr.partIdx, placeholder)
			inlineTotal -= rr.inlineBytes
			rr.mode = "evicted"
		}
	}

	return nil
}

// canonicalize ensures `llm/agents/<agentID>/K` exists in S3 and returns
// the canonical key. On first miss it fetches the original from
// `agents/<agentID>/K`, preprocesses (if image), and PUTs the derived blob.
// Returns the canonical key and the (possibly updated) MIME type.
func canonicalize(ctx context.Context, s3 *storage.S3Client, agentID uuid.UUID, key, hintMime string) (string, string, error) {
	origKey := "agents/" + agentID.String() + "/" + key
	canonicalKey := "llm/agents/" + agentID.String() + "/" + key

	// Fast path: already canonical.
	if _, mime, err := s3.HeadObject(ctx, canonicalKey); err == nil {
		if mime == "" {
			mime = hintMime
		}
		return canonicalKey, mime, nil
	} else if !isNotFound(err) {
		return "", "", fmt.Errorf("head canonical: %w", err)
	}

	// Fetch original.
	rc, err := s3.GetObject(ctx, origKey)
	if err != nil {
		return "", "", fmt.Errorf("get original %q: %w", origKey, err)
	}
	raw, err := readAll(rc)
	rc.Close()
	if err != nil {
		return "", "", fmt.Errorf("read original: %w", err)
	}

	// Figure out MIME if not supplied.
	mime := hintMime
	if mime == "" {
		if _, origMime, headErr := s3.HeadObject(ctx, origKey); headErr == nil {
			mime = origMime
		}
	}

	pre, err := preprocessImage(raw, mime)
	if err != nil {
		return "", "", fmt.Errorf("preprocess: %w", err)
	}

	if pre.Skip {
		if err := s3.CopyObject(ctx, origKey, canonicalKey); err != nil {
			return "", "", fmt.Errorf("copy to canonical: %w", err)
		}
		return canonicalKey, pre.MimeType, nil
	}

	if err := s3.PutObject(ctx, canonicalKey, bytes.NewReader(pre.Bytes), int64(len(pre.Bytes))); err != nil {
		return "", "", fmt.Errorf("put canonical: %w", err)
	}
	return canonicalKey, pre.MimeType, nil
}

// writeResolved rewrites a message part with the resolved URL or base64.
// Exactly one of url/b64 must be set.
//
// Field routing differs for files: FilePart has separate URL / Data fields
// and provider conversion logic picks one or the other (e.g. Anthropic
// emits source.type=url iff URL is set). Keep exactly one populated.
// ImagePart.Image is polymorphic — providers auto-detect http prefix —
// so URL-or-base64 goes into the same field.
func writeResolved(msgs []message.Message, mi, pi int, kind, mime, url, b64 string) {
	parts := msgs[mi].Content.Parts
	switch kind {
	case "image":
		value := url
		if value == "" {
			value = b64
		}
		old := parts[pi].(message.ImagePart)
		old.Image = value
		if mime != "" {
			old.MimeType = mime
		}
		parts[pi] = old
	case "file":
		old := parts[pi].(message.FilePart)
		if url != "" {
			old.URL = url
			old.Data = ""
		} else {
			old.Data = b64
			old.URL = ""
		}
		if mime != "" {
			old.MimeType = mime
		}
		parts[pi] = old
	}
}

// replacePartWithText swaps a part out for a text placeholder. Used by
// eviction so the LLM sees a clear re-attach instruction instead of a
// broken image.
func replacePartWithText(msgs []message.Message, mi, pi int, text string) {
	msgs[mi].Content.Parts[pi] = message.TextPart{Text: text}
}

func evictionPlaceholder(kind, agentKey string) string {
	noun := "Image"
	if kind == "file" {
		noun = "File"
	}
	return fmt.Sprintf(
		"[%s %s was dropped — request exceeded size limit. Call attachToContext(%q) inside run_js if you need to see it again.]",
		noun, agentKey, agentKey,
	)
}

// isNotFound returns true when the S3 error is a 404/NoSuchKey.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		code := ae.ErrorCode()
		if code == "NoSuchKey" || code == "NotFound" || code == "404" {
			return true
		}
	}
	return false
}
