package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
)

const (
	HttpMaxTimeout     = 120 // seconds
	HttpDefaultTimeout = 30  // seconds
	// httpAutoSaveThreshold — text responses larger than this are streamed
	// to S3 automatically instead of returned inline. Binary responses are
	// always auto-saved regardless of size. Keeps httpRequest tool results
	// well below agentsdk.maxToolOutputLen (16 KB) so they don't burn the
	// LLM's context window on a single call.
	HttpAutoSaveThreshold = 8 * 1024
	// httpMaxHTMLBytes caps the raw HTML we'll buffer for markdown
	// conversion. Pages bigger than this get treated as normal text and
	// either inlined (if somehow under the threshold) or streamed to S3.
	HttpMaxHTMLBytes = 10 * 1024 * 1024 // 10 MB
)

// previewMaxBytes is the head size kept as BodyPreview for saved text
// bodies — enough to identify the content without burning context.
const previewMaxBytes = 1024

// curateHeaders returns response headers. Default: only the few an agent
// reasons about (content negotiation, redirects, caching, pagination,
// rate limits). all=true returns every header verbatim.
func CurateHeaders(h http.Header, all bool) map[string]string {
	if all {
		m := make(map[string]string, len(h))
		for k := range h {
			m[k] = h.Get(k)
		}
		return m
	}
	keep := []string{
		"Content-Type", "Content-Length", "Content-Disposition",
		"Location", "Retry-After", "ETag", "Last-Modified", "Link",
	}
	m := make(map[string]string, len(keep))
	for _, k := range keep {
		if v := h.Get(k); v != "" {
			m[k] = v
		}
	}
	// Rate-limit families vary in prefix/casing across providers.
	for k := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-ratelimit-") || strings.HasPrefix(lk, "ratelimit-") {
			m[k] = h.Get(k)
		}
	}
	return m
}

// countingReader tallies bytes read so a streamed-to-S3 body can report
// an exact Size even when the upstream Content-Length is unknown
// (chunked transfer).
type CountingReader struct {
	R io.Reader
	N int
}

func (c *CountingReader) Read(p []byte) (int, error) {
	m, err := c.R.Read(p)
	c.N += m
	return m, err
}

// previewText returns a valid-UTF-8 head of b, capped at previewMaxBytes,
// for use as HTTPResponse.BodyPreview.
func PreviewText(b []byte) string {
	if len(b) > previewMaxBytes {
		b = b[:previewMaxBytes]
	}
	return strings.ToValidUTF8(string(b), "")
}

// streamSaveToS3 streams r into S3 at s3Key, returning the exact number
// of bytes written and — unless binary — a short UTF-8 preview of the
// head. The head is buffered once and re-prepended so the upload is
// still a single pass with no full-body buffering.
func StreamSaveToS3(ctx context.Context, s3 *storage.S3Client, s3Key string, r io.Reader, binary bool) (int, string, error) {
	head := make([]byte, previewMaxBytes)
	hn, rerr := io.ReadFull(r, head)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return 0, "", rerr
	}
	head = head[:hn]
	cr := &CountingReader{R: io.MultiReader(bytes.NewReader(head), r)}
	if err := s3.PutObject(ctx, s3Key, cr, -1); err != nil {
		return 0, "", err
	}
	preview := ""
	if !binary {
		preview = PreviewText(head)
	}
	return cr.N, preview, nil
}

// isHTMLContentType matches text/html and application/xhtml+xml (ignoring charset/params).
func IsHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// generateAutoSaveKey builds a tmp/ key with a stable basename derived from
// Content-Disposition, the URL path, or the content type's default extension.
func GenerateAutoSaveKey(rawURL, contentType, contentDisposition string) string {
	basename := ""
	if contentDisposition != "" {
		if _, params, err := mime.ParseMediaType(contentDisposition); err == nil {
			if name := params["filename"]; name != "" {
				basename = path.Base(name)
			}
		}
	}
	if basename == "" {
		if u, err := url.Parse(rawURL); err == nil {
			if b := path.Base(u.Path); b != "" && b != "/" && b != "." {
				basename = b
			}
		}
	}
	if basename == "" || basename == "/" {
		ext := ".bin"
		if exts, _ := mime.ExtensionsByType(contentType); len(exts) > 0 {
			ext = exts[0]
		}
		basename = "download" + ext
	}
	// Prefix a short uuid so repeated downloads don't collide.
	return fmt.Sprintf("tmp/http-%s-%s", uuid.New().String()[:8], basename)
}

// isBinaryContentType returns true if the content type represents binary data
// that should be base64-encoded rather than returned as a string.
func IsBinaryContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if strings.HasPrefix(ct, "text/") || strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml") || strings.HasPrefix(ct, "application/javascript") {
		return false
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "application/pdf") || strings.HasPrefix(ct, "application/zip") {
		return true
	}
	return false
}
