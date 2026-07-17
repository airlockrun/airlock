package agentapi

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
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/sol/webfetch"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	httpMaxTimeout     = 120 // seconds
	httpDefaultTimeout = 30  // seconds
	// httpAutoSaveThreshold — text responses larger than this are streamed
	// to S3 automatically instead of returned inline. Binary responses are
	// always auto-saved regardless of size. Keeps httpRequest tool results
	// well below agentsdk.maxToolOutputLen (16 KB) so they don't burn the
	// LLM's context window on a single call.
	httpAutoSaveThreshold = 8 * 1024
	// httpMaxHTMLBytes caps the raw HTML we'll buffer for markdown
	// conversion. Pages bigger than this get treated as normal text and
	// either inlined (if somehow under the threshold) or streamed to S3.
	httpMaxHTMLBytes = 10 * 1024 * 1024 // 10 MB
)

// AgentHTTP handles POST /api/agent/http — raw HTTP proxy for permitted URLs.
// No auth injection (use proxy/{slug} for authenticated connections).
func (h *Handler) AgentHTTP(w http.ResponseWriter, r *http.Request) {
	var req wire.HTTPRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL == "" {
		writeJSONError(w, http.StatusBadRequest, "url is required")
		return
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = httpDefaultTimeout
	}
	if timeout > httpMaxTimeout {
		timeout = httpMaxTimeout
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	upstreamURL, err := h.httpNetwork.ParseURL(req.URL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request URL: "+err.Error())
		return
	}

	upstream, err := http.NewRequestWithContext(r.Context(), method, upstreamURL.String(), bodyReader)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	// Default to a real-browser UA so sites with bot heuristics or
	// edge protection (Cloudflare, etc.) don't 403 every fetch.
	// Caller-supplied User-Agent overrides via the Set below.
	upstream.Header.Set("User-Agent", webfetch.UserAgent)
	for k, v := range req.Headers {
		upstream.Header.Set(k, v)
	}

	client := h.httpNetwork.Client(time.Duration(timeout) * time.Second)
	resp, err := client.Do(upstream)
	if err != nil {
		h.logger.Error("agent HTTP request failed", zap.String("url", req.URL), zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Curated headers by default — the handful an agent reasons about.
	// Full set only on explicit opt-in (raw passthrough is mostly CSP /
	// Via / Alt-Svc / telemetry noise that burns the model's context).
	headers := curateHeaders(resp.Header, req.AllHeaders)

	ct := resp.Header.Get("Content-Type")
	binary := isBinaryContentType(ct)
	agentID := auth.AgentIDFromContext(r.Context())

	// Explicit saveAs — stream directly to S3 (binary-safe, unbounded size).
	if req.SaveAs != "" {
		s3Key, err := agentStorageKey(agentID, req.SaveAs)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid saveAs: "+err.Error())
			return
		}
		size, preview, err := streamSaveToS3(r.Context(), h.s3, s3Key, resp.Body, binary)
		if err != nil {
			h.logger.Error("saveAs: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        size,
			BodyPreview: preview,
			SavedTo:     req.SaveAs,
			Note:        fmt.Sprintf("%d bytes saved to %s.", size, req.SaveAs),
		})
		return
	}

	// Binary responses → always auto-save. Stream directly to S3 without
	// loading into memory so multi-MB downloads don't blow up the agent.
	if binary {
		key := generateAutoSaveKey(req.URL, ct, resp.Header.Get("Content-Disposition"))
		s3Key, err := agentStorageKey(agentID, key)
		if err != nil {
			h.logger.Error("auto-save: invalid generated key", zap.String("key", key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		size, _, err := streamSaveToS3(r.Context(), h.s3, s3Key, resp.Body, true)
		if err != nil {
			h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        size,
			SavedTo:     key,
			Note:        fmt.Sprintf("%d bytes of binary %s saved to %s.", size, ct, key),
		})
		return
	}

	// HTML → markdown conversion (default). The LLM almost always wants
	// prose, not tag soup. Caller can opt out with raw=true.
	if !req.Raw && isHTMLContentType(ct) {
		htmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, httpMaxHTMLBytes+1))
		if err != nil {
			h.logger.Error("read HTML body failed", zap.Error(err))
			writeJSONError(w, http.StatusBadGateway, "failed to read response body")
			return
		}
		if len(htmlBytes) > httpMaxHTMLBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("HTML response exceeds %dMB — use raw=true + saveAs to capture verbatim", httpMaxHTMLBytes/(1024*1024)))
			return
		}
		markdown := webfetch.ConvertHTMLToMarkdown(string(htmlBytes))
		note := fmt.Sprintf("Body auto-converted from %s to markdown. Pass {raw: true} to get the original HTML.", ct)
		if len(markdown) > httpAutoSaveThreshold {
			// Still too big — save the markdown to S3 rather than forcing
			// the LLM to chew through it.
			key := generateAutoSaveKey(req.URL, "text/markdown", resp.Header.Get("Content-Disposition"))
			s3Key, err := agentStorageKey(agentID, key)
			if err != nil {
				h.logger.Error("auto-save: invalid generated key", zap.String("key", key), zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to save response")
				return
			}
			if err := h.s3.PutObject(r.Context(), s3Key, strings.NewReader(markdown), int64(len(markdown))); err != nil {
				h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to save response")
				return
			}
			writeJSON(w, http.StatusOK, wire.HTTPResponse{
				Status:      resp.StatusCode,
				Headers:     headers,
				ContentType: ct,
				Size:        len(markdown),
				BodyPreview: previewText([]byte(markdown)),
				SavedTo:     key,
				Note:        fmt.Sprintf("%s %d bytes saved as markdown to %s; bodyPreview holds the head.", note, len(markdown), key),
			})
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        len(markdown),
			Body:        markdown,
			Note:        note,
		})
		return
	}

	// Text response — peek up to the auto-save threshold. If we exceed it,
	// buffer the rest to S3 so the LLM doesn't get a huge inline blob.
	peek, err := io.ReadAll(io.LimitReader(resp.Body, httpAutoSaveThreshold+1))
	if err != nil {
		h.logger.Error("read response body failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "failed to read response body")
		return
	}

	if len(peek) > httpAutoSaveThreshold {
		// Too big to inline — stitch peek + remaining stream into S3.
		// No size cap: matches the explicit saveAs path.
		key := generateAutoSaveKey(req.URL, ct, resp.Header.Get("Content-Disposition"))
		s3Key, err := agentStorageKey(agentID, key)
		if err != nil {
			h.logger.Error("auto-save: invalid generated key", zap.String("key", key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		cr := &countingReader{r: io.MultiReader(strings.NewReader(string(peek)), resp.Body)}
		if err := h.s3.PutObject(r.Context(), s3Key, cr, -1); err != nil {
			h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        cr.n,
			BodyPreview: previewText(peek),
			SavedTo:     key,
			Note:        fmt.Sprintf("%d bytes saved to %s; bodyPreview holds the head.", cr.n, key),
		})
		return
	}

	writeJSON(w, http.StatusOK, wire.HTTPResponse{
		Status:      resp.StatusCode,
		Headers:     headers,
		ContentType: ct,
		Size:        len(peek),
		Body:        string(peek),
	})
}

// previewMaxBytes is the head size kept as BodyPreview for saved text
// bodies — enough to identify the content without burning context.
const previewMaxBytes = 1024

// curateHeaders returns response headers. Default: only the few an agent
// reasons about (content negotiation, redirects, caching, pagination,
// rate limits). all=true returns every header verbatim.
func curateHeaders(h http.Header, all bool) map[string]string {
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
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	m, err := c.r.Read(p)
	c.n += m
	return m, err
}

// previewText returns a valid-UTF-8 head of b, capped at previewMaxBytes,
// for use as HTTPResponse.BodyPreview.
func previewText(b []byte) string {
	if len(b) > previewMaxBytes {
		b = b[:previewMaxBytes]
	}
	return strings.ToValidUTF8(string(b), "")
}

// streamSaveToS3 streams r into S3 at s3Key, returning the exact number
// of bytes written and — unless binary — a short UTF-8 preview of the
// head. The head is buffered once and re-prepended so the upload is
// still a single pass with no full-body buffering.
func streamSaveToS3(ctx context.Context, s3 *storage.S3Client, s3Key string, r io.Reader, binary bool) (int, string, error) {
	head := make([]byte, previewMaxBytes)
	hn, rerr := io.ReadFull(r, head)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return 0, "", rerr
	}
	head = head[:hn]
	cr := &countingReader{r: io.MultiReader(bytes.NewReader(head), r)}
	if err := s3.PutObject(ctx, s3Key, cr, -1); err != nil {
		return 0, "", err
	}
	preview := ""
	if !binary {
		preview = previewText(head)
	}
	return cr.n, preview, nil
}

// isHTMLContentType matches text/html and application/xhtml+xml (ignoring charset/params).
func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// generateAutoSaveKey builds a tmp/ key with a stable basename derived from
// Content-Disposition, the URL path, or the content type's default extension.
func generateAutoSaveKey(rawURL, contentType, contentDisposition string) string {
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
func isBinaryContentType(ct string) bool {
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
