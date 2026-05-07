package api

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
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

// AgentHTTP handles POST /api/agent/http — raw HTTP proxy for public URLs.
// No auth injection (use proxy/{slug} for authenticated connections).
func (h *agentHandler) AgentHTTP(w http.ResponseWriter, r *http.Request) {
	var req agentsdk.HTTPRequest
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

	upstream, err := http.NewRequestWithContext(r.Context(), method, req.URL, bodyReader)
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

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(upstream)
	if err != nil {
		h.logger.Error("agent HTTP request failed", zap.String("url", req.URL), zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Collect response headers (first value only).
	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	ct := resp.Header.Get("Content-Type")
	binary := isBinaryContentType(ct)
	agentID := auth.AgentIDFromContext(r.Context())

	// Explicit saveAs — stream directly to S3 (binary-safe, unbounded size).
	if req.SaveAs != "" {
		s3Key := agentStorageKey(agentID, req.SaveAs)
		if err := h.s3.PutObject(r.Context(), s3Key, resp.Body, resp.ContentLength); err != nil {
			h.logger.Error("saveAs: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        contentLengthInt(resp.ContentLength),
			SavedTo:     req.SaveAs,
		})
		return
	}

	// Binary responses → always auto-save. Stream directly to S3 without
	// loading into memory so multi-MB downloads don't blow up the agent.
	if binary {
		key := generateAutoSaveKey(req.URL, ct, resp.Header.Get("Content-Disposition"))
		s3Key := agentStorageKey(agentID, key)
		if err := h.s3.PutObject(r.Context(), s3Key, resp.Body, resp.ContentLength); err != nil {
			h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        contentLengthInt(resp.ContentLength),
			SavedTo:     key,
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
			s3Key := agentStorageKey(agentID, key)
			if err := h.s3.PutObject(r.Context(), s3Key, strings.NewReader(markdown), int64(len(markdown))); err != nil {
				h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to save response")
				return
			}
			writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
				Status:      resp.StatusCode,
				Headers:     headers,
				ContentType: ct,
				SavedTo:     key,
				Note:        note + " Saved as markdown to " + key + ".",
			})
			return
		}
		writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
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
		s3Key := agentStorageKey(agentID, key)
		combined := io.MultiReader(strings.NewReader(string(peek)), resp.Body)
		if err := h.s3.PutObject(r.Context(), s3Key, combined, -1); err != nil {
			h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			SavedTo:     key,
		})
		return
	}

	writeJSON(w, http.StatusOK, agentsdk.HTTPResponse{
		Status:      resp.StatusCode,
		Headers:     headers,
		ContentType: ct,
		Size:        len(peek),
		Body:        string(peek),
	})
}

// contentLengthInt converts http.Response.ContentLength to int. Returns 0
// for unknown length (-1) or values that would overflow.
func contentLengthInt(n int64) int {
	if n <= 0 {
		return 0
	}
	return int(n)
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
