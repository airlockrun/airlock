package agentapi

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/sol/webfetch"
	"github.com/google/uuid"
	"go.uber.org/zap"
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
	if req.SaveAs != "" {
		runID, err := uuid.Parse(req.RunID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "runId is required for saveAs")
			return
		}
		if _, err := h.appService().ResolveRun(callbackContext(r), runID); err != nil {
			h.appError(w, err)
			return
		}
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = runtimesvc.HttpDefaultTimeout
	}
	if timeout > runtimesvc.HttpMaxTimeout {
		timeout = runtimesvc.HttpMaxTimeout
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
	headers := runtimesvc.CurateHeaders(resp.Header, req.AllHeaders)

	ct := resp.Header.Get("Content-Type")
	binary := runtimesvc.IsBinaryContentType(ct)
	agentID := auth.AgentIDFromContext(r.Context())

	// Explicit saveAs — stream directly to S3 (binary-safe, unbounded size).
	if req.SaveAs != "" {
		runID, err := uuid.Parse(req.RunID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "runId is required for saveAs")
			return
		}
		resolved, err := h.files.ResolveForRun(r.Context(), agentID, runID, req.SaveAs, agentstoragesvc.OperationWrite)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "saveAs path not found")
			return
		}
		size, preview, err := runtimesvc.StreamSaveToS3(r.Context(), h.s3, resolved.S3Key, resp.Body, binary)
		if err != nil {
			h.logger.Error("saveAs: S3 put failed", zap.String("key", resolved.S3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        size,
			BodyPreview: preview,
			SavedTo:     resolved.Relative,
			Note:        fmt.Sprintf("%d bytes saved to %s.", size, resolved.Relative),
		})
		return
	}

	// Binary responses → always auto-save. Stream directly to S3 without
	// loading into memory so multi-MB downloads don't blow up the agent.
	if binary {
		key := runtimesvc.GenerateAutoSaveKey(req.URL, ct, resp.Header.Get("Content-Disposition"))
		s3Key, err := agentStorageKey(agentID, key)
		if err != nil {
			h.logger.Error("auto-save: invalid generated key", zap.String("key", key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		size, _, err := runtimesvc.StreamSaveToS3(r.Context(), h.s3, s3Key, resp.Body, true)
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
	if !req.Raw && runtimesvc.IsHTMLContentType(ct) {
		htmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, runtimesvc.HttpMaxHTMLBytes+1))
		if err != nil {
			h.logger.Error("read HTML body failed", zap.Error(err))
			writeJSONError(w, http.StatusBadGateway, "failed to read response body")
			return
		}
		if len(htmlBytes) > runtimesvc.HttpMaxHTMLBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("HTML response exceeds %dMB — use raw=true + saveAs to capture verbatim", runtimesvc.HttpMaxHTMLBytes/(1024*1024)))
			return
		}
		markdown := webfetch.ConvertHTMLToMarkdown(string(htmlBytes))
		note := fmt.Sprintf("Body auto-converted from %s to markdown. Pass {raw: true} to get the original HTML.", ct)
		if len(markdown) > runtimesvc.HttpAutoSaveThreshold {
			// Still too big — save the markdown to S3 rather than forcing
			// the LLM to chew through it.
			key := runtimesvc.GenerateAutoSaveKey(req.URL, "text/markdown", resp.Header.Get("Content-Disposition"))
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
				BodyPreview: runtimesvc.PreviewText([]byte(markdown)),
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
	peek, err := io.ReadAll(io.LimitReader(resp.Body, runtimesvc.HttpAutoSaveThreshold+1))
	if err != nil {
		h.logger.Error("read response body failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "failed to read response body")
		return
	}

	if len(peek) > runtimesvc.HttpAutoSaveThreshold {
		// Too big to inline — stitch peek + remaining stream into S3.
		// No size cap: matches the explicit saveAs path.
		key := runtimesvc.GenerateAutoSaveKey(req.URL, ct, resp.Header.Get("Content-Disposition"))
		s3Key, err := agentStorageKey(agentID, key)
		if err != nil {
			h.logger.Error("auto-save: invalid generated key", zap.String("key", key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		cr := &runtimesvc.CountingReader{R: io.MultiReader(strings.NewReader(string(peek)), resp.Body)}
		if err := h.s3.PutObject(r.Context(), s3Key, cr, -1); err != nil {
			h.logger.Error("auto-save: S3 put failed", zap.String("key", s3Key), zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to save response")
			return
		}
		writeJSON(w, http.StatusOK, wire.HTTPResponse{
			Status:      resp.StatusCode,
			Headers:     headers,
			ContentType: ct,
			Size:        cr.N,
			BodyPreview: runtimesvc.PreviewText(peek),
			SavedTo:     key,
			Note:        fmt.Sprintf("%d bytes saved to %s; bodyPreview holds the head.", cr.N, key),
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
