package agentapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// MCP resources/list + resources/read + resources/templates/list.
//
// Resources expose the agent's registered directories (agent_directories
// rows) over MCP so external clients can browse and download files
// without going through the chat UI. Access is gated by the directory's
// list_access / read_access tier against the caller's resolved access.
//
// URI scheme: "agent://{path}". URIs are server-opaque — clients pass
// them back to resources/read; we never expect anyone to fetch them
// directly over HTTP. Bearer auth on the JSON-RPC request is what
// carries authorization.

// handleResourcesList returns a paginated list of files the caller can
// read across all directories whose list_access they satisfy.
//
// v1: no pagination — agents typically have well under 1000 files. If a
// directory exceeds 10k entries we cap and document. Pagination via
// nextCursor can be added when actual usage hits the cap.
func (s *MCPServer) handleResourcesList(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, msg jsonrpcMessage) {
	dirs, err := q.ListDirectoriesByAgent(ctx, target.ID)
	if err != nil {
		s.logger.Error("mcp resources: list dirs", zap.Error(err))
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "list directories: "+err.Error())
		return
	}
	type entry struct {
		URI      string `json:"uri"`
		Name     string `json:"name"`
		MimeType string `json:"mimeType,omitempty"`
		Size     int64  `json:"size,omitempty"`
	}
	const perDirCap = 10000
	out := make([]entry, 0, 64)
	agentPrefix := "agents/" + uuid.UUID(target.ID.Bytes).String() + "/"
	for _, dir := range dirs {
		if !accessSatisfies(string(access), dir.ListAccess) {
			continue
		}
		// Hide framework-internal A2A inbox even to admins — it's not
		// useful to browse and only contains transient files.
		if dir.Path == "__incoming" {
			continue
		}
		prefix := agentPrefix + dir.Path + "/"
		objs, err := h.s3.ListObjects(ctx, prefix)
		if err != nil {
			s.logger.Warn("mcp resources: list objects", zap.String("prefix", prefix), zap.Error(err))
			continue
		}
		if len(objs) > perDirCap {
			s.logger.Warn("mcp resources: directory exceeds cap",
				zap.String("dir", dir.Path), zap.Int("count", len(objs)), zap.Int("cap", perDirCap))
			objs = objs[:perDirCap]
		}
		for _, obj := range objs {
			rel := strings.TrimPrefix(obj.Key, agentPrefix)
			out = append(out, entry{
				URI:      "agent://" + rel,
				Name:     filepath.Base(rel),
				MimeType: mimeFromName(rel),
				Size:     obj.Size,
			})
		}
	}
	result, _ := json.Marshal(map[string]any{"resources": out})
	writeJSONRPCResult(w, msg.ID, result)
}

// handleResourcesRead returns the bytes of one resource. For ≤10MB
// files, inline base64. For larger files, return a friendly text +
// _meta.airlock.run/downloadUrl presigned URL.
func (s *MCPServer) handleResourcesRead(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, msg jsonrpcMessage) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.URI == "" {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "uri is required")
		return
	}
	path := strings.TrimPrefix(params.URI, "agent://")
	if path == params.URI {
		// Some clients may pass the bare path. Accept that too.
	}
	cleaned, err := storage.CleanAgentPath(path)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "invalid uri path: "+err.Error())
		return
	}

	// Access check: find the longest-prefix directory whose read_access
	// the caller satisfies. Reject otherwise. We treat "no matching
	// readable directory" as 404 so URL-guessing leaks no info.
	dirs, err := q.ListDirectoriesByAgent(ctx, target.ID)
	if err != nil {
		s.logger.Error("mcp resources: list dirs for read", zap.Error(err))
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "list directories")
		return
	}
	var ownerDir *dbq.AgentDirectory
	var bestLen int
	for i := range dirs {
		d := &dirs[i]
		if !strings.HasPrefix(cleaned, d.Path+"/") && cleaned != d.Path {
			continue
		}
		if len(d.Path) <= bestLen {
			continue
		}
		bestLen = len(d.Path)
		ownerDir = d
	}
	if ownerDir == nil || !accessSatisfies(string(access), ownerDir.ReadAccess) {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "resource not found")
		return
	}

	s3Key := "agents/" + uuid.UUID(target.ID.Bytes).String() + "/" + cleaned
	info, ct, err := h.s3.HeadObject(ctx, s3Key)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "resource not found")
		return
	}

	// Large file: return the presigned URL via _meta + a friendly text
	// stub. Spec-compliant clients that ignore _meta still get a useful
	// message; ones that read _meta open the URL directly.
	if info.Size > int64(maxInlineResourceBytes) {
		url, perr := h.s3.PublicPresignGetURL(ctx, s3Key, presignedURLTTL)
		var stub string
		meta := map[string]any{"airlock.run/size": info.Size}
		if perr == nil {
			meta["airlock.run/downloadUrl"] = url
			meta["airlock.run/downloadExpiresAt"] = time.Now().Add(presignedURLTTL).UTC().Format(time.RFC3339)
			stub = "File exceeds inline transfer limit. Use the airlock.run/downloadUrl in _meta."
		} else {
			s.logger.Warn("mcp resources: presign", zap.Error(perr))
			stub = "File exceeds inline transfer limit and a download URL could not be generated."
		}
		contents := []map[string]any{{
			"uri":      params.URI,
			"mimeType": ct,
			"text":     stub,
			"_meta":    meta,
		}}
		result, _ := json.Marshal(map[string]any{"contents": contents})
		writeJSONRPCResult(w, msg.ID, result)
		return
	}

	reader, err := h.s3.GetObject(ctx, s3Key)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "fetch: "+err.Error())
		return
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, int64(maxInlineResourceBytes)+1))
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "read: "+err.Error())
		return
	}
	contents := []map[string]any{{
		"uri":      params.URI,
		"mimeType": ct,
		"blob":     base64.StdEncoding.EncodeToString(raw),
	}}
	result, _ := json.Marshal(map[string]any{"contents": contents})
	writeJSONRPCResult(w, msg.ID, result)
}

// handleResourcesTemplatesList returns one URI template per visible
// directory so clients can show a tree view of the agent's namespace.
func (s *MCPServer) handleResourcesTemplatesList(ctx context.Context, w http.ResponseWriter, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, msg jsonrpcMessage) {
	dirs, err := q.ListDirectoriesByAgent(ctx, target.ID)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "list directories: "+err.Error())
		return
	}
	type tmpl struct {
		URITemplate string `json:"uriTemplate"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	out := make([]tmpl, 0, len(dirs))
	for _, dir := range dirs {
		if !accessSatisfies(string(access), dir.ListAccess) {
			continue
		}
		if dir.Path == "__incoming" {
			continue
		}
		out = append(out, tmpl{
			URITemplate: "agent://" + dir.Path + "/{filename}",
			Name:        dir.Path,
			Description: dir.Description,
		})
	}
	result, _ := json.Marshal(map[string]any{"resourceTemplates": out})
	writeJSONRPCResult(w, msg.ID, result)
}

// mimeFromName guesses content-type from extension. Used purely as a UI
// hint in resources/list — the authoritative content-type comes from S3
// metadata via HeadObject at resources/read time. Falls back to
// application/octet-stream.
func mimeFromName(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".md":
		return "text/markdown"
	case ".json":
		return "application/json"
	case ".csv":
		return "text/csv"
	case ".html":
		return "text/html"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".mp4":
		return "video/mp4"
	}
	return "application/octet-stream"
}
