package agentapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
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
func (s *MCPServer) handleResourcesList(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
	targetID := uuid.UUID(target.ID.Bytes)
	caller := mcpFileCaller(access, principal)
	roots, err := h.files.ListRoots(ctx, caller, targetID)
	if err != nil {
		s.logger.Error("mcp resources: resolve list roots", zap.Error(err))
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
	agentPrefix := "agents/" + targetID.String() + "/"
	objects := make(map[string]storage.ObjectInfo)
	for _, root := range roots {
		prefix := root.S3Key + "/"
		objs, err := h.s3.ListObjects(ctx, prefix)
		if err != nil {
			s.logger.Warn("mcp resources: list objects", zap.String("prefix", prefix), zap.Error(err))
			continue
		}
		if len(objs) > perDirCap {
			s.logger.Warn("mcp resources: directory exceeds cap",
				zap.String("dir", root.DirectoryPath), zap.Int("count", len(objs)), zap.Int("cap", perDirCap))
			objs = objs[:perDirCap]
		}
		for _, obj := range objs {
			rel := strings.TrimPrefix(obj.Key, agentPrefix)
			objects[rel] = obj
		}
	}
	paths := make([]string, 0, len(objects))
	for path := range objects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	visible, err := h.files.FilterList(ctx, caller, targetID, paths)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "authorize directory listing")
		return
	}
	out := make([]entry, 0, len(visible))
	for _, path := range visible {
		obj := objects[path.Relative]
		out = append(out, entry{URI: "agent://" + path.Relative, Name: filepath.Base(path.Relative), MimeType: mimeFromName(path.Relative), Size: obj.Size})
	}
	result, _ := json.Marshal(map[string]any{"resources": out})
	writeJSONRPCResult(w, msg.ID, result)
}

// handleResourcesRead returns the bytes of one resource. For ≤10MB
// files, inline base64. For larger files, return a friendly text +
// _meta.airlock.run/downloadUrl presigned URL.
func (s *MCPServer) handleResourcesRead(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
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
	resolved, err := h.files.Resolve(ctx, mcpFileCaller(access, principal), uuid.UUID(target.ID.Bytes), path, agentstoragesvc.OperationRead)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "resource not found")
		return
	}

	info, ct, err := h.s3.HeadObject(ctx, resolved.S3Key)
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "resource not found")
		return
	}

	// Large file: return the presigned URL via _meta + a friendly text
	// stub. Spec-compliant clients that ignore _meta still get a useful
	// message; ones that read _meta open the URL directly.
	if info.Size > int64(maxInlineResourceBytes) {
		url, perr := h.s3.PublicPresignGetURL(ctx, resolved.S3Key, presignedURLTTL)
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

	reader, err := h.s3.GetObject(ctx, resolved.S3Key)
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
func (s *MCPServer) handleResourcesTemplatesList(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
	roots, err := h.files.ListRoots(ctx, mcpFileCaller(access, principal), uuid.UUID(target.ID.Bytes))
	if err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "list directories: "+err.Error())
		return
	}
	type tmpl struct {
		URITemplate string `json:"uriTemplate"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	out := make([]tmpl, 0, len(roots))
	for _, root := range roots {
		out = append(out, tmpl{
			URITemplate: "agent://" + root.Relative + "/{filename}",
			Name:        root.DirectoryPath,
			Description: root.Description,
		})
	}
	result, _ := json.Marshal(map[string]any{"resourceTemplates": out})
	writeJSONRPCResult(w, msg.ID, result)
}

func mcpFileCaller(access agentsdk.Access, principal MCPPrincipal) agentstoragesvc.Caller {
	caller := agentstoragesvc.Caller{Access: access, UserID: principal.UserID, ParentRunID: principal.ParentRunID}
	if principal.Kind == MCPPrincipalAnon {
		caller.Principal = authz.AnonymousPrincipal()
		return caller
	}
	caller.Principal = authz.UserPrincipal(principal.UserID, "")
	caller.Principal.OnBehalfOfAgent = principal.CallerAgentID
	return caller
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
