package agentapi

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/mcpaccess"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
func (s *MCPServer) listResources(ctx context.Context, h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal) (*mcp.ListResourcesResult, error) {
	targetID := uuid.UUID(target.ID.Bytes)
	roots, err := access.ListRoots(ctx, principal, targetID)
	if err != nil {
		s.logger.Error("mcp resources: resolve list roots", zap.Error(err))
		return nil, err
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
	visible, err := access.FilterList(ctx, principal, targetID, paths)
	if err != nil {
		return nil, err
	}
	out := make([]*mcp.Resource, 0, len(visible))
	for _, path := range visible {
		obj := objects[path.Relative]
		out = append(out, &mcp.Resource{URI: "agent://" + path.Relative, Name: filepath.Base(path.Relative), MIMEType: mimeFromName(path.Relative), Size: obj.Size})
	}
	return &mcp.ListResourcesResult{Resources: out, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
}

// handleResourcesRead returns the bytes of one resource. For ≤10MB
// files, inline base64. For larger files, return a friendly text +
// _meta.airlock.run/downloadUrl presigned URL.
func (s *MCPServer) readResource(ctx context.Context, h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal, uri string) (*mcp.ReadResourceResult, error) {
	path, ok := strings.CutPrefix(uri, "agent://")
	if !ok || path == "" {
		return nil, errors.New("agent resource URI is required")
	}
	resolved, err := access.ResolveFile(ctx, principal, uuid.UUID(target.ID.Bytes), path)
	if err != nil {
		return nil, errors.New("resource not found")
	}

	info, ct, err := h.s3.HeadObject(ctx, resolved.S3Key)
	if err != nil {
		return nil, errors.New("resource not found")
	}

	// Large file: return the presigned URL via _meta + a friendly text
	// stub. Spec-compliant clients that ignore _meta still get a useful
	// message; ones that read _meta open the URL directly.
	if info.Size > int64(maxInlineResourceBytes) {
		if _, err := access.ResolveFile(ctx, principal, uuid.UUID(target.ID.Bytes), path); err != nil {
			return nil, errors.New("resource not found")
		}
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
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: ct, Text: stub, Meta: meta}}, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
	}

	reader, err := h.s3.GetObject(ctx, resolved.S3Key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, int64(maxInlineResourceBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInlineResourceBytes {
		return nil, errors.New("file exceeds inline transfer limit")
	}
	if _, err := access.ResolveFile(ctx, principal, uuid.UUID(target.ID.Bytes), path); err != nil {
		return nil, errors.New("resource not found")
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: ct, Blob: raw}}, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
}

// handleResourcesTemplatesList returns one URI template per visible
// directory so clients can show a tree view of the agent's namespace.
func (s *MCPServer) listResourceTemplates(ctx context.Context, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal) (*mcp.ListResourceTemplatesResult, error) {
	roots, err := access.ListRoots(ctx, principal, uuid.UUID(target.ID.Bytes))
	if err != nil {
		return nil, err
	}
	out := make([]*mcp.ResourceTemplate, 0, len(roots))
	for _, root := range roots {
		out = append(out, &mcp.ResourceTemplate{
			URITemplate: "agent://" + root.Relative + "/{filename}",
			Name:        root.DirectoryPath,
			Description: root.Description,
		})
	}
	return &mcp.ListResourceTemplatesResult{ResourceTemplates: out, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
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
