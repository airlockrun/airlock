package api

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// agentStorageKey turns an absolute agent path (e.g. "/uploads/foo.png")
// into the canonical S3 key under the agent's prefix:
// "agents/{agentID}/uploads/foo.png" — note no extra slash between
// agentID and path because path already starts with '/'.
func agentStorageKey(agentID uuid.UUID, path string) string {
	return "agents/" + agentID.String() + path
}

// pathFromWildcard pulls "*" from chi and ensures it carries a leading '/'.
// Empty path returns ("", false) — caller should 400.
func pathFromWildcard(r *http.Request) (string, bool) {
	rest := chi.URLParam(r, "*")
	if rest == "" {
		return "", false
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return rest, true
}

// StorageStore handles PUT /api/agent/storage/*. Path-based: the wildcard
// is the absolute path under the agent's storage root. Original filename
// can ride on `X-Filename` and is persisted as S3 object metadata.
func (h *agentHandler) StorageStore(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key := agentStorageKey(agentID, path)
	meta := map[string]string{}
	if filename := r.Header.Get("X-Filename"); filename != "" {
		meta["filename"] = filename
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		meta["content-type"] = ct
	}
	if err := h.s3.PutObjectWithMetadata(r.Context(), s3Key, r.Body, r.ContentLength, meta); err != nil {
		h.logger.Error("storage put failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage put failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageLoad handles GET /api/agent/storage/*.
func (h *agentHandler) StorageLoad(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key := agentStorageKey(agentID, path)
	reader, err := h.s3.GetObject(r.Context(), s3Key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, reader)
}

// StorageDelete handles DELETE /api/agent/storage/*.
func (h *agentHandler) StorageDelete(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key := agentStorageKey(agentID, path)
	if err := h.s3.DeleteObject(r.Context(), s3Key); err != nil {
		h.logger.Error("storage delete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage delete failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageCopy handles POST /api/agent/storage/copy. Both src and dst are
// absolute paths.
func (h *agentHandler) StorageCopy(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if err := readJSON(r, &req); err != nil || req.Src == "" || req.Dst == "" {
		writeJSONError(w, http.StatusBadRequest, "src and dst are required")
		return
	}

	srcKey := agentStorageKey(agentID, req.Src)
	dstKey := agentStorageKey(agentID, req.Dst)
	if err := h.s3.CopyObject(r.Context(), srcKey, dstKey); err != nil {
		h.logger.Error("storage copy failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage copy failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageInfo handles POST /api/agent/storage/info. Body: {path}. Returns
// FileInfo with the original filename surfaced from S3 metadata when the
// upload set it (chat uploads do; raw writeFile does not).
func (h *agentHandler) StorageInfo(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil || req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key := agentStorageKey(agentID, req.Path)
	info, ct, err := h.s3.HeadObject(r.Context(), s3Key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}

	filename := pathBase(req.Path)
	if origFilename, ok := info.Metadata["filename"]; ok && origFilename != "" {
		filename = origFilename
	}

	writeJSON(w, http.StatusOK, agentsdk.FileInfo{
		Path:         req.Path,
		Filename:     filename,
		ContentType:  ct,
		Size:         info.Size,
		LastModified: info.LastModified,
	})
}

// serveStoragePath serves reads from a registered directory on the
// subdomain proxy's /__air/storage{path} endpoint, gating by the
// directory's read_access:
//
//   - "public" — served unauthenticated (any browser can fetch the URL)
//   - "user"   — requires a valid __air_session cookie + agent membership
//   - "admin"  — requires admin role on the agent
//   - "internal" / unknown — 404
//
// Missing cookies on user/admin dirs get redirected through the relay
// flow (rejectOrRedirect) so a click-from-chat triggers login. Once
// logged in, the user lands back on the same URL with a session cookie
// set and the file streams.
//
// Unknown agent/path returns 404 — we deliberately don't distinguish
// "not authorized" from "not found" so URL-guessing leaks no info.
func serveStoragePath(w http.ResponseWriter, r *http.Request, database *db.DB, s3 *storage.S3Client, agentID uuid.UUID, path, jwtSecret, publicURL string, logger *zap.Logger) {
	if path == "" || path[0] != '/' {
		http.NotFound(w, r)
		return
	}
	q := dbq.New(database.Pool())
	dir, err := q.GetDirectoryByPath(r.Context(), dbq.GetDirectoryByPathParams{
		AgentID: toPgUUID(agentID),
		Path:    path,
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch dir.ReadAccess {
	case string(agentsdk.AccessPublic):
		// no auth check
	case string(agentsdk.AccessUser):
		claims, ok := validateSubdomainAuth(r, jwtSecret)
		if !ok {
			rejectOrRedirect(w, r, publicURL)
			return
		}
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			rejectOrRedirect(w, r, publicURL)
			return
		}
		hasAccess, err := q.HasAgentAccess(r.Context(), dbq.HasAgentAccessParams{
			AgentID: toPgUUID(agentID),
			UserID:  toPgUUID(uid),
		})
		if err != nil || !hasAccess {
			http.NotFound(w, r)
			return
		}
	case string(agentsdk.AccessAdmin):
		claims, ok := validateSubdomainAuth(r, jwtSecret)
		if !ok {
			rejectOrRedirect(w, r, publicURL)
			return
		}
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			rejectOrRedirect(w, r, publicURL)
			return
		}
		member, err := q.GetAgentMember(r.Context(), dbq.GetAgentMemberParams{
			AgentID: toPgUUID(agentID),
			UserID:  toPgUUID(uid),
		})
		if err != nil || !auth.RoleAtLeast(member.Role, "admin") {
			http.NotFound(w, r)
			return
		}
	default:
		// Internal / unknown — never reachable from outside.
		http.NotFound(w, r)
		return
	}

	s3Key := agentStorageKey(agentID, path)
	reader, err := s3.GetObject(r.Context(), s3Key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer reader.Close()

	// Surface stored content-type and original filename when available so
	// browsers render images inline and downloads keep their original
	// names.
	if info, ct, err := s3.HeadObject(r.Context(), s3Key); err == nil {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if origFilename, ok := info.Metadata["filename"]; ok && origFilename != "" {
			w.Header().Set("Content-Disposition", "inline; filename=\""+origFilename+"\"")
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if _, err := io.Copy(w, reader); err != nil {
		logger.Debug("storage stream interrupted", zap.Error(err))
	}
}

// StorageList handles GET /api/agent/storage. Query params:
//   - path=/uploads/   → list under this absolute path
//   - recursive=true|false (default false; one level only)
func (h *agentHandler) StorageList(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}
	if path[0] != '/' {
		path = "/" + path
	}
	recursive := r.URL.Query().Get("recursive") == "true"

	s3Prefix := agentStorageKey(agentID, path)
	objects, err := h.s3.ListObjects(r.Context(), s3Prefix)
	if err != nil {
		h.logger.Error("storage list failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage list failed")
		return
	}

	agentPrefix := agentStorageKey(agentID, "/")
	files := make([]agentsdk.FileInfo, 0, len(objects))
	listPrefix := strings.TrimSuffix(path, "/") + "/"
	if path == "/" {
		listPrefix = "/"
	}
	for _, obj := range objects {
		// Strip "agents/{id}" → relative path; that's already absolute (starts with /).
		filePath := strings.TrimPrefix(obj.Key, agentPrefix[:len(agentPrefix)-1])
		if !recursive {
			// Non-recursive: skip entries that have additional '/' under
			// the listing prefix.
			rest := strings.TrimPrefix(filePath, listPrefix)
			if rest == filePath || strings.Contains(rest, "/") {
				continue
			}
		}
		files = append(files, agentsdk.FileInfo{
			Path:         filePath,
			Filename:     pathBase(filePath),
			Size:         obj.Size,
			LastModified: obj.LastModified,
		})
	}

	writeJSON(w, http.StatusOK, files)
}

// pathBase returns the last path segment ("/foo/bar.csv" → "bar.csv").
func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// (kept for compile-time; time import used by StorageInfo via agentsdk.FileInfo.LastModified — remove if unused)
var _ = time.Time{}
