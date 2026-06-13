package agentapi

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// agentStorageKey turns an agent storage path (e.g. "uploads/foo.png")
// into the canonical S3 key under the agent's prefix:
// "agents/{agentID}/uploads/foo.png". The path is validated via
// storage.CleanAgentPath — traversal, absolute paths, NUL bytes, and
// other malformed inputs return an error instead of reaching S3.
func agentStorageKey(agentID uuid.UUID, path string) (string, error) {
	cleaned, err := storage.CleanAgentPath(path)
	if err != nil {
		return "", err
	}
	return "agents/" + agentID.String() + "/" + cleaned, nil
}

// pathFromWildcard pulls "*" from chi as a slashless storage path. Strips
// any leading '/' (chi may include or omit it depending on route shape)
// to keep the canonical form consistent. Empty path returns ("", false).
func pathFromWildcard(r *http.Request) (string, bool) {
	rest := chi.URLParam(r, "*")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return "", false
	}
	return rest, true
}

// StorageStore handles PUT /api/agent/storage/*. Path-based: the wildcard
// is the absolute path under the agent's storage root. Original filename
// can ride on `X-Filename` and is persisted as S3 object metadata.
func (h *Handler) StorageStore(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key, err := agentStorageKey(agentID, path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
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
func (h *Handler) StorageLoad(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key, err := agentStorageKey(agentID, path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		h.serveRange(w, r, s3Key, rangeHeader)
		return
	}

	reader, err := h.s3.GetObject(r.Context(), s3Key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, reader)
}

// serveRange answers a ranged GET with 206 Partial Content. It heads the
// object for its size (needed to clamp the range and set Content-Range),
// then streams the ranged body. A malformed or unsatisfiable range gets a
// 416 with `Content-Range: bytes */<size>`.
func (h *Handler) serveRange(w http.ResponseWriter, r *http.Request, s3Key, rangeHeader string) {
	info, _, err := h.s3.HeadObject(r.Context(), s3Key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}
	start, end, ok := parseByteRange(rangeHeader, info.Size)
	if !ok {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", info.Size))
		writeJSONError(w, http.StatusRequestedRangeNotSatisfiable, "invalid range")
		return
	}
	reader, err := h.s3.GetObjectRange(r.Context(), s3Key, start, end)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
	io.Copy(w, reader)
}

// parseByteRange parses a single-range HTTP `Range` header ("bytes=start-end",
// "bytes=start-", or suffix "bytes=-N") against the object size. Returns the
// inclusive [start, end] clamped to the object, ok=false on a malformed,
// multi-range, or unsatisfiable spec.
func parseByteRange(header string, size int64) (start, end int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(header, prefix)
	if strings.Contains(spec, ",") {
		return 0, 0, false // multi-range not supported
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false
	}
	startStr, endStr := spec[:dash], spec[dash+1:]
	if startStr == "" {
		// Suffix form "bytes=-N" → last N bytes.
		n, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || n <= 0 || size == 0 {
			return 0, 0, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true
	}
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	if endStr == "" {
		end = size - 1
	} else {
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil || end < start {
			return 0, 0, false
		}
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true
}

// StorageDelete handles DELETE /api/agent/storage/*.
func (h *Handler) StorageDelete(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path, ok := pathFromWildcard(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key, err := agentStorageKey(agentID, path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	if err := h.s3.DeleteObject(r.Context(), s3Key); err != nil {
		h.logger.Error("storage delete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage delete failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageCopy handles POST /api/agent/storage/copy. Both src and dst are
// absolute paths.
func (h *Handler) StorageCopy(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if err := readJSON(r, &req); err != nil || req.Src == "" || req.Dst == "" {
		writeJSONError(w, http.StatusBadRequest, "src and dst are required")
		return
	}

	srcKey, err := agentStorageKey(agentID, req.Src)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid src: "+err.Error())
		return
	}
	dstKey, err := agentStorageKey(agentID, req.Dst)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid dst: "+err.Error())
		return
	}
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
func (h *Handler) StorageInfo(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil || req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	s3Key, err := agentStorageKey(agentID, req.Path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
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
		Path:         agentsdk.FilePath(req.Path),
		Filename:     filename,
		ContentType:  ct,
		Size:         info.Size,
		LastModified: info.LastModified,
	})
}

// StorageShare handles POST /api/agent/storage/share. Returns a presigned,
// unauthenticated, time-limited URL for the given storage path. Used by
// the agent's shareFileURL JS binding (and ShareFileURL Go method) to
// hand out a link the user — or a third party — can fetch directly,
// without going through agent membership / login on the subdomain proxy.
//
// The URL is signed for the public S3 endpoint when configured (so
// browsers, LLM providers, and external tools can resolve it from outside
// the docker network). Falls back to the internal endpoint otherwise.
//
// 404s on missing files via HeadObject pre-check so the LLM gets a clear
// signal instead of a working URL that 404s when followed.
func (h *Handler) StorageShare(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req agentsdk.ShareFileRequest
	if err := readJSON(r, &req); err != nil || req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	// Default 1h, cap 24h. Caller has no business asking for a multi-day
	// URL when they could just call shareFileURL again on demand.
	expiry := time.Duration(req.ExpiresSeconds) * time.Second
	if expiry <= 0 {
		expiry = time.Hour
	}
	if expiry > 24*time.Hour {
		expiry = 24 * time.Hour
	}

	s3Key, err := agentStorageKey(agentID, req.Path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	if _, _, err := h.s3.HeadObject(r.Context(), s3Key); err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}

	url, err := h.s3.PublicPresignGetURL(r.Context(), s3Key, expiry)
	if err != nil {
		h.logger.Error("presign share URL", zap.String("path", req.Path), zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "presign failed")
		return
	}

	writeJSON(w, http.StatusOK, agentsdk.ShareFileResponse{
		URL:         url,
		ExpiresAtMs: time.Now().Add(expiry).UnixMilli(),
	})
}

// ServeStoragePath serves reads from a registered directory on the
// subdomain proxy's /__air/storage{path} endpoint, gating by the
// directory's read_access:
//
//   - "public" — served unauthenticated (any browser can fetch the URL)
//   - "user"   — requires a valid __air_session cookie + agent membership
//   - "admin"  — requires admin role on the agent
//   - unknown  — 404
//
// Missing cookies on user/admin dirs get redirected through the relay
// flow (rejectOrRedirect) so a click-from-chat triggers login. Once
// logged in, the user lands back on the same URL with a session cookie
// set and the file streams.
//
// Unknown agent/path returns 404 — we deliberately don't distinguish
// "not authorized" from "not found" so URL-guessing leaks no info.
func ServeStoragePath(w http.ResponseWriter, r *http.Request, database *db.DB, s3 *storage.S3Client, agentID uuid.UUID, path, jwtSecret, publicURL string, logger *zap.Logger) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
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
		if err != nil || !authz.AccessAtLeast(agentsdk.Access(member.Role), agentsdk.AccessAdmin) {
			http.NotFound(w, r)
			return
		}
	default:
		// Unknown / unrecognized read_access — fail closed.
		http.NotFound(w, r)
		return
	}

	s3Key, err := agentStorageKey(agentID, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
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
//   - path=uploads/    → list under this storage path (slashless; trailing
//     '/' optional)
//   - path= (empty)    → list the agent root
//   - recursive=true|false (default false; one level only)
func (h *Handler) StorageList(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	path := strings.TrimPrefix(r.URL.Query().Get("path"), "/")
	recursive := r.URL.Query().Get("recursive") == "true"

	// agent prefix is "agents/{id}/"; the requested subprefix appends path
	// (with a trailing '/' to keep listings at directory granularity).
	agentPrefix := "agents/" + agentID.String() + "/"
	s3Prefix := agentPrefix
	if path != "" {
		s3Prefix = agentPrefix + strings.TrimSuffix(path, "/") + "/"
	}
	objects, err := h.s3.ListObjects(r.Context(), s3Prefix)
	if err != nil {
		h.logger.Error("storage list failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage list failed")
		return
	}

	files := make([]agentsdk.FileInfo, 0, len(objects))
	listPrefix := ""
	if path != "" {
		listPrefix = strings.TrimSuffix(path, "/") + "/"
	}
	for _, obj := range objects {
		// Strip "agents/{id}/" → slashless storage path.
		filePath := strings.TrimPrefix(obj.Key, agentPrefix)
		if !recursive {
			// Non-recursive: skip entries that have additional '/' under
			// the listing prefix.
			rest := strings.TrimPrefix(filePath, listPrefix)
			if strings.Contains(rest, "/") {
				continue
			}
		}
		files = append(files, agentsdk.FileInfo{
			Path:         agentsdk.FilePath(filePath),
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
