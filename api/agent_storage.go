package api

import (
	"io"
	"net/http"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func agentStorageKey(agentID uuid.UUID, key string) string {
	return "agents/" + agentID.String() + "/" + key
}

// StorageStore handles PUT /api/agent/storage/*.
func (h *agentHandler) StorageStore(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	key := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if key == "" {
		writeJSONError(w, http.StatusBadRequest, "key is required")
		return
	}

	s3Key := agentStorageKey(agentID, key)
	if err := h.s3.PutObject(r.Context(), s3Key, r.Body, r.ContentLength); err != nil {
		h.logger.Error("storage put failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage put failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageLoad handles GET /api/agent/storage/*.
func (h *agentHandler) StorageLoad(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	key := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if key == "" {
		writeJSONError(w, http.StatusBadRequest, "key is required")
		return
	}

	s3Key := agentStorageKey(agentID, key)
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
	key := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if key == "" {
		writeJSONError(w, http.StatusBadRequest, "key is required")
		return
	}

	s3Key := agentStorageKey(agentID, key)
	if err := h.s3.DeleteObject(r.Context(), s3Key); err != nil {
		h.logger.Error("storage delete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage delete failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StorageCopy handles POST /api/agent/storage/copy.
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

// StorageInfo handles POST /api/agent/storage/info.
func (h *agentHandler) StorageInfo(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req struct {
		Key string `json:"key"`
	}
	if err := readJSON(r, &req); err != nil || req.Key == "" {
		writeJSONError(w, http.StatusBadRequest, "key is required")
		return
	}

	s3Key := agentStorageKey(agentID, req.Key)
	info, contentType, err := h.s3.HeadObject(r.Context(), s3Key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found")
		return
	}

	writeJSON(w, http.StatusOK, agentsdk.StoredFile{
		Key:          req.Key,
		Size:         info.Size,
		ContentType:  contentType,
		LastModified: info.LastModified,
	})
}

// GetAttachment handles GET /api/agent/files/{fileID}.
func (h *agentHandler) GetAttachment(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	if fileID == "" {
		writeJSONError(w, http.StatusBadRequest, "fileID is required")
		return
	}

	key := "attachments/" + fileID
	reader, err := h.s3.GetObject(r.Context(), key)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "file not found")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, reader)
}

// serveStorageZone serves reads from a registered storage zone on the
// subdomain proxy's /__air/storage/{slug}/{key...} path, gating by the
// zone's read_access:
//
//   - "public" — served unauthenticated (any browser can fetch the URL)
//   - "user"   — requires a valid __air_session cookie + agent membership
//   - "admin"  — requires admin role on the agent
//   - "internal" / unknown — 404
//
// Missing cookies on user/admin zones get redirected through the relay
// flow (rejectOrRedirect) so a click-from-chat triggers login. Once
// logged in, the user lands back on the same URL with a session cookie
// set and the file streams.
//
// Unknown agent/zone returns 404 — we deliberately don't distinguish
// "not authorized" from "not found" so URL-guessing leaks no information.
func serveStorageZone(w http.ResponseWriter, r *http.Request, database *db.DB, s3 *storage.S3Client, agentID uuid.UUID, zoneSlug, key, jwtSecret, publicURL string, logger *zap.Logger) {
	if zoneSlug == "" || key == "" {
		http.NotFound(w, r)
		return
	}
	q := dbq.New(database.Pool())
	zone, err := q.GetStorageZone(r.Context(), dbq.GetStorageZoneParams{
		AgentID: toPgUUID(agentID),
		Slug:    zoneSlug,
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch zone.ReadAccess {
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

	s3Key := agentStorageKey(agentID, zoneSlug+"/"+key)
	reader, err := s3.GetObject(r.Context(), s3Key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, reader); err != nil {
		logger.Debug("storage stream interrupted", zap.Error(err))
	}
}

// StorageList handles GET /api/agent/storage (no wildcard).
func (h *agentHandler) StorageList(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	prefix := r.URL.Query().Get("prefix")

	s3Prefix := agentStorageKey(agentID, prefix)
	objects, err := h.s3.ListObjects(r.Context(), s3Prefix)
	if err != nil {
		h.logger.Error("storage list failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "storage list failed")
		return
	}

	agentPrefix := agentStorageKey(agentID, "")
	files := make([]agentsdk.StoredFile, len(objects))
	for i, obj := range objects {
		files[i] = agentsdk.StoredFile{
			Key:          strings.TrimPrefix(obj.Key, agentPrefix),
			Size:         obj.Size,
			LastModified: obj.LastModified,
		}
	}

	writeJSON(w, http.StatusOK, files)
}
