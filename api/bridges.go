package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type bridgeHandler struct {
	db        *db.DB
	encryptor secrets.Store
	telegram  *trigger.TelegramDriver
	discord   *trigger.DiscordDriver
	bridgeMgr *trigger.BridgeManager
	logger    *zap.Logger
}

// CreateBridge handles POST /api/v1/bridges.
func (h *bridgeHandler) CreateBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req airlockv1.CreateBridgeRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	userID := auth.UserIDFromContext(ctx)

	// Bridge creation is a manager+ capability. `user` role is read-only on
	// bridges (they can view system bridges and bridges to agents they're a
	// member of, but not create new ones).
	if !auth.RoleAtLeast(claims.TenantRole, "manager") {
		writeError(w, http.StatusForbidden, "creating bridges requires manager role")
		return
	}

	var agentPgID pgtype.UUID
	var createdBy pgtype.UUID
	var isSystem bool

	if req.AgentId == "" {
		// System bridge — admin only.
		if !auth.RoleAtLeast(claims.TenantRole, "admin") {
			writeError(w, http.StatusForbidden, "system bridges require admin role")
			return
		}
		isSystem = true
		createdBy = toPgUUID(userID)
	} else {
		// Agent bridge — verify ownership.
		agentID, err := uuid.Parse(req.AgentId)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid agent_id")
			return
		}
		if err := verifyAgentOwnership(ctx, h.db, agentID, userID); err != nil {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}
		agentPgID = toPgUUID(agentID)
		createdBy = toPgUUID(userID)
	}

	// Default to telegram for back-compat with clients that pre-date the
	// type field. Validate the token by asking the platform who we are.
	bridgeType := req.Type
	if bridgeType == "" {
		bridgeType = "telegram"
	}
	var (
		botUsername string
		validateErr error
	)
	switch bridgeType {
	case "telegram":
		botUsername, validateErr = h.telegram.GetMe(ctx, req.Token)
	case "discord":
		botUsername, validateErr = h.discord.GetMe(ctx, req.Token)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported bridge type %q", bridgeType))
		return
	}
	if validateErr != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid bot token: %v", validateErr))
		return
	}

	encToken, err := h.encryptor.Put(ctx, "bridge/new/bot_token", req.Token)
	if err != nil {
		h.logger.Error("encrypt token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	q := dbq.New(h.db.Pool())
	br, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		Type:           bridgeType,
		Name:           req.Name,
		BotTokenRef: encToken,
		BotUsername:    botUsername,
		AgentID:        agentPgID,
		CreatedBy:      createdBy,
		IsSystem:       isSystem,
	})
	if err != nil {
		h.logger.Error("create bridge failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create bridge")
		return
	}

	// Initialize driver state. Init needs the decrypted token so the
	// driver can hit the platform API directly without round-tripping
	// through the encryptor.
	initBr := br
	initBr.BotTokenRef = req.Token
	var initErr error
	switch bridgeType {
	case "telegram":
		initErr = h.telegram.Init(ctx, &initBr)
	case "discord":
		initErr = h.discord.Init(ctx, &initBr)
	}
	if initErr != nil {
		h.logger.Warn("bridge init failed", zap.Error(initErr))
	} else if len(initBr.Config) > 0 {
		_ = q.UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{
			Config: initBr.Config,
			ID:     br.ID,
		})
	}

	// Start polling for the new bridge.
	if h.bridgeMgr != nil {
		h.bridgeMgr.AddBridge(pgUUID(br.ID))
	}

	writeProto(w, http.StatusOK, bridgeToProto(br))
}

// ListBridges handles GET /api/v1/bridges. Admins see every bridge; everyone
// else sees system bridges plus bridges bound to agents they have access to
// (via agent_members — covers agents they created and agents they were
// invited to).
func (h *bridgeHandler) ListBridges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	q := dbq.New(h.db.Pool())

	var out []*airlockv1.BridgeInfo
	if auth.RoleAtLeast(claims.TenantRole, "admin") {
		rows, err := q.ListBridgesAdmin(ctx)
		if err != nil {
			h.logger.Error("list bridges failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to list bridges")
			return
		}
		out = make([]*airlockv1.BridgeInfo, len(rows))
		for i, row := range rows {
			out[i] = bridgeAdminRowToProto(row)
		}
	} else {
		userID := auth.UserIDFromContext(ctx)
		rows, err := q.ListBridgesAccessible(ctx, toPgUUID(userID))
		if err != nil {
			h.logger.Error("list bridges failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to list bridges")
			return
		}
		out = make([]*airlockv1.BridgeInfo, len(rows))
		for i, row := range rows {
			out[i] = bridgeAccessibleRowToProto(row)
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListBridgesResponse{Bridges: out})
}

// UpdateBridge handles PUT /api/v1/bridges/{bridgeID} — today only reassigns
// agent_id. Empty agent_id moves the bridge to system-level (admin only).
func (h *bridgeHandler) UpdateBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bridgeID, err := parseUUID(chi.URLParam(r, "bridgeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}

	var req airlockv1.UpdateBridgeRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	userID := auth.UserIDFromContext(ctx)
	isAdmin := auth.RoleAtLeast(claims.TenantRole, "admin")

	q := dbq.New(h.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "bridge not found")
			return
		}
		h.logger.Error("get bridge failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get bridge")
		return
	}

	// Source authority — only the bridge's owner can change the agent it's
	// bound to. Admins explicitly cannot reassign someone else's bridge
	// (they CAN delete it via DELETE — that's the escape hatch). System
	// bridges have no per-bridge owner so they're admin-only; orphaned
	// bridges (agent_id NULL but is_system false) belong to the original
	// creator who can rebind them to a new agent.
	isCreator := br.CreatedBy.Valid && pgUUID(br.CreatedBy) == userID
	switch {
	case br.IsSystem:
		if !isAdmin {
			writeError(w, http.StatusForbidden, "system bridges require admin role to modify")
			return
		}
	case !isCreator:
		writeError(w, http.StatusForbidden, "only the bridge owner can change its agent")
		return
	}

	// Target authority — caller still has to be allowed to point the
	// bridge at the new target. Empty agent_id unbinds the bridge
	// (orphan state, owner can rebind later); making it a true system
	// bridge is a separate action wired through a dedicated endpoint.
	// A non-empty target requires ownership of that agent.
	var newAgentID pgtype.UUID
	if req.AgentId != "" {
		agentID, err := uuid.Parse(req.AgentId)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid agent_id")
			return
		}
		if !isAdmin {
			if err := verifyAgentOwnership(ctx, h.db, agentID, userID); err != nil {
				writeError(w, http.StatusForbidden, "access denied")
				return
			}
		}
		newAgentID = toPgUUID(agentID)
	}

	updated, err := q.UpdateBridgeAgentID(ctx, dbq.UpdateBridgeAgentIDParams{
		ID:      toPgUUID(bridgeID),
		AgentID: newAgentID,
	})
	if err != nil {
		h.logger.Error("update bridge failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update bridge")
		return
	}

	// Settings update is independent — when present, replace the whole
	// settings JSON. Any field the client omits implicitly resets to
	// its proto-default (false / 0); the frontend always sends the
	// full current state so this is round-trip safe.
	if req.Settings != nil {
		mode := req.Settings.PublicSessionMode
		if mode != trigger.PublicSessionModeOneShot {
			mode = trigger.PublicSessionModeSession
		}
		settings := trigger.BridgeSettings{
			AllowPublicDMs:          req.Settings.AllowPublicDms,
			PublicSessionTTLSeconds: int(req.Settings.PublicSessionTtlSeconds),
			PublicSessionMode:       mode,
		}
		raw, mErr := json.Marshal(settings)
		if mErr != nil {
			h.logger.Error("marshal settings failed", zap.Error(mErr))
			writeError(w, http.StatusInternalServerError, "failed to encode settings")
			return
		}
		updated, err = q.UpdateBridgeSettings(ctx, dbq.UpdateBridgeSettingsParams{
			ID:       toPgUUID(bridgeID),
			Settings: raw,
		})
		if err != nil {
			h.logger.Error("update bridge settings failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to update settings")
			return
		}
	}

	// Reload the poller so the running goroutine picks up the new agent_id.
	// AddBridge cancels any existing poller for this ID and starts a fresh
	// one from the updated DB row.
	if h.bridgeMgr != nil {
		h.bridgeMgr.AddBridge(bridgeID)
	}

	writeProto(w, http.StatusOK, bridgeToProto(updated))
}

// DeleteBridge handles DELETE /api/v1/bridges/{bridgeID}.
func (h *bridgeHandler) DeleteBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bridgeID, err := parseUUID(chi.URLParam(r, "bridgeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}

	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	userID := auth.UserIDFromContext(ctx)

	q := dbq.New(h.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "bridge not found")
			return
		}
		h.logger.Error("get bridge failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get bridge")
		return
	}

	// System bridges → admin only. Otherwise the creator or any admin
	// may delete — covers both live agent bridges and orphaned bridges
	// (agent_id NULL after the agent was removed but is_system false).
	isAdmin := auth.RoleAtLeast(claims.TenantRole, "admin")
	isCreator := br.CreatedBy.Valid && pgUUID(br.CreatedBy) == userID
	if br.IsSystem {
		if !isAdmin {
			writeError(w, http.StatusForbidden, "system bridges require admin role to delete")
			return
		}
	} else if !isAdmin && !isCreator {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if err := q.DeleteBridge(ctx, toPgUUID(bridgeID)); err != nil {
		h.logger.Error("delete bridge failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete bridge")
		return
	}

	// Stop the poller goroutine. Without this the deleted bridge keeps
	// polling its platform with the old token; if the user then creates
	// a new bridge with the same token, two pollers race for the same
	// Telegram long-poll session and both get 409 Conflict forever.
	if h.bridgeMgr != nil {
		h.bridgeMgr.RemoveBridge(bridgeID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// bridgeFieldsToProto is the single mapping from row fields to BridgeInfo,
// shared by bridgeToProto (single-row Create/Update/Get returns, no JOIN)
// and the two list variants which carry the owner JOIN.
func bridgeFieldsToProto(
	id, agentID, createdBy pgtype.UUID,
	typ, name, botUsername, status string,
	createdAt, updatedAt pgtype.Timestamptz,
	ownerEmail, ownerDisplayName pgtype.Text,
	settingsJSON []byte,
) *airlockv1.BridgeInfo {
	settings := trigger.DecodeBridgeSettings(settingsJSON)
	info := &airlockv1.BridgeInfo{
		Id:          pgUUID(id).String(),
		Name:        name,
		Type:        typ,
		BotUsername: botUsername,
		Status:      status,
		CreatedAt:   timestamppb.New(createdAt.Time),
		UpdatedAt:   timestamppb.New(updatedAt.Time),
		Settings: &airlockv1.BridgeSettings{
			AllowPublicDms:          settings.AllowPublicDMs,
			PublicSessionTtlSeconds: int32(settings.PublicSessionTTLSeconds),
			PublicSessionMode:       settings.PublicSessionMode,
		},
	}
	if agentID.Valid {
		info.AgentId = pgUUID(agentID).String()
	}
	// Owner is only set when both the creator UUID and the joined user row
	// are present — system bridges have CreatedBy NULL, and the LEFT JOIN
	// can produce NULL email/display_name if a user row was deleted.
	if createdBy.Valid && ownerEmail.Valid {
		info.Owner = &airlockv1.UserSummary{
			Id:          pgUUID(createdBy).String(),
			Email:       ownerEmail.String,
			DisplayName: ownerDisplayName.String,
		}
	}
	return info
}

// bridgeToProto maps a bare bridge row (no owner JOIN) — used by Create,
// Update, and Get returns where the JOIN would just be a wasted lookup.
func bridgeToProto(br dbq.Bridge) *airlockv1.BridgeInfo {
	return bridgeFieldsToProto(
		br.ID, br.AgentID, br.CreatedBy,
		br.Type, br.Name, br.BotUsername, br.Status,
		br.CreatedAt, br.UpdatedAt,
		pgtype.Text{}, pgtype.Text{},
		br.Settings,
	)
}

func bridgeAdminRowToProto(r dbq.ListBridgesAdminRow) *airlockv1.BridgeInfo {
	return bridgeFieldsToProto(
		r.ID, r.AgentID, r.CreatedBy,
		r.Type, r.Name, r.BotUsername, r.Status,
		r.CreatedAt, r.UpdatedAt,
		r.OwnerEmail, r.OwnerDisplayName,
		r.Settings,
	)
}

func bridgeAccessibleRowToProto(r dbq.ListBridgesAccessibleRow) *airlockv1.BridgeInfo {
	return bridgeFieldsToProto(
		r.ID, r.AgentID, r.CreatedBy,
		r.Type, r.Name, r.BotUsername, r.Status,
		r.CreatedAt, r.UpdatedAt,
		r.OwnerEmail, r.OwnerDisplayName,
		r.Settings,
	)
}

func verifyAgentOwnership(ctx context.Context, database *db.DB, agentID, userID uuid.UUID) error {
	q := dbq.New(database.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		return fmt.Errorf("agent not found")
	}
	if pgUUID(agent.UserID) != userID {
		return fmt.Errorf("not owner")
	}
	return nil
}
