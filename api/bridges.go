package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type bridgeHandler struct {
	svc *bridgessvc.Service
}

func newBridgeHandler(svc *bridgessvc.Service) *bridgeHandler {
	if svc == nil {
		panic("api: bridges.Service is required")
	}
	return &bridgeHandler{svc: svc}
}

// tenantClaims extracts (userID, tenantRole) from the request ctx;
// returns ok=false and writes 401 if no auth claims are present.
func tenantClaims(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return uuid.Nil, "", false
	}
	return auth.UserIDFromContext(r.Context()), claims.TenantRole, true
}

// writeBridgesError renders sentinels with the original fallback strings.
// Detail-wrapped errors (Detail(...) → err.Error()) win so the specific
// reason text travels with the error.
func writeBridgesError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrForbidden):
		// Specific message attached via service.Detail; if no Detail
		// wrap exists fall through to a sensible generic.
		if msg := err.Error(); msg != "invalid input" && msg != "forbidden" {
			writeError(w, status, msg)
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, status, "access denied")
			return
		}
		writeError(w, status, "invalid input")
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "not authenticated")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "bridge not found")
	default:
		writeError(w, status, fallback)
	}
}

// CreateBridge handles POST /api/v1/bridges.
func (h *bridgeHandler) CreateBridge(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.CreateBridgeRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, tenantRole, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Create(r.Context(), userID, tenantRole, bridgessvc.CreateRequest{
		Type:    req.Type,
		Name:    req.Name,
		Token:   req.Token,
		AgentID: req.AgentId,
	})
	if err != nil {
		writeBridgesError(w, err, "failed to create bridge")
		return
	}
	writeProto(w, http.StatusOK, bridgeResultToProto(res))
}

// ListBridges handles GET /api/v1/bridges.
func (h *bridgeHandler) ListBridges(w http.ResponseWriter, r *http.Request) {
	userID, tenantRole, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), userID, tenantRole)
	if err != nil {
		writeBridgesError(w, err, "failed to list bridges")
		return
	}
	out := make([]*airlockv1.BridgeInfo, len(items))
	for i, item := range items {
		out[i] = bridgeListItemToProto(item)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListBridgesResponse{Bridges: out})
}

// UpdateBridge handles PUT /api/v1/bridges/{bridgeID}.
func (h *bridgeHandler) UpdateBridge(w http.ResponseWriter, r *http.Request) {
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
	userID, tenantRole, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	upd := bridgessvc.UpdateRequest{AgentID: req.AgentId}
	if req.Settings != nil {
		upd.Settings = &bridgessvc.SettingsUpdate{
			AllowPublicDMs:             req.Settings.AllowPublicDms,
			PublicSessionTTLSeconds:    req.Settings.PublicSessionTtlSeconds,
			PublicSessionMode:          req.Settings.PublicSessionMode,
			PublicPromptTimeoutSeconds: req.Settings.PublicPromptTimeoutSeconds,
		}
	}
	res, err := h.svc.Update(r.Context(), userID, tenantRole, bridgeID, upd)
	if err != nil {
		writeBridgesError(w, err, "failed to update bridge")
		return
	}
	writeProto(w, http.StatusOK, bridgeResultToProto(res))
}

// DeleteBridge handles DELETE /api/v1/bridges/{bridgeID}.
func (h *bridgeHandler) DeleteBridge(w http.ResponseWriter, r *http.Request) {
	bridgeID, err := parseUUID(chi.URLParam(r, "bridgeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}
	userID, tenantRole, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), userID, tenantRole, bridgeID); err != nil {
		writeBridgesError(w, err, "failed to delete bridge")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- proto helpers ---

func bridgeResultToProto(res bridgessvc.Result) *airlockv1.BridgeInfo {
	var ownerEmail, ownerName pgtype.Text
	var createdBy pgtype.UUID
	if res.Owner != nil {
		ownerEmail = pgtype.Text{String: res.Owner.Email, Valid: true}
		ownerName = pgtype.Text{String: res.Owner.DisplayName, Valid: true}
		createdBy = pgtype.UUID{Bytes: res.Owner.ID, Valid: true}
	} else {
		createdBy = res.Bridge.CreatedBy
	}
	return bridgeFieldsToProto(
		res.Bridge.ID, res.Bridge.AgentID, createdBy,
		res.Bridge.Type, res.Bridge.Name, res.Bridge.BotUsername, res.Bridge.Status,
		res.Bridge.CreatedAt, res.Bridge.UpdatedAt,
		ownerEmail, ownerName,
		res.Bridge.Settings,
	)
}

func bridgeListItemToProto(item bridgessvc.ListItem) *airlockv1.BridgeInfo {
	var ownerEmail, ownerName pgtype.Text
	if item.Owner != nil {
		ownerEmail = pgtype.Text{String: item.Owner.Email, Valid: true}
		ownerName = pgtype.Text{String: item.Owner.DisplayName, Valid: true}
	}
	return bridgeFieldsToProto(
		item.Bridge.ID, item.Bridge.AgentID, item.Bridge.CreatedBy,
		item.Bridge.Type, item.Bridge.Name, item.Bridge.BotUsername, item.Bridge.Status,
		item.Bridge.CreatedAt, item.Bridge.UpdatedAt,
		ownerEmail, ownerName,
		item.Bridge.Settings,
	)
}

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
			AllowPublicDms:             settings.AllowPublicDMs,
			PublicSessionTtlSeconds:    int32(settings.PublicSessionTTLSeconds),
			PublicSessionMode:          settings.PublicSessionMode,
			PublicPromptTimeoutSeconds: int32(settings.PublicPromptTimeoutSeconds),
		},
	}
	if agentID.Valid {
		info.AgentId = pgUUID(agentID).String()
	}
	if createdBy.Valid && ownerEmail.Valid {
		info.Owner = &airlockv1.UserSummary{
			Id:          pgUUID(createdBy).String(),
			Email:       ownerEmail.String,
			DisplayName: ownerDisplayName.String,
		}
	}
	return info
}

// bridgeToProto: bare row → BridgeInfo (no owner JOIN), used by other
// callers in the api package that synthesize a BridgeInfo from a fresh
// row.
func bridgeToProto(br dbq.Bridge) *airlockv1.BridgeInfo {
	return bridgeFieldsToProto(
		br.ID, br.AgentID, br.CreatedBy,
		br.Type, br.Name, br.BotUsername, br.Status,
		br.CreatedAt, br.UpdatedAt,
		pgtype.Text{}, pgtype.Text{},
		br.Settings,
	)
}

// verifyAgentOwnership remains in the api package because credentials.go
// uses it from its own handler. The bridges service has its own copy
// since it's part of the gating boundary now.
func verifyAgentOwnership(ctx context.Context, database *db.DB, agentID, userID uuid.UUID) error {
	q := dbq.New(database.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return errAgentNotFound
	}
	if pgUUID(agent.UserID) != userID {
		return errAgentNotOwner
	}
	return nil
}

var (
	errAgentNotFound = errors.New("agent not found")
	errAgentNotOwner = errors.New("not owner")
)
