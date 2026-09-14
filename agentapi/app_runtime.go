package agentapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apperr"
	appruntime "github.com/airlockrun/airlock/service/appruntime"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func (h *Handler) appService() *appruntime.Service {
	return appruntime.New(appruntime.Config{DB: h.db, Runtime: h.runtime, Encryptor: h.encryptor, OAuthClient: h.oauthClient, S3: h.s3, PubSub: h.pubsub, BridgeMgr: h.bridgeMgr, Scheduler: h.scheduler, PublicURL: h.publicURL, AgentBaseURL: h.agentBaseURL, HTTPNetwork: h.httpNetwork, Logger: h.logger, Builder: h.builder})
}
func (h *Handler) appError(w http.ResponseWriter, err error) {
	var required *appruntime.AuthorizationRequired
	if errors.As(err, &required) {
		writeJSON(w, http.StatusPaymentRequired, required.Details)
		return
	}
	if errors.Is(err, appruntime.ErrUpstream) {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	status := apperr.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		h.logger.Error("app runtime operation failed", zap.Error(err))
		writeJSONError(w, status, "app runtime operation failed")
		return
	}
	writeJSONError(w, status, err.Error())
}
func readAppJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return apperr.ErrInvalidInput
	}
	return nil
}

func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	var req wire.SyncRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().Sync(r.Context(), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) CreateRun(w http.ResponseWriter, r *http.Request) {
	var req wire.CreateRunRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().CreateRun(r.Context(), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) RunComplete(w http.ResponseWriter, r *http.Request) {
	var req wire.RunCompleteRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	err := h.appService().RunComplete(callbackContext(r), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) Print(w http.ResponseWriter, r *http.Request) {
	var req wire.PrintRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	err := h.appService().Print(callbackContext(r), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SessionLoad(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	result, err := h.appService().SessionLoad(r.Context(), convID)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) SessionAppend(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	var req wire.SessionAppendRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var runID pgtype.UUID
	if value := r.URL.Query().Get("runId"); value != "" {
		id, err := parseUUID(value)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid runId")
			return
		}
		runID = toPgUUID(id)
	}
	result, err := h.appService().SessionAppend(callbackContext(r), convID, req, runID)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) SessionCompact(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	var req wire.SessionCompactRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().SessionCompact(r.Context(), convID, req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) TopicSubscribe(w http.ResponseWriter, r *http.Request) {
	var req wire.TopicSubscriptionRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	convID, err := parseUUID(req.ConversationID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
		return
	}
	if err := h.appService().TopicSubscribe(r.Context(), chi.URLParam(r, "slug"), convID); err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) TopicUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var req wire.TopicSubscriptionRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	convID, err := parseUUID(req.ConversationID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
		return
	}
	if err := h.appService().TopicUnsubscribe(r.Context(), chi.URLParam(r, "slug"), convID); err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpsertEnvVar(w http.ResponseWriter, r *http.Request) {
	var req wire.EnvVarDef
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.appService().UpsertEnvVar(r.Context(), chi.URLParam(r, "slug"), req); err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetEnvVarValue(w http.ResponseWriter, r *http.Request) {
	result, err := h.appService().GetEnvVarValue(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
