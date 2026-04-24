package api

import (
	"net/http"
	"sort"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	solprovider "github.com/airlockrun/sol/provider"
	"go.uber.org/zap"
)

type ProvidersHandler struct {
	db  *db.DB
	enc *crypto.Encryptor
}

func NewProvidersHandler(database *db.DB, enc *crypto.Encryptor) *ProvidersHandler {
	return &ProvidersHandler{db: database, enc: enc}
}

func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateProviderRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ProviderId == "" {
		writeError(w, http.StatusBadRequest, "provider_id is required")
		return
	}
	if req.ApiKey == "" {
		writeError(w, http.StatusBadRequest, "api_key is required")
		return
	}

	if _, ok := solprovider.GetProviderInfo(req.ProviderId); !ok {
		writeError(w, http.StatusBadRequest, "unknown provider_id: "+req.ProviderId)
		return
	}

	encrypted, err := h.enc.Encrypt(req.ApiKey)
	if err != nil {
		logFor(r).Error("encrypt api key failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to encrypt api key")
		return
	}

	q := dbq.New(h.db.Pool())
	p, err := q.CreateProvider(r.Context(), dbq.CreateProviderParams{
		ProviderID:  req.ProviderId,
		DisplayName: req.DisplayName,
		ApiKey:      encrypted,
		BaseUrl:     req.BaseUrl,
		IsEnabled:   true,
	})
	if err != nil {
		logFor(r).Error("create provider failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create provider")
		return
	}

	writeProto(w, http.StatusCreated, &airlockv1.CreateProviderResponse{
		Provider: convert.ProviderToProto(p, req.ApiKey),
	})
}

func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	q := dbq.New(h.db.Pool())
	providers, err := q.ListProviders(r.Context())
	if err != nil {
		logFor(r).Error("list providers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}

	out := make([]*airlockv1.Provider, len(providers))
	for i, p := range providers {
		decrypted, err := h.enc.Decrypt(p.ApiKey)
		if err != nil {
			logFor(r).Error("decrypt api key failed", zap.Error(err), zap.String("provider", p.ProviderID))
			decrypted = "****"
		}
		out[i] = convert.ProviderToProto(p, decrypted)
	}

	writeProto(w, http.StatusOK, &airlockv1.ListProvidersResponse{Providers: out})
}

func (h *ProvidersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}

	req := &airlockv1.UpdateProviderRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	params := dbq.UpdateProviderParams{
		ID:          toPgUUID(id),
		DisplayName: req.DisplayName,
		BaseUrl:     req.BaseUrl,
	}

	if req.ApiKey != "" {
		encrypted, err := h.enc.Encrypt(req.ApiKey)
		if err != nil {
			logFor(r).Error("encrypt api key failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to encrypt api key")
			return
		}
		params.UpdateApiKey = true
		params.ApiKey = encrypted
	}

	if req.IsEnabled != nil {
		params.UpdateIsEnabled = true
		params.IsEnabled = *req.IsEnabled
	}

	q := dbq.New(h.db.Pool())
	p, err := q.UpdateProvider(r.Context(), params)
	if err != nil {
		logFor(r).Error("update provider failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update provider")
		return
	}

	decrypted, err := h.enc.Decrypt(p.ApiKey)
	if err != nil {
		decrypted = "****"
	}

	writeProto(w, http.StatusOK, &airlockv1.UpdateProviderResponse{
		Provider: convert.ProviderToProto(p, decrypted),
	})
}

func (h *ProvidersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.DeleteProvider(r.Context(), toPgUUID(id)); err != nil {
		logFor(r).Error("delete provider failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete provider")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ProvidersHandler) ListCatalogProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := solprovider.LoadProviders()
	if err != nil {
		logFor(r).Error("load catalog providers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load providers")
		return
	}

	out := make([]*airlockv1.ProviderInfo, 0, len(providers))
	for _, p := range providers {
		out = append(out, &airlockv1.ProviderInfo{
			Id:   p.ID,
			Name: p.Name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })

	writeProto(w, http.StatusOK, &airlockv1.ListCatalogProvidersResponse{Providers: out})
}

func (h *ProvidersHandler) ListCatalogModels(w http.ResponseWriter, r *http.Request) {
	providerFilter := r.URL.Query().Get("provider")

	// When ?configured=true, only return models from enabled providers in the DB.
	var configuredSet map[string]bool
	if r.URL.Query().Get("configured") == "true" {
		q := dbq.New(h.db.Pool())
		dbProviders, err := q.ListProviders(r.Context())
		if err != nil {
			logFor(r).Error("list configured providers failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to list providers")
			return
		}
		configuredSet = make(map[string]bool, len(dbProviders))
		for _, p := range dbProviders {
			if p.IsEnabled {
				configuredSet[p.ProviderID] = true
			}
		}
	}

	// AllProviders merges models.dev with the hand-maintained overlay so
	// entries like OpenAI's Whisper / TTS-1 (not in models.dev) are visible
	// to pickers. Keeping this in sync with ListCapabilities — which also
	// uses AllProviders — is what makes the STT/TTS cells in the capability
	// matrix actually populate the Settings dropdowns.
	providers, err := solprovider.AllProviders()
	if err != nil {
		logFor(r).Error("load catalog providers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load providers")
		return
	}

	var out []*airlockv1.ModelInfo
	for provID, prov := range providers {
		if providerFilter != "" && provID != providerFilter {
			continue
		}
		if configuredSet != nil && !configuredSet[provID] {
			continue
		}
		for modelID, model := range prov.Models {
			mi := &airlockv1.ModelInfo{
				Id:         modelID,
				Name:       model.Name,
				ProviderId: provID,
				ToolCall:   model.ToolCall,
				Reasoning:  model.Reasoning,
			}
			if model.Cost != nil {
				mi.CostInput = model.Cost.Input
				mi.CostOutput = model.Cost.Output
			}
			if model.Limit != nil {
				mi.ContextLimit = int32(model.Limit.Context)
				mi.OutputLimit = int32(model.Limit.Output)
			}
			if model.Modalities != nil {
				mi.InputModalities = append([]string(nil), model.Modalities.Input...)
				mi.OutputModalities = append([]string(nil), model.Modalities.Output...)
			}
			out = append(out, mi)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProviderId != out[j].ProviderId {
			return out[i].ProviderId < out[j].ProviderId
		}
		return out[i].Id < out[j].Id
	})

	writeProto(w, http.StatusOK, &airlockv1.ListCatalogModelsResponse{Models: out})
}
