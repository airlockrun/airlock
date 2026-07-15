package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/modelresolve"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// LLMStream handles POST /api/agent/llm/stream.
func (h *Handler) LLMStream(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()

	var req wire.LLMProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Resolve model: explicit slug > capability default > agent exec_model.
	providerID, providerSlug, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Unmarshal call options from the raw JSON.
	var opts stream.CallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	// In dev mode, route LLM calls through the proxy (e.g. telescope).
	if h.llmProxyURL != "" {
		baseURL = h.llmProxyURL
	}

	// Resolve s3ref: sentinels into URLs or base64 before the provider sees
	// the messages. Providers continue to receive a standard URL-or-base64
	// Image/Data string.
	policy := solprovider.PolicyFor(providerID, modelID)
	if h.forceInlineAttachments {
		// Dev escape hatch: public URL isn't reachable from the model
		// provider. Strip URL capability so the resolver falls through
		// to base64 for every attachment.
		policy.SupportsURL = false
		policy.SupportsFileURL = false
		policy.MaxURLImages = 0
	}
	if err := attachref.ResolveForLLM(ctx, h.s3, dbq.New(h.db.Pool()), agentID, policy, opts.Messages); err != nil {
		h.logger.Error("attachref resolve for LLM failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	model := solprovider.CreateModel(providerID, modelID, solprovider.Options{
		APIKey:  apiKey,
		BaseURL: baseURL,
	})

	capture := llmUsageCapture{
		providerCatalogID: providerID,
		providerSlug:      providerSlug,
		model:             modelID,
		capability:        normalizeCapability(req.Capability),
		slug:              req.Slug,
	}
	var usageAcc stream.Usage
	started := time.Now()

	events, err := model.Stream(ctx, &opts)
	if err != nil {
		h.logger.Error("LLM stream failed", zap.Error(err))
		capture.errored = true
		capture.finishReason = "stream-init-error"
		capture.latency = time.Since(started)
		h.recordLLMUsage(agentID, runIDHdr, capture)
		writeJSONError(w, http.StatusBadGateway, "LLM stream failed")
		return
	}

	// Write NDJSON response.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	bw := bufio.NewWriter(w)
	flusher, canFlush := w.(http.Flusher)

	for event := range events {
		nd := ndJSONEvent{
			Type: string(event.Type),
			Data: sanitizeEventData(event.Data),
		}

		// ErrorEvent.Error is an `error` — not JSON-serializable. Convert to string.
		// Log mid-stream errors so platform-side LLM failures (provider 4xx, network
		// blips, etc.) show up in airlock logs instead of being silently relayed
		// to the agent as opaque NDJSON.
		if ee, ok := event.Data.(stream.ErrorEvent); ok {
			h.logger.Warn("LLM stream error",
				zap.String("provider", providerID),
				zap.String("model", modelID),
				zap.String("agent", agentID.String()),
				zap.Error(ee.Error),
			)
			nd.Data = map[string]string{"error": ee.Error.Error()}
			capture.errored = true
		}
		// Usage rides the terminal FinishEvent (one per provider
		// round-trip). Accumulate defensively in case a provider emits
		// more than one before the stream closes.
		if fe, ok := event.Data.(stream.FinishEvent); ok {
			usageAcc.Add(fe.Usage)
			capture.finishReason = string(fe.FinishReason)
		}

		line, err := json.Marshal(nd)
		if err != nil {
			// A single malformed event must not abort the entire stream —
			// the agent would read EOF and time out (surfaced to the user
			// as "context deadline exceeded"). Skip this event and keep
			// going; the run continues with the next one.
			h.logger.Error("marshal NDJSON event failed — skipping event",
				zap.String("event_type", string(event.Type)),
				zap.Error(err))
			continue
		}
		bw.Write(line)
		bw.WriteByte('\n')
		bw.Flush()
		if canFlush {
			flusher.Flush()
		}
	}

	capture.fromStreamUsage(usageAcc)
	capture.latency = time.Since(started)
	h.recordLLMUsage(agentID, runIDHdr, capture)
}

// sanitizeEventData replaces empty json.RawMessage fields on stream
// events with null so encoding/json doesn't fail with "unexpected end
// of JSON input". Empty RawMessage shows up when a provider streams a
// tool-call frame before the input has been accumulated, or on partial
// reasoning/tool-call deltas.
func sanitizeEventData(data any) any {
	switch e := data.(type) {
	case stream.ToolCallEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolResultEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolErrorEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolOutputDeniedEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	}
	return data
}

// sanitizeRawMessage normalizes a json.RawMessage to a value the JSON
// encoder accepts: empty (zero-length but non-nil) becomes null.
func sanitizeRawMessage(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("null")
	}
	return m
}

type ndJSONEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// resolveModel determines which provider row + model name to use for a
// request, then loads the row by FK and decrypts its API key.
//
// Precedence:
//  1. A non-empty slug names a registered agent_model_slots row:
//     - bound (assigned_provider_id + assigned_model) ⇒ use it directly
//     - unbound ⇒ resolve the default for the SLOT's declared capability,
//     not the request-supplied one (the slot owns the capability — it is
//     what the operator sees and binds in the UI)
//     An unregistered non-empty slug is a loud error: the agentsdk getters
//     require RegisterModel, so a missing row means a stale/typo'd slug, not
//     something to silently route to a default.
//  2. An empty slug is the capability-routed path used by the built-in media
//     tools (transcribe/vision/image/speech/embedding): resolve the default
//     for the request-supplied capability.
//
// Steps 1(unbound) and 2 then walk the agent's per-capability override pair,
// then the system_settings capability default pair (modelForCapability).
// Empty FK at every tier ⇒ "no model configured" error.
func (h *Handler) resolveModel(ctx context.Context, agentID, slug, capability string) (providerID, providerSlug, modelID, apiKey, baseURL string, err error) {
	q := dbq.New(h.db.Pool())

	agentUUID, parseErr := parseUUID(agentID)
	if parseErr != nil {
		return "", "", "", "", "", fmt.Errorf("invalid agent ID: %w", parseErr)
	}
	pgAgentID := toPgUUID(agentUUID)

	var (
		providerRowID pgtype.UUID
		modelName     string
	)

	if slug != "" {
		slot, slotErr := q.GetAgentModelSlot(ctx, dbq.GetAgentModelSlotParams{
			AgentID: pgAgentID,
			Slug:    slug,
		})
		switch {
		case errors.Is(slotErr, pgx.ErrNoRows):
			return "", "", "", "", "", fmt.Errorf("model slug %q is not registered for this agent — declare it with RegisterModel", slug)
		case slotErr != nil:
			return "", "", "", "", "", fmt.Errorf("look up model slot %q: %w", slug, slotErr)
		case slot.AssignedProviderID.Valid && slot.AssignedModel != "":
			providerRowID = slot.AssignedProviderID
			modelName = slot.AssignedModel
		default:
			// Declared but unbound: the slot's declared capability governs the
			// default fallback, overriding whatever capability the request
			// carried — a vision slot must never resolve via the text/exec pair.
			capability = slot.Capability
		}
	}

	if !providerRowID.Valid || modelName == "" {
		providerRowID, modelName, err = h.modelForCapability(ctx, q, pgAgentID, capability)
		if err != nil {
			return "", "", "", "", "", err
		}
	}
	if !providerRowID.Valid || modelName == "" {
		return "", "", "", "", "", fmt.Errorf("no model configured for capability %q — set one in admin Settings or the agent's Models tab", capability)
	}

	// Load the providers row by FK so we get the catalog provider_id and
	// API key without parsing strings.
	p, dbErr := q.GetProviderByID(ctx, providerRowID)
	if dbErr != nil {
		return "", "", "", "", "", fmt.Errorf("provider row not found: %w", dbErr)
	}
	if !p.IsEnabled {
		return "", "", "", "", "", fmt.Errorf("provider %q (%s) is disabled", p.CatalogID, p.Slug)
	}
	decrypted, decErr := h.encryptor.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
	if decErr != nil {
		return "", "", "", "", "", fmt.Errorf("decrypt API key for %q (%s): %w", p.CatalogID, p.Slug, decErr)
	}
	return p.CatalogID, p.Slug, modelName, decrypted, p.BaseUrl, nil
}

// modelForCapability picks the model for a capability using the tier-2 and
// tier-3 fallbacks: per-agent override pair, then system default pair.
// Returns invalid FK + empty name when both tiers are empty so the caller
// can produce a single clear error.
func (h *Handler) modelForCapability(ctx context.Context, q *dbq.Queries, agentID pgtype.UUID, capability string) (pgtype.UUID, string, error) {
	agent, dbErr := q.GetAgentByID(ctx, agentID)
	if dbErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get agent: %w", dbErr)
	}
	if fk, name := modelresolve.AgentCapabilityOverride(agent, capability); fk.Valid && name != "" {
		return fk, name, nil
	}
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get system settings: %w", sErr)
	}
	fk, name := modelresolve.SystemCapabilityDefault(settings, capability)
	return fk, name, nil
}

// --- Non-language model handlers ---

// ImageGenerate handles POST /api/agent/llm/image.
func (h *Handler) ImageGenerate(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, providerSlug, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve image model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateImageModel(providerID, modelID, solprovider.Options{APIKey: apiKey, BaseURL: baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support image generation", providerID))
		return
	}

	var opts model.ImageCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: providerID, providerSlug: providerSlug, model: modelID, capability: "image", slug: req.Slug}
	started := time.Now()
	result, err := m.Generate(ctx, opts)
	capture.latency = time.Since(started)
	if err != nil {
		h.logger.Error("image generation failed", zap.Error(err))
		capture.errored = true
		h.recordLLMUsage(agentID, runIDHdr, capture)
		writeJSONError(w, http.StatusBadGateway, "image generation failed: "+err.Error())
		return
	}

	// Token-priced image models (e.g. gpt-image-1) report TotalTokens —
	// route those through the catalog. Diffusion models report none; image
	// units are tracked but not priced (recorded with cost 0).
	capture.unitKind = "image"
	capture.units = float64(len(result.Images))
	if result.Usage != nil {
		capture.tokensIn = int64(result.Usage.TotalTokens)
	}
	h.recordLLMUsage(agentID, runIDHdr, capture)

	writeJSON(w, http.StatusOK, result)
}

// Embed handles POST /api/agent/llm/embedding.
func (h *Handler) Embed(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, providerSlug, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve embedding model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateEmbeddingModel(providerID, modelID, solprovider.Options{APIKey: apiKey, BaseURL: baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support embeddings", providerID))
		return
	}

	var opts model.EmbedCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: providerID, providerSlug: providerSlug, model: modelID, capability: "embedding", slug: req.Slug}
	started := time.Now()
	result, err := m.Embed(ctx, opts)
	capture.latency = time.Since(started)
	if err != nil {
		h.logger.Error("embedding failed", zap.Error(err))
		capture.errored = true
		h.recordLLMUsage(agentID, runIDHdr, capture)
		writeJSONError(w, http.StatusBadGateway, "embedding failed: "+err.Error())
		return
	}

	capture.tokensIn = int64(result.Usage.Tokens)
	h.recordLLMUsage(agentID, runIDHdr, capture)

	writeJSON(w, http.StatusOK, result)
}

// SpeechGenerate handles POST /api/agent/llm/speech.
func (h *Handler) SpeechGenerate(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, providerSlug, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve speech model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateSpeechModel(providerID, modelID, solprovider.Options{APIKey: apiKey, BaseURL: baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support speech generation", providerID))
		return
	}

	var opts model.SpeechCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: providerID, providerSlug: providerSlug, model: modelID, capability: "speech", slug: req.Slug}
	started := time.Now()
	result, err := m.Generate(ctx, opts)
	capture.latency = time.Since(started)
	if err != nil {
		h.logger.Error("speech generation failed", zap.Error(err))
		capture.errored = true
		h.recordLLMUsage(agentID, runIDHdr, capture)
		writeJSONError(w, http.StatusBadGateway, "speech generation failed: "+err.Error())
		return
	}

	// TTS bills per character; the catalog has no per-char rate, so
	// characters are tracked but not priced (recorded with cost 0).
	capture.unitKind = "character"
	if result.Usage != nil {
		capture.units = float64(result.Usage.Characters)
	}
	h.recordLLMUsage(agentID, runIDHdr, capture)

	writeJSON(w, http.StatusOK, result)
}

// Transcribe handles POST /api/agent/llm/transcription.
func (h *Handler) Transcribe(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, providerSlug, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve transcription model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateTranscriptionModel(providerID, modelID, solprovider.Options{APIKey: apiKey, BaseURL: baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support transcription", providerID))
		return
	}

	var opts model.TranscribeCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	// Normalize to MP3 if the agent sent ogg/opus — gpt-4o-transcribe
	// rejects it. Transcoder failures fall through with the original
	// bytes so whisper-1 (which accepts opus) still works.
	if audioBytes, filename, mime, tErr := audio.NormalizeForSTT(ctx, opts.Audio, opts.Filename, opts.MimeType); tErr == nil {
		opts.Audio = audioBytes
		opts.Filename = filename
		opts.MimeType = mime
	} else {
		h.logger.Warn("transcription transcode failed — sending original bytes", zap.Error(tErr))
	}

	capture := llmUsageCapture{providerCatalogID: providerID, providerSlug: providerSlug, model: modelID, capability: "transcription", slug: req.Slug}
	started := time.Now()
	result, err := m.Transcribe(ctx, opts)
	capture.latency = time.Since(started)
	if err != nil {
		h.logger.Error("transcription failed", zap.Error(err))
		capture.errored = true
		h.recordLLMUsage(agentID, runIDHdr, capture)
		writeJSONError(w, http.StatusBadGateway, "transcription failed: "+err.Error())
		return
	}

	// STT bills per audio-second; no catalog rate, so seconds are tracked
	// but not priced (recorded with cost 0).
	capture.unitKind = "second"
	if result.Usage != nil {
		capture.units = result.Usage.DurationSeconds
	}
	h.recordLLMUsage(agentID, runIDHdr, capture)

	writeJSON(w, http.StatusOK, result)
}
