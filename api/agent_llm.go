package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// LLMStream handles POST /api/agent/llm/stream.
func (h *agentHandler) LLMStream(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	ctx := r.Context()

	var req agentsdk.LLMProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Resolve model: explicit slug > capability default > agent exec_model.
	providerID, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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

	events, err := model.Stream(ctx, &opts)
	if err != nil {
		h.logger.Error("LLM stream failed", zap.Error(err))
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
		}
		if ee, ok := event.Data.(stream.ToolErrorEvent); ok {
			nd.Data = map[string]any{
				"toolCallId": ee.ToolCallID,
				"toolName":   ee.ToolName,
				"input":      sanitizeRawMessage(ee.Input),
				"error":      ee.Error.Error(),
			}
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

// resolveModel determines which provider/model to use for a request.
//
// Precedence:
//  1. slug declared in agent_model_slots with a non-empty assigned_model
//  2. agent's per-capability override column (empty = fall through)
//  3. system_settings capability default (empty = error)
//
// An undeclared or unbound slug quietly falls through to step 2.
func (h *agentHandler) resolveModel(ctx context.Context, agentID, slug, capability string) (providerID, modelID, apiKey, baseURL string, err error) {
	q := dbq.New(h.db.Pool())

	agentUUID, parseErr := parseUUID(agentID)
	if parseErr != nil {
		return "", "", "", "", fmt.Errorf("invalid agent ID: %w", parseErr)
	}
	pgAgentID := toPgUUID(agentUUID)

	var modelStr string

	if slug != "" {
		if slot, slotErr := q.GetAgentModelSlot(ctx, dbq.GetAgentModelSlotParams{
			AgentID: pgAgentID,
			Slug:    slug,
		}); slotErr == nil && slot.AssignedModel != "" {
			modelStr = slot.AssignedModel
		}
	}

	if modelStr == "" {
		modelStr, err = h.modelForCapability(ctx, q, pgAgentID, capability)
		if err != nil {
			return "", "", "", "", err
		}
	}
	if modelStr == "" {
		return "", "", "", "", fmt.Errorf("no model configured for capability %q — set one in admin Settings or the agent's Models tab", capability)
	}

	providerID, modelID = solprovider.ParseModel(modelStr)

	// Look up the provider in DB to get API key.
	p, dbErr := q.GetProviderByProviderID(ctx, providerID)
	if dbErr != nil {
		return "", "", "", "", fmt.Errorf("provider %q not configured", providerID)
	}
	if !p.IsEnabled {
		return "", "", "", "", fmt.Errorf("provider %q is disabled", providerID)
	}
	decrypted, decErr := h.encryptor.Decrypt(p.ApiKey)
	if decErr != nil {
		return "", "", "", "", fmt.Errorf("decrypt API key for %q: %w", providerID, decErr)
	}
	return providerID, modelID, decrypted, p.BaseUrl, nil
}

// modelForCapability picks the model for a capability using the tier-2 and
// tier-3 fallbacks: per-agent column, then system default. Returns "" when
// both are empty so the caller can produce a single clear error.
func (h *agentHandler) modelForCapability(ctx context.Context, q *dbq.Queries, agentID pgtype.UUID, capability string) (string, error) {
	agent, dbErr := q.GetAgentByID(ctx, agentID)
	if dbErr != nil {
		return "", fmt.Errorf("get agent: %w", dbErr)
	}
	if override := agentCapabilityOverride(agent, capability); override != "" {
		return override, nil
	}
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return "", fmt.Errorf("get system settings: %w", sErr)
	}
	return systemCapabilityDefault(settings, capability), nil
}

// agentCapabilityOverride returns the agent's per-capability override string
// from the column matching `capability`. Empty string means "no override —
// inherit system default". An unknown capability returns "".
func agentCapabilityOverride(agent dbq.Agent, capability string) string {
	switch capability {
	case "", "text":
		return agent.ExecModel
	case "vision":
		return agent.VisionModel
	case "image":
		return agent.ImageGenModel
	case "speech":
		return agent.TtsModel
	case "transcription":
		return agent.SttModel
	case "embedding":
		return agent.EmbeddingModel
	}
	return ""
}

// systemCapabilityDefault returns the corresponding default_*_model column
// from system_settings for the given capability.
func systemCapabilityDefault(settings dbq.SystemSetting, capability string) string {
	switch capability {
	case "", "text":
		return settings.DefaultExecModel
	case "vision":
		return settings.DefaultVisionModel
	case "image":
		return settings.DefaultImageGenModel
	case "speech":
		return settings.DefaultTtsModel
	case "transcription":
		return settings.DefaultSttModel
	case "embedding":
		return settings.DefaultEmbeddingModel
	}
	return ""
}

// --- Non-language model handlers ---

// ImageGenerate handles POST /api/agent/llm/image.
func (h *agentHandler) ImageGenerate(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	ctx := r.Context()

	var req agentsdk.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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

	result, err := m.Generate(ctx, opts)
	if err != nil {
		h.logger.Error("image generation failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "image generation failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// Embed handles POST /api/agent/llm/embedding.
func (h *agentHandler) Embed(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	ctx := r.Context()

	var req agentsdk.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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

	result, err := m.Embed(ctx, opts)
	if err != nil {
		h.logger.Error("embedding failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "embedding failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// SpeechGenerate handles POST /api/agent/llm/speech.
func (h *agentHandler) SpeechGenerate(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	ctx := r.Context()

	var req agentsdk.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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

	result, err := m.Generate(ctx, opts)
	if err != nil {
		h.logger.Error("speech generation failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "speech generation failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// Transcribe handles POST /api/agent/llm/transcription.
func (h *agentHandler) Transcribe(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	ctx := r.Context()

	var req agentsdk.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerID, modelID, apiKey, baseURL, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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

	result, err := m.Transcribe(ctx, opts)
	if err != nil {
		h.logger.Error("transcription failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "transcription failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
