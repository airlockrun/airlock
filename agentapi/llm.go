package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/modelresolve"
	goaierrors "github.com/airlockrun/goai/errors"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func (h *Handler) validateRunHeader(w http.ResponseWriter, r *http.Request, agentID uuid.UUID, value string) bool {
	if value == "" {
		return true
	}
	runID, err := parseUUID(value)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid X-Airlock-Run-ID")
		return false
	}
	if _, err := dbq.New(h.db.Pool()).GetRunByIDAndAgent(r.Context(), dbq.GetRunByIDAndAgentParams{
		ID: toPgUUID(runID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return false
	}
	return true
}

// LLMStream handles POST /api/agent/llm/stream.
func (h *Handler) LLMStream(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runIDHdr := r.Header.Get("X-Airlock-Run-ID")
	ctx := r.Context()
	if !h.validateRunHeader(w, r, agentID, runIDHdr) {
		return
	}

	var req wire.LLMProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Resolve model: explicit slug > capability default > agent exec_model.
	resolved, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
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
		resolved.baseURL = h.llmProxyURL
	}

	// Resolve s3ref: sentinels into URLs or base64 before the provider sees
	// the messages. Providers continue to receive a standard URL-or-base64
	// Image/Data string.
	policy := solprovider.PolicyFor(resolved.providerID, resolved.modelID)
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

	model := solprovider.CreateModel(resolved.providerID, resolved.modelID, h.languageModelOptions(resolved))

	capture := llmUsageCapture{
		providerCatalogID: resolved.providerID,
		providerSlug:      resolved.providerSlug,
		model:             resolved.modelID,
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
		setLLMStreamErrorHeaders(w.Header(), err)
		writeJSONError(w, llmStreamErrorStatus(err), "LLM stream failed")
		return
	}

	// Some providers perform HTTP setup inside the returned stream. Hold their
	// initial Start event until setup is confirmed so a pre-content ErrorEvent
	// can still be returned as an HTTP error for the caller's retry policy.
	pending, setupErr := awaitLLMStreamSetup(r.Context(), events)
	if setupErr != nil {
		h.logger.Error("LLM stream setup failed", zap.Error(setupErr))
		capture.errored = true
		capture.finishReason = "stream-init-error"
		capture.latency = time.Since(started)
		h.recordLLMUsage(agentID, runIDHdr, capture)
		setLLMStreamErrorHeaders(w.Header(), setupErr)
		writeJSONError(w, llmStreamErrorStatus(setupErr), "LLM stream failed")
		return
	}

	// Write NDJSON response once provider setup has succeeded.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	bw := bufio.NewWriter(w)
	flusher, canFlush := w.(http.Flusher)

	writeEvent := func(event stream.Event) {
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
				zap.String("provider", resolved.providerID),
				zap.String("model", resolved.modelID),
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
			return
		}
		bw.Write(line)
		bw.WriteByte('\n')
		bw.Flush()
		if canFlush {
			flusher.Flush()
		}
	}
	for _, event := range pending {
		writeEvent(event)
	}
	for event := range events {
		writeEvent(event)
	}

	capture.fromStreamUsage(usageAcc)
	capture.latency = time.Since(started)
	h.recordLLMUsage(agentID, runIDHdr, capture)
}

func llmStreamErrorStatus(err error) int {
	var apiErr *goaierrors.APICallError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode <= 599 {
		return apiErr.StatusCode
	}
	return http.StatusBadGateway
}

func llmStreamErrorRetryable(err error) bool {
	var apiErr *goaierrors.APICallError
	return errors.As(err, &apiErr) && apiErr.IsRetryable
}

func setLLMStreamErrorHeaders(header http.Header, err error) {
	header.Set("X-Airlock-LLM-Retryable", strconv.FormatBool(llmStreamErrorRetryable(err)))
	var apiErr *goaierrors.APICallError
	if !errors.As(err, &apiErr) {
		return
	}
	for name, value := range apiErr.ResponseHeaders {
		if strings.EqualFold(name, "Retry-After") || strings.EqualFold(name, "Retry-After-Ms") {
			header.Set(name, value)
		}
	}
}

func awaitLLMStreamSetup(ctx context.Context, events <-chan stream.Event) ([]stream.Event, error) {
	if events == nil {
		return nil, errors.New("LLM provider returned nil event stream")
	}
	var pending []stream.Event
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return pending, nil
			}
			if eventErr, ok := event.Data.(stream.ErrorEvent); ok {
				go drainLLMStream(ctx, events)
				return nil, eventErr.Error
			}
			pending = append(pending, event)
			if event.Type != stream.EventStart {
				return pending, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func drainLLMStream(ctx context.Context, events <-chan stream.Event) {
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) languageModelOptions(resolved resolvedModel) solprovider.Options {
	opts := solprovider.Options{
		APIKey:                    resolved.apiKey,
		BaseURL:                   resolved.baseURL,
		IncludeUsage:              resolved.includeUsage,
		SupportsStructuredOutputs: resolved.supportsStructuredOutputs,
	}
	if resolved.providerID == "openai-compatible" {
		opts.HTTPClient = h.httpNetwork.ProviderEndpointClient(0)
	}
	return opts
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
type resolvedModel struct {
	providerID                string
	providerSlug              string
	modelID                   string
	apiKey                    string
	baseURL                   string
	includeUsage              *bool
	supportsStructuredOutputs *bool
}

func (h *Handler) resolveModel(ctx context.Context, agentID, slug, capability string) (resolvedModel, error) {
	q := dbq.New(h.db.Pool())

	agentUUID, parseErr := parseUUID(agentID)
	if parseErr != nil {
		return resolvedModel{}, fmt.Errorf("invalid agent ID: %w", parseErr)
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
			return resolvedModel{}, fmt.Errorf("model slug %q is not registered for this agent — declare it with RegisterModel", slug)
		case slotErr != nil:
			return resolvedModel{}, fmt.Errorf("look up model slot %q: %w", slug, slotErr)
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
		var err error
		providerRowID, modelName, err = h.modelForCapability(ctx, q, pgAgentID, capability)
		if err != nil {
			return resolvedModel{}, err
		}
	}
	if !providerRowID.Valid || modelName == "" {
		return resolvedModel{}, fmt.Errorf("no model configured for capability %q — set one in admin Settings or the agent's Models tab", capability)
	}

	// Load the providers row by FK so we get the catalog provider_id and
	// API key without parsing strings.
	p, dbErr := q.GetProviderByID(ctx, providerRowID)
	if dbErr != nil {
		return resolvedModel{}, fmt.Errorf("provider row not found: %w", dbErr)
	}
	if !p.IsEnabled {
		return resolvedModel{}, fmt.Errorf("provider %q (%s) is disabled", p.CatalogID, p.Slug)
	}
	var includeUsage *bool
	var supportsStructuredOutputs *bool
	if p.CatalogID == "openai-compatible" {
		confirmed, modelErr := q.GetProviderModel(ctx, dbq.GetProviderModelParams{
			ConfiguredProviderID: p.ID,
			ModelID:              modelName,
		})
		if modelErr != nil {
			return resolvedModel{}, fmt.Errorf("model %q is not confirmed for provider %q (%s): %w", modelName, p.CatalogID, p.Slug, modelErr)
		}
		includeUsage = &confirmed.IncludeUsage
		supportsStructuredOutputs = &confirmed.StructuredOutputs
	}
	decrypted := ""
	if p.ApiKey != "" {
		decrypted, dbErr = h.encryptor.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
		if dbErr != nil {
			return resolvedModel{}, fmt.Errorf("decrypt API key for %q (%s): %w", p.CatalogID, p.Slug, dbErr)
		}
	}
	return resolvedModel{
		providerID: p.CatalogID, providerSlug: p.Slug, modelID: modelName,
		apiKey: decrypted, baseURL: p.BaseUrl, includeUsage: includeUsage,
		supportsStructuredOutputs: supportsStructuredOutputs,
	}, nil
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
	if !h.validateRunHeader(w, r, agentID, runIDHdr) {
		return
	}
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resolved, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve image model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateImageModel(resolved.providerID, resolved.modelID, solprovider.Options{APIKey: resolved.apiKey, BaseURL: resolved.baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support image generation", resolved.providerID))
		return
	}

	var opts model.ImageCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: resolved.providerID, providerSlug: resolved.providerSlug, model: resolved.modelID, capability: "image", slug: req.Slug}
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
	if !h.validateRunHeader(w, r, agentID, runIDHdr) {
		return
	}
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resolved, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve embedding model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateEmbeddingModel(resolved.providerID, resolved.modelID, solprovider.Options{APIKey: resolved.apiKey, BaseURL: resolved.baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support embeddings", resolved.providerID))
		return
	}

	var opts model.EmbedCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: resolved.providerID, providerSlug: resolved.providerSlug, model: resolved.modelID, capability: "embedding", slug: req.Slug}
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
	if !h.validateRunHeader(w, r, agentID, runIDHdr) {
		return
	}
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resolved, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve speech model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateSpeechModel(resolved.providerID, resolved.modelID, solprovider.Options{APIKey: resolved.apiKey, BaseURL: resolved.baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support speech generation", resolved.providerID))
		return
	}

	var opts model.SpeechCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid options")
		return
	}

	capture := llmUsageCapture{providerCatalogID: resolved.providerID, providerSlug: resolved.providerSlug, model: resolved.modelID, capability: "speech", slug: req.Slug}
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
	if !h.validateRunHeader(w, r, agentID, runIDHdr) {
		return
	}
	ctx := r.Context()

	var req wire.ModelProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resolved, err := h.resolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve transcription model failed", zap.Error(err))
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	m := solprovider.CreateTranscriptionModel(resolved.providerID, resolved.modelID, solprovider.Options{APIKey: resolved.apiKey, BaseURL: resolved.baseURL})
	if m == nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not support transcription", resolved.providerID))
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

	capture := llmUsageCapture{providerCatalogID: resolved.providerID, providerSlug: resolved.providerSlug, model: resolved.modelID, capability: "transcription", slug: req.Slug}
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
