package appruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/execution"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (h *Service) modelRun(ctx context.Context, value string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	q := dbq.New(h.db.Pool())
	appID, err := h.admit(ctx, q)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	runID, err := parseUUID(value)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, apperr.Detail(apperr.ErrInvalidInput, "a run ID is required")
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: toPgUUID(runID), AgentID: toPgUUID(appID)})
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, apperr.ErrNotFound
	}
	if run.Status != "running" {
		return uuid.Nil, uuid.Nil, uuid.Nil, apperr.ErrConflict
	}
	admitted, err := execution.ResolveInvocation(ctx, q, appID, runID, auth.AgentTokenVersionFromContext(ctx), execution.InvocationProofFromContext(ctx))
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return appID, runID, uuid.UUID(admitted.Run.RuntimeOwnerToken.Bytes), nil
}

type ModelStream struct {
	Events   <-chan stream.Event
	Provider string
	Model    string
}

func (h *Service) watchModel(ctx context.Context, appID, runID, ownerToken uuid.UUID) (context.Context, func()) {
	if ownerToken != uuid.Nil {
		ctx = execution.WithRuntimeOwner(ctx, runID, ownerToken)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := execution.Watch(ctx, dbq.New(h.db.Pool()), appID, runID, cancel)
	return ctx, func() { cancel(); stop() }
}

func (h *Service) LLMStream(ctx context.Context, runIDHeader string, req wire.LLMProxyRequest) (ModelStream, error) {
	appID, runID, ownerToken, err := h.modelRun(ctx, runIDHeader)
	if err != nil {
		return ModelStream{}, err
	}
	var opts stream.CallOptions
	if ownerToken != uuid.Nil {
		ctx = execution.WithRuntimeOwner(ctx, runID, ownerToken)
	}
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		return ModelStream{}, apperr.ErrInvalidInput
	}
	resolved, err := h.runtime.RuntimeModel(ctx, appID, runID, req.Slug, req.Capability)
	if err != nil {
		return ModelStream{}, err
	}
	events, err := resolved.Stream(ctx, &opts)
	if err != nil {
		return ModelStream{}, err
	}
	return ModelStream{Events: events, Provider: resolved.Provider(), Model: resolved.ID()}, nil
}

func (h *Service) ImageGenerate(ctx context.Context, runIDHdr string, req wire.ModelProxyRequest) (*model.ImageResult, error) {
	agentID, runID, ownerToken, err := h.modelRun(ctx, runIDHdr)
	if err != nil {
		return nil, err
	}
	ctx, stop := h.watchModel(ctx, agentID, runID, ownerToken)
	defer stop()
	resolved, err := h.runtime.ResolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve image model failed", zap.Error(err))
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", err.Error())
	}

	m := solprovider.CreateImageModel(resolved.ProviderID, resolved.ModelID, solprovider.Options{APIKey: resolved.ApiKey, BaseURL: resolved.BaseURL})
	if m == nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("provider %q does not support image generation", resolved.ProviderID))
	}

	var opts model.ImageCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "invalid options")
	}

	capture := runtimesvc.LlmUsageCapture{ProviderCatalogID: resolved.ProviderID, ProviderSlug: resolved.ProviderSlug, Model: resolved.ModelID, Capability: "image", Slug: req.Slug, TaskOwnerToken: ownerToken, TaskUsageID: uuid.New()}
	started := time.Now()
	result, err := m.Generate(ctx, opts)
	capture.Latency = time.Since(started)
	if err != nil {
		h.logger.Error("image generation failed", zap.Error(err))
		capture.Errored = true
		h.runtime.RecordLLMUsage(agentID, runIDHdr, capture)
		return nil, fmt.Errorf("%s: %w", "image generation failed: "+err.Error(), ErrUpstream)
	}

	// Token-priced image models (e.g. gpt-image-1) report TotalTokens —
	// route those through the catalog. Diffusion models report none; image
	// units are tracked but not priced (recorded with cost 0).
	capture.UnitKind = "image"
	capture.Units = float64(len(result.Images))
	if result.Usage != nil {
		capture.TokensIn = int64(result.Usage.TotalTokens)
	}
	if err := h.runtime.RecordLLMUsage(agentID, runIDHdr, capture); err != nil {
		return nil, err
	}

	return result, nil
}

func (h *Service) Embed(ctx context.Context, runIDHdr string, req wire.ModelProxyRequest) (*model.EmbedResult, error) {
	agentID, runID, ownerToken, err := h.modelRun(ctx, runIDHdr)
	if err != nil {
		return nil, err
	}
	ctx, stop := h.watchModel(ctx, agentID, runID, ownerToken)
	defer stop()
	resolved, err := h.runtime.ResolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve embedding model failed", zap.Error(err))
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", err.Error())
	}

	m := solprovider.CreateEmbeddingModel(resolved.ProviderID, resolved.ModelID, solprovider.Options{APIKey: resolved.ApiKey, BaseURL: resolved.BaseURL})
	if m == nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("provider %q does not support embeddings", resolved.ProviderID))
	}

	var opts model.EmbedCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "invalid options")
	}

	capture := runtimesvc.LlmUsageCapture{ProviderCatalogID: resolved.ProviderID, ProviderSlug: resolved.ProviderSlug, Model: resolved.ModelID, Capability: "embedding", Slug: req.Slug, TaskOwnerToken: ownerToken, TaskUsageID: uuid.New()}
	started := time.Now()
	result, err := m.Embed(ctx, opts)
	capture.Latency = time.Since(started)
	if err != nil {
		h.logger.Error("embedding failed", zap.Error(err))
		capture.Errored = true
		h.runtime.RecordLLMUsage(agentID, runIDHdr, capture)
		return nil, fmt.Errorf("%s: %w", "embedding failed: "+err.Error(), ErrUpstream)
	}

	capture.TokensIn = int64(result.Usage.Tokens)
	if err := h.runtime.RecordLLMUsage(agentID, runIDHdr, capture); err != nil {
		return nil, err
	}

	return result, nil
}

func (h *Service) SpeechGenerate(ctx context.Context, runIDHdr string, req wire.ModelProxyRequest) (*model.SpeechResult, error) {
	agentID, runID, ownerToken, err := h.modelRun(ctx, runIDHdr)
	if err != nil {
		return nil, err
	}
	ctx, stop := h.watchModel(ctx, agentID, runID, ownerToken)
	defer stop()
	resolved, err := h.runtime.ResolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve speech model failed", zap.Error(err))
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", err.Error())
	}

	m := solprovider.CreateSpeechModel(resolved.ProviderID, resolved.ModelID, solprovider.Options{APIKey: resolved.ApiKey, BaseURL: resolved.BaseURL})
	if m == nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("provider %q does not support speech generation", resolved.ProviderID))
	}

	var opts model.SpeechCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "invalid options")
	}

	capture := runtimesvc.LlmUsageCapture{ProviderCatalogID: resolved.ProviderID, ProviderSlug: resolved.ProviderSlug, Model: resolved.ModelID, Capability: "speech", Slug: req.Slug, TaskOwnerToken: ownerToken, TaskUsageID: uuid.New()}
	started := time.Now()
	result, err := m.Generate(ctx, opts)
	capture.Latency = time.Since(started)
	if err != nil {
		h.logger.Error("speech generation failed", zap.Error(err))
		capture.Errored = true
		h.runtime.RecordLLMUsage(agentID, runIDHdr, capture)
		return nil, fmt.Errorf("%s: %w", "speech generation failed: "+err.Error(), ErrUpstream)
	}

	// TTS bills per character; the catalog has no per-char rate, so
	// characters are tracked but not priced (recorded with cost 0).
	capture.UnitKind = "character"
	if result.Usage != nil {
		capture.Units = float64(result.Usage.Characters)
	}
	if err := h.runtime.RecordLLMUsage(agentID, runIDHdr, capture); err != nil {
		return nil, err
	}

	return result, nil
}

func (h *Service) Transcribe(ctx context.Context, runIDHdr string, req wire.ModelProxyRequest) (*model.TranscriptionResult, error) {
	agentID, runID, ownerToken, err := h.modelRun(ctx, runIDHdr)
	if err != nil {
		return nil, err
	}
	ctx, stop := h.watchModel(ctx, agentID, runID, ownerToken)
	defer stop()
	resolved, err := h.runtime.ResolveModel(ctx, agentID.String(), req.Slug, req.Capability)
	if err != nil {
		h.logger.Error("resolve transcription model failed", zap.Error(err))
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", err.Error())
	}

	m := solprovider.CreateTranscriptionModel(resolved.ProviderID, resolved.ModelID, solprovider.Options{APIKey: resolved.ApiKey, BaseURL: resolved.BaseURL})
	if m == nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("provider %q does not support transcription", resolved.ProviderID))
	}

	var opts model.TranscribeCallOptions
	if err := json.Unmarshal(req.Options, &opts); err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "invalid options")
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

	capture := runtimesvc.LlmUsageCapture{ProviderCatalogID: resolved.ProviderID, ProviderSlug: resolved.ProviderSlug, Model: resolved.ModelID, Capability: "transcription", Slug: req.Slug, TaskOwnerToken: ownerToken, TaskUsageID: uuid.New()}
	started := time.Now()
	result, err := m.Transcribe(ctx, opts)
	capture.Latency = time.Since(started)
	if err != nil {
		h.logger.Error("transcription failed", zap.Error(err))
		capture.Errored = true
		h.runtime.RecordLLMUsage(agentID, runIDHdr, capture)
		return nil, fmt.Errorf("%s: %w", "transcription failed: "+err.Error(), ErrUpstream)
	}

	// STT bills per audio-second; no catalog rate, so seconds are tracked
	// but not priced (recorded with cost 0).
	capture.UnitKind = "second"
	if result.Usage != nil {
		capture.Units = result.Usage.DurationSeconds
	}
	if err := h.runtime.RecordLLMUsage(agentID, runIDHdr, capture); err != nil {
		return nil, err
	}

	return result, nil
}
