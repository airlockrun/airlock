package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/compat"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// cronReloader is the subset of trigger.Scheduler needed by the Sync handler.
type cronReloader interface {
	ReloadAgent(ctx context.Context, agentID uuid.UUID) error
}

type agentHandler struct {
	db                     *db.DB
	encryptor              secrets.Store
	s3                     *storage.S3Client
	builder                *builder.BuildService
	pubsub                 *realtime.PubSub
	bridgeMgr              bridgePartsDeliverer // for printToUser/topic bridge delivery
	scheduler              cronReloader         // nil until trigger system is wired
	publicURL              string
	agentDomain            string              // e.g. "dev.airlock.run" → {slug}.dev.airlock.run
	agentRouteScheme       string              // "http" or "https" — copied from PUBLIC_URL so dev/local overlays can drop https
	agentRoutePort         string              // empty for the standard 80/443; set when Caddy is fronted on a non-default port so signed /__air/storage URLs include it
	llmProxyURL            string              // optional: route LLM calls through this proxy
	forceInlineAttachments bool                // dev escape hatch — ignore provider URL capability, send everything as base64
	jwtSecret              string              // shared with auth middleware; read by mcp_server.go to validate incoming A2A JWTs
	dispatcher             *trigger.Dispatcher // forward-prompt + ensure-running for A2A
	logger                 *zap.Logger
}

// bridgePartsDeliverer is the subset of trigger.BridgeManager needed for message delivery.
type bridgePartsDeliverer interface {
	SendParts(ctx context.Context, bridgeID uuid.UUID, externalID string, parts []agentsdk.DisplayPart) error
}

// UpsertConnection handles PUT /api/agent/connections/{slug}.
func (h *agentHandler) UpsertConnection(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var def agentsdk.ConnectionDef
	if err := readJSON(r, &def); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	authInjection, err := json.Marshal(def.AuthInjection)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid auth_injection")
		return
	}

	q := dbq.New(h.db.Pool())
	_, err = q.UpsertConnection(r.Context(), dbq.UpsertConnectionParams{
		AgentID:           toPgUUID(agentID),
		Slug:              slug,
		Name:              def.Name,
		Description:       def.Description,
		LlmHint:           def.LLMHint,
		AuthMode:          string(def.AuthMode),
		AuthUrl:           def.AuthURL,
		TokenUrl:          def.TokenURL,
		BaseUrl:           def.BaseURL,
		Scopes:            strings.Join(def.Scopes, ","),
		AuthInjection:     authInjection,
		SetupInstructions: def.SetupInstructions,
		Config:            []byte("{}"),
		Access:            string(def.Access),
	})
	if err != nil {
		h.logger.Error("upsert connection failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to upsert connection")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CreateRun handles POST /api/agent/run/create.
// Called by agent containers to create a run record for programmatic runs (e.g. from route handlers).
func (h *agentHandler) CreateRun(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())

	var req agentsdk.CreateRunRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TriggerType == "" {
		req.TriggerType = "code"
	}

	q := dbq.New(h.db.Pool())

	var sourceRef string
	if agent, err := q.GetAgentByID(r.Context(), toPgUUID(agentID)); err == nil {
		sourceRef = agent.SourceRef
	}

	run, err := q.CreateRun(r.Context(), dbq.CreateRunParams{
		AgentID:      toPgUUID(agentID),
		InputPayload: []byte("{}"),
		SourceRef:    sourceRef,
		TriggerType:  req.TriggerType,
		TriggerRef:   req.TriggerRef,
	})
	if err != nil {
		h.logger.Error("create run failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to create run")
		return
	}

	writeJSON(w, http.StatusOK, agentsdk.CreateRunResponse{
		RunID: pgUUID(run.ID).String(),
	})
}

// Sync handles PUT /api/agent/sync.
func (h *agentHandler) Sync(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	pgAgentID := toPgUUID(agentID)

	var req agentsdk.SyncRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	ctx := r.Context()

	// Validate the reported agentsdk version against what this airlock
	// process was built against. A mismatch means the container image is
	// stale relative to this airlock — reject the sync so the container
	// exits and surface a persistent error the operator sees in the UI.
	if req.Version != "" {
		if err := compat.CheckSDKVersion(req.Version); err != nil {
			_ = q.UpdateAgentErrorMessage(ctx, dbq.UpdateAgentErrorMessageParams{
				ID:           pgAgentID,
				ErrorMessage: err.Error(),
			})
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		_ = q.UpdateAgentSDKVersion(ctx, dbq.UpdateAgentSDKVersionParams{
			ID:         pgAgentID,
			SdkVersion: req.Version,
		})
		// Clear any stale compatibility error now that the sync succeeded.
		_ = q.UpdateAgentErrorMessage(ctx, dbq.UpdateAgentErrorMessageParams{
			ID:           pgAgentID,
			ErrorMessage: "",
		})
	}
	if req.Description != "" {
		_ = q.UpdateAgentDescription(ctx, dbq.UpdateAgentDescriptionParams{
			ID:          pgAgentID,
			Description: req.Description,
		})
	}
	// Emoji is cosmetic: persist a sane value, otherwise drop it (never
	// fail the whole sync over decoration). cleanAgentEmoji bounds
	// length and strips control chars without enforcing a single rune
	// (ZWJ / skin-tone / flag emoji are multi-codepoint).
	if e, ok := cleanAgentEmoji(req.Emoji); ok {
		_ = q.UpdateAgentEmoji(ctx, dbq.UpdateAgentEmojiParams{
			ID:    pgAgentID,
			Emoji: e,
		})
	}

	// Sync is authoritative for extra_prompts — absent field resets to
	// empty so removing an AddExtraPrompt call and resyncing wipes stale
	// fragments.
	extrasJSON := []byte("[]")
	if len(req.ExtraPrompts) > 0 {
		if b, err := json.Marshal(req.ExtraPrompts); err == nil {
			extrasJSON = b
		}
	}
	_ = q.UpdateAgentExtraPrompts(ctx, dbq.UpdateAgentExtraPromptsParams{
		ID:           pgAgentID,
		ExtraPrompts: extrasJSON,
	})

	// Upsert tools, then delete stale.
	toolNames := make([]string, len(req.Tools))
	for i, t := range req.Tools {
		toolNames[i] = t.Name
		inSchema := []byte(t.InputSchema)
		if len(inSchema) == 0 {
			inSchema = []byte("{}")
		}
		outSchema := []byte(t.OutputSchema)
		if len(outSchema) == 0 {
			outSchema = []byte("{}")
		}
		_ = q.UpsertAgentTool(ctx, dbq.UpsertAgentToolParams{
			AgentID:      pgAgentID,
			Name:         t.Name,
			Description:  t.Description,
			LlmHint:      t.LLMHint,
			Access:       string(t.Access),
			InputSchema:  inSchema,
			OutputSchema: outSchema,
		})
	}
	_ = q.DeleteStaleAgentTools(ctx, dbq.DeleteStaleAgentToolsParams{
		AgentID: pgAgentID,
		Names:   toolNames,
	})

	// Tool-set change detection: hash the current set, compare to the
	// stored hash, and trigger a sibling-update broadcast on mismatch.
	// Avoids fan-out churn when an agent re-syncs unchanged state on
	// container restart (the common case).
	currentTools, terr := q.ListAgentTools(ctx, pgAgentID)
	if terr == nil {
		newHash := computeToolsHash(currentTools)
		// Lazy fetch agent to compare prior hash. Cheap — single PK lookup.
		if prior, perr := q.GetAgentByID(ctx, pgAgentID); perr == nil {
			if !bytesEqual(prior.ToolsHash, newHash) {
				_ = q.UpdateAgentToolsHash(ctx, dbq.UpdateAgentToolsHashParams{
					ID:        pgAgentID,
					ToolsHash: newHash,
				})
				go broadcastSiblingChange(context.Background(), dbq.New(h.db.Pool()), h.dispatcher, h.logger, agentID)
			}
		}
	}

	// Upsert model slots, then delete stale. Upsert preserves the admin's
	// assigned_model across syncs — only the declaration fields update.
	slotSlugs := make([]string, len(req.ModelSlots))
	for i, s := range req.ModelSlots {
		slotSlugs[i] = s.Slug
		_ = q.UpsertAgentModelSlot(ctx, dbq.UpsertAgentModelSlotParams{
			AgentID:     pgAgentID,
			Slug:        s.Slug,
			Capability:  s.Capability,
			Description: s.Description,
		})
	}
	_ = q.DeleteStaleAgentModelSlots(ctx, dbq.DeleteStaleAgentModelSlotsParams{
		AgentID: pgAgentID,
		Slugs:   slotSlugs,
	})

	// Upsert webhooks, then delete stale.
	paths := make([]string, len(req.Webhooks))
	for i, wh := range req.Webhooks {
		timeoutMs := int32(wh.TimeoutMs)
		if timeoutMs == 0 {
			timeoutMs = 120000
		}
		if err := q.UpsertWebhook(ctx, dbq.UpsertWebhookParams{
			AgentID:      pgAgentID,
			Path:         wh.Path,
			VerifyMode:   wh.Verify,
			VerifyHeader: wh.Header,
			TimeoutMs:    timeoutMs,
			Description:  wh.Description,
		}); err != nil {
			h.logger.Error("upsert webhook failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync webhooks")
			return
		}
		paths[i] = wh.Path
	}
	if err := q.DeleteWebhooksByAgentExcept(ctx, dbq.DeleteWebhooksByAgentExceptParams{
		AgentID: pgAgentID,
		Paths:   paths,
	}); err != nil {
		h.logger.Error("delete stale webhooks failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync webhooks")
		return
	}

	// Upsert crons, then delete stale.
	cronNames := make([]string, len(req.Crons))
	for i, cron := range req.Crons {
		cronTimeoutMs := int32(cron.TimeoutMs)
		if cronTimeoutMs == 0 {
			cronTimeoutMs = 120000
		}
		if err := q.UpsertCron(ctx, dbq.UpsertCronParams{
			AgentID:     pgAgentID,
			Name:        cron.Name,
			Schedule:    cron.Schedule,
			TimeoutMs:   cronTimeoutMs,
			Description: cron.Description,
		}); err != nil {
			h.logger.Error("upsert cron failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync crons")
			return
		}
		cronNames[i] = cron.Name
	}
	if err := q.DeleteCronsByAgentExcept(ctx, dbq.DeleteCronsByAgentExceptParams{
		AgentID: pgAgentID,
		Names:   cronNames,
	}); err != nil {
		h.logger.Error("delete stale crons failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync crons")
		return
	}

	// Reload cron scheduler for this agent.
	if h.scheduler != nil {
		if err := h.scheduler.ReloadAgent(ctx, agentID); err != nil {
			h.logger.Error("reload scheduler failed", zap.Error(err))
		}
	}

	// Upsert routes, then delete stale.
	routeKeys := make([]string, len(req.Routes))
	for i, rt := range req.Routes {
		if err := q.UpsertRoute(ctx, dbq.UpsertRouteParams{
			AgentID:     pgAgentID,
			Path:        rt.Path,
			Method:      rt.Method,
			Access:      string(rt.Access),
			Description: rt.Description,
		}); err != nil {
			h.logger.Error("upsert route failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync routes")
			return
		}
		routeKeys[i] = rt.Path + "|" + rt.Method
	}
	if err := q.DeleteRoutesByAgentExcept(ctx, dbq.DeleteRoutesByAgentExceptParams{
		AgentID: pgAgentID,
		Keys:    routeKeys,
	}); err != nil {
		h.logger.Error("delete stale routes failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync routes")
		return
	}

	// Upsert topics, then delete stale.
	topicSlugs := make([]string, len(req.Topics))
	for i, t := range req.Topics {
		if err := q.UpsertTopic(ctx, dbq.UpsertTopicParams{
			AgentID:     pgAgentID,
			Slug:        t.Slug,
			Description: t.Description,
			LlmHint:     t.LLMHint,
			Access:      string(t.Access),
		}); err != nil {
			h.logger.Error("upsert topic failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync topics")
			return
		}
		topicSlugs[i] = t.Slug
	}
	if err := q.DeleteTopicsByAgentExcept(ctx, dbq.DeleteTopicsByAgentExceptParams{
		AgentID: pgAgentID,
		Slugs:   topicSlugs,
	}); err != nil {
		h.logger.Error("delete stale topics failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync topics")
		return
	}

	// Upsert MCP servers, then delete stale.
	mcpSlugs := make([]string, len(req.MCPServers))
	for i, mcp := range req.MCPServers {
		scopes := ""
		if len(mcp.Scopes) > 0 {
			b, _ := json.Marshal(mcp.Scopes)
			scopes = string(b)
		}
		authInjection, err := json.Marshal(mcp.AuthInjection)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid auth_injection for MCP "+mcp.Slug)
			return
		}
		if _, err := q.UpsertMCPServer(ctx, dbq.UpsertMCPServerParams{
			AgentID:       pgAgentID,
			Slug:          mcp.Slug,
			Name:          mcp.Name,
			Url:           mcp.URL,
			AuthMode:      string(mcp.AuthMode),
			AuthUrl:       mcp.AuthURL,
			TokenUrl:      mcp.TokenURL,
			Scopes:        scopes,
			Access:        string(mcp.Access),
			AuthInjection: authInjection,
		}); err != nil {
			h.logger.Error("upsert MCP server failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
			return
		}
		mcpSlugs[i] = mcp.Slug
	}
	if err := q.DeleteMCPServersByAgentExcept(ctx, dbq.DeleteMCPServersByAgentExceptParams{
		AgentID: pgAgentID,
		Slugs:   mcpSlugs,
	}); err != nil {
		h.logger.Error("delete stale MCP servers failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
		return
	}

	// Upsert directories, then delete stale.
	dirPaths := make([]string, len(req.Directories))
	for i, d := range req.Directories {
		if err := q.UpsertDirectory(ctx, dbq.UpsertDirectoryParams{
			AgentID:        pgAgentID,
			Path:           d.Path,
			ReadAccess:     string(d.Read),
			WriteAccess:    string(d.Write),
			ListAccess:     string(d.List),
			Description:    d.Description,
			LlmHint:        d.LLMHint,
			RetentionHours: int32(d.RetentionHours),
			Scope:          string(d.Scope),
		}); err != nil {
			h.logger.Error("upsert directory failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync directories")
			return
		}
		dirPaths[i] = d.Path
	}
	if err := q.DeleteDirectoriesByAgentExcept(ctx, dbq.DeleteDirectoriesByAgentExceptParams{
		AgentID: pgAgentID,
		Paths:   dirPaths,
	}); err != nil {
		h.logger.Error("delete stale directories failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync directories")
		return
	}

	// Discover MCP status for servers with credentials. discoverAllMCPStatus
	// updates the tool_schemas JSONB column on success, so re-fetch the rows
	// afterwards to read the freshly-cached schemas into the prompt + response.
	mcpServers, _ := q.ListMCPServersByAgent(ctx, pgAgentID)
	mcpStatuses := h.discoverAllMCPStatus(ctx, q, agentID, mcpServers)
	mcpServers, _ = q.ListMCPServersByAgent(ctx, pgAgentID)

	// Index the (possibly-refreshed) server rows by slug so we can decode
	// tool_schemas once and reuse for both the prompt template and the
	// SyncResponse payload.
	serverBySlug := make(map[string]dbq.AgentMcpServer, len(mcpServers))
	for _, srv := range mcpServers {
		serverBySlug[srv.Slug] = srv
	}

	// Decode discovered MCP tool schemas + per-server auth status for the
	// SyncResponse. Prompt rendering moved into agentsdk so we no longer
	// build a parallel promptpkg.MCPServerStatus list here — the agent
	// composes its own MCP status lines from MCPAuthStatus + MCPSchemas.
	_ = serverBySlug // retained for readability of the loop below
	var mcpAuthStatus []agentsdk.MCPAuthStatus
	mcpSchemas := make(map[string][]agentsdk.MCPToolSchema)
	for _, s := range mcpStatuses {
		mcpAuthStatus = append(mcpAuthStatus, s.MCPAuthStatus)
		if srv, ok := serverBySlug[s.Slug]; ok && len(srv.ToolSchemas) > 0 {
			var stored []mcpToolInfo
			if err := json.Unmarshal(srv.ToolSchemas, &stored); err == nil {
				schemas := make([]agentsdk.MCPToolSchema, len(stored))
				for i, t := range stored {
					schemas[i] = agentsdk.MCPToolSchema{
						ServerSlug:  s.Slug,
						Name:        t.Name,
						Description: t.Description,
						InputSchema: t.InputSchema,
					}
				}
				if len(schemas) > 0 {
					mcpSchemas[s.Slug] = schemas
				}
			} else {
				h.logger.Warn("decode tool_schemas failed", zap.String("slug", s.Slug), zap.Error(err))
			}
		}
	}

	// Build agent route URL. h.agentDomain is required at startup
	// (config.resolveAgentDomain panics if neither AGENT_DOMAIN nor
	// PUBLIC_URL is set), and SubdomainProxy panics on empty too — so
	// it's always populated by the time this handler runs.
	agentRecord, err := q.GetAgentByID(ctx, pgAgentID)
	if err != nil {
		h.logger.Error("load agent for prompt data", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load agent")
		return
	}
	agentRouteURL := h.agentRouteScheme + "://" + agentRecord.Slug + "." + h.agentDomain
	if h.agentRoutePort != "" {
		agentRouteURL += ":" + h.agentRoutePort
	}

	// Sibling address book: pre-rendered Tools list per sibling so the
	// agent can install agent_<slug> bindings + render the prompt
	// without per-turn lookups. Visibility-by-user is layered on at
	// dispatch (PromptInput.VisibleSiblings); the SiblingInfo list
	// itself is unfiltered.
	siblings, err := h.buildSiblingInfos(ctx, q, pgAgentID)
	if err != nil {
		h.logger.Error("load sibling info", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load siblings")
		return
	}

	// Public storage base — the prefix StorageHandle.URL joins with '/'
	// and the storage path (e.g. "reports/q1.csv") to form a URL.
	publicStorageBase := agentRouteURL + "/__air/storage"

	// Notify subscribed clients (agent detail tabs) that the agent's
	// declared surface — tools, webhooks, crons, routes, MCP servers,
	// connections, model slots — was just refreshed. Tabs subscribed to
	// "agent.synced" can refetch instead of waiting for the user to hit
	// reload after a build/upgrade completes.
	if h.pubsub != nil {
		uuidAgentID := uuid.UUID(pgAgentID.Bytes)
		_ = h.pubsub.Publish(ctx, uuidAgentID, realtime.NewEnvelope("agent.synced", uuidAgentID.String(), &airlockv1.AgentSyncedEvent{
			AgentId: uuidAgentID.String(),
		}))
	}

	// Resolve the agent's effective model slots (agent override →
	// system default) so the prompt template can branch on which
	// builtins are actually available at runtime.
	caps, modalities, err := h.resolveAgentCapabilities(ctx, q, agentRecord)
	if err != nil {
		h.logger.Warn("resolve agent capabilities", zap.Error(err))
		// Non-fatal — fall through with zero-value caps (everything
		// false). The template will emit a minimal prompt.
	}

	writeJSON(w, http.StatusOK, agentsdk.SyncResponse{
		PromptData: agentsdk.PromptData{
			AgentDashboardURL:   h.publicURL + "/agents/" + agentID.String(),
			AgentRouteURL:       agentRouteURL,
			Siblings:            siblings,
			Capabilities:        caps,
			SupportedModalities: modalities,
		},
		MCPAuthStatus:     mcpAuthStatus,
		MCPSchemas:        mcpSchemas,
		PublicStorageBase: publicStorageBase,
	})
}

// resolveAgentCapabilities walks the agent's six optional model
// slots (vision/stt/tts/image_gen/embedding/search) plus the
// system-settings defaults and emits a Capabilities matrix + the
// chat model's input modality list. Each slot is "bound" iff
// (agent has provider+model) OR (system default has provider+model).
//
// Errors from GetSystemSettings are returned for logging; the
// returned Capabilities is still meaningful (slots that ONLY rely
// on agent overrides will resolve correctly).
func (h *agentHandler) resolveAgentCapabilities(ctx context.Context, q *dbq.Queries, ag dbq.Agent) (agentsdk.Capabilities, []string, error) {
	settings, sErr := q.GetSystemSettings(ctx)
	hasDefault := sErr == nil

	bound := func(agentPID pgtype.UUID, agentModel string, defaultPID pgtype.UUID, defaultModel string) bool {
		if agentPID.Valid && agentModel != "" {
			return true
		}
		if hasDefault && defaultPID.Valid && defaultModel != "" {
			return true
		}
		return false
	}

	caps := agentsdk.Capabilities{
		Vision:        bound(ag.VisionProviderID, ag.VisionModel, settings.DefaultVisionProviderID, settings.DefaultVisionModel),
		Transcription: bound(ag.SttProviderID, ag.SttModel, settings.DefaultSttProviderID, settings.DefaultSttModel),
		Speech:        bound(ag.TtsProviderID, ag.TtsModel, settings.DefaultTtsProviderID, settings.DefaultTtsModel),
		Embedding:     bound(ag.EmbeddingProviderID, ag.EmbeddingModel, settings.DefaultEmbeddingProviderID, settings.DefaultEmbeddingModel),
		Image:         bound(ag.ImageGenProviderID, ag.ImageGenModel, settings.DefaultImageGenProviderID, settings.DefaultImageGenModel),
		Search:        bound(ag.SearchProviderID, ag.SearchModel, settings.DefaultSearchProviderID, settings.DefaultSearchModel),
	}

	// Chat-model modalities: same agent → default fallback for the
	// exec slot, then look up the model in the models.dev catalog.
	execModel := ag.ExecModel
	var execProvider pgtype.UUID = ag.ExecProviderID
	if execModel == "" || !execProvider.Valid {
		if hasDefault {
			execModel = settings.DefaultExecModel
			execProvider = settings.DefaultExecProviderID
		}
	}
	var modalities []string
	if execModel != "" && execProvider.Valid {
		if prov, err := q.GetProviderByID(ctx, execProvider); err == nil {
			if m := solprovider.GetModalities(prov.CatalogID, execModel); m != nil {
				modalities = m.Input
			}
		}
	}

	if sErr != nil {
		return caps, modalities, sErr
	}
	return caps, modalities, nil
}

// buildSiblingInfos hydrates the parent agent's sibling address book
// into the wire shape: id + slug + name + description + tool
// schemas. Tool schemas come from the sibling's agent_tools rows
// (synced from the sibling agentsdk's own RegisterTool calls). The
// built-in `prompt` meta-tool is added by the agent-side renderer
// (it's the same shape for every sibling, no per-row data).
func (h *agentHandler) buildSiblingInfos(ctx context.Context, q *dbq.Queries, parentAgentID pgtype.UUID) ([]agentsdk.SiblingInfo, error) {
	rows, err := q.ListSiblings(ctx, parentAgentID)
	if err != nil {
		return nil, fmt.Errorf("list siblings: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make([]agentsdk.SiblingInfo, 0, len(rows))
	for _, r := range rows {
		toolRows, err := q.ListAgentTools(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("list tools for sibling %s: %w", r.Slug, err)
		}
		tools := make([]agentsdk.MCPToolSchema, len(toolRows))
		for i, t := range toolRows {
			tools[i] = agentsdk.MCPToolSchema{
				ServerSlug:  r.Slug,
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			}
		}
		out = append(out, agentsdk.SiblingInfo{
			ID:          uuid.UUID(r.ID.Bytes),
			Slug:        r.Slug,
			Name:        r.Name,
			Description: r.Description,
			Tools:       tools,
		})
	}
	return out, nil
}

// cleanAgentEmoji bounds and sanitizes a synced agent emoji. It is
// deliberately NOT "one rune" — valid emoji are routinely multi-codepoint
// (ZWJ sequences like 👨‍💻, skin-tone modifiers, two-regional-indicator
// flags). It only trims, caps the byte length, and rejects control
// characters / newlines. Returns ok=false for empty or rejected input so
// the caller skips the update rather than failing the sync over cosmetics.
func cleanAgentEmoji(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 16 {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return s, true
}
