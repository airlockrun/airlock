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
	promptpkg "github.com/airlockrun/airlock/prompt"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// cronReloader is the subset of trigger.Scheduler needed by the Sync handler.
type cronReloader interface {
	ReloadAgent(ctx context.Context, agentID uuid.UUID) error
}

type agentHandler struct {
	db        *db.DB
	encryptor *crypto.Encryptor
	s3        *storage.S3Client
	builder   *builder.BuildService
	pubsub      *realtime.PubSub
	bridgeMgr   bridgePartsDeliverer // for printToUser/topic bridge delivery
	scheduler   cronReloader         // nil until trigger system is wired
	publicURL              string
	agentDomain            string // e.g. "dev.airlock.run" → {slug}.dev.airlock.run
	llmProxyURL            string // optional: route LLM calls through this proxy
	forceInlineAttachments bool   // dev escape hatch — ignore provider URL capability, send everything as base64
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

	var def agentsdk.Connection
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
			Access:       t.Access,
			InputSchema:  inSchema,
			OutputSchema: outSchema,
		})
	}
	_ = q.DeleteStaleAgentTools(ctx, dbq.DeleteStaleAgentToolsParams{
		AgentID: pgAgentID,
		Names:   toolNames,
	})

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
			Access:      rt.Access,
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
			Access:      t.Access,
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
		if _, err := q.UpsertMCPServer(ctx, dbq.UpsertMCPServerParams{
			AgentID:  pgAgentID,
			Slug:     mcp.Slug,
			Name:     mcp.Name,
			Url:      mcp.URL,
			AuthMode: mcp.AuthMode,
			AuthUrl:  mcp.AuthURL,
			TokenUrl: mcp.TokenURL,
			Scopes:   scopes,
			Access:   mcp.Access,
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

	// Build MCP server status for prompt and auth status for response.
	var promptMCPServers []promptpkg.MCPServerStatus
	var mcpAuthStatus []agentsdk.MCPAuthStatus
	mcpSchemas := make(map[string][]agentsdk.MCPToolSchema)
	for _, s := range mcpStatuses {
		mcpAuthStatus = append(mcpAuthStatus, s.MCPAuthStatus)
		status := "requires authentication"
		if s.Authorized {
			status = fmt.Sprintf("connected, %d tools", s.ToolCount)
		}

		// Decode cached tool_schemas → ToolInfo for the prompt template
		// AND MCPToolSchema for the SyncResponse. Both consumers need the
		// same data; decoding once keeps it consistent.
		var promptTools []promptpkg.ToolInfo
		var schemas []agentsdk.MCPToolSchema
		if srv, ok := serverBySlug[s.Slug]; ok && len(srv.ToolSchemas) > 0 {
			var stored []mcpToolInfo
			if err := json.Unmarshal(srv.ToolSchemas, &stored); err == nil {
				promptTools = make([]promptpkg.ToolInfo, len(stored))
				schemas = make([]agentsdk.MCPToolSchema, len(stored))
				for i, t := range stored {
					promptTools[i] = promptpkg.ToolInfo{
						Name:        t.Name,
						Description: t.Description,
						InputSchema: t.InputSchema,
					}
					schemas[i] = agentsdk.MCPToolSchema{
						ServerSlug:  s.Slug,
						Name:        t.Name,
						Description: t.Description,
						InputSchema: t.InputSchema,
					}
				}
			} else {
				h.logger.Warn("decode tool_schemas failed", zap.String("slug", s.Slug), zap.Error(err))
			}
		}
		if len(schemas) > 0 {
			mcpSchemas[s.Slug] = schemas
		}

		name := s.Slug
		if srv, ok := serverBySlug[s.Slug]; ok && srv.Name != "" {
			name = srv.Name
		}
		promptMCPServers = append(promptMCPServers, promptpkg.MCPServerStatus{
			Slug:   s.Slug,
			Name:   name,
			Status: status,
			Tools:  promptTools,
		})
	}

	// Render system prompt from template.
	conns, _ := q.ListConnectionsByAgent(ctx, pgAgentID)
	promptConns := make([]promptpkg.ConnInfo, len(conns))
	for i, c := range conns {
		promptConns[i] = promptpkg.ConnInfo{
			Slug:        c.Slug,
			Name:        c.Name,
			Description: c.Description,
			BaseURL:     c.BaseUrl,
		}
	}
	promptTools := make([]promptpkg.ToolInfo, len(req.Tools))
	for i, t := range req.Tools {
		promptTools[i] = promptpkg.ToolInfo{
			Name:         t.Name,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			OutputSchema: t.OutputSchema,
		}
	}
	promptTopics := make([]promptpkg.TopicInfo, len(req.Topics))
	for i, t := range req.Topics {
		promptTopics[i] = promptpkg.TopicInfo{Slug: t.Slug, Description: t.Description}
	}
	promptWebhooks := make([]promptpkg.WebhookInfo, len(req.Webhooks))
	for i, wh := range req.Webhooks {
		promptWebhooks[i] = promptpkg.WebhookInfo{Path: wh.Path, Description: wh.Description}
	}
	promptCrons := make([]promptpkg.CronInfo, len(req.Crons))
	for i, c := range req.Crons {
		promptCrons[i] = promptpkg.CronInfo{Name: c.Name, Schedule: c.Schedule, Description: c.Description}
	}
	promptRoutes := make([]promptpkg.RouteInfo, len(req.Routes))
	for i, rt := range req.Routes {
		promptRoutes[i] = promptpkg.RouteInfo{Method: rt.Method, Path: rt.Path, Access: rt.Access, Description: rt.Description}
	}

	// Build agent route URL if agent domain is configured.
	var agentRouteURL string
	if h.agentDomain != "" {
		if agentRecord, err := q.GetAgentByID(ctx, pgAgentID); err == nil {
			agentRouteURL = "https://" + agentRecord.Slug + "." + h.agentDomain
		}
	}

	rendered, err := promptpkg.RenderAgentPrompt(promptpkg.AgentData{
		AgentDashboardURL: h.publicURL + "/agents/" + agentID.String(),
		AgentRouteURL:     agentRouteURL,
		Tools:             promptTools,
		Connections:       promptConns,
		Topics:            promptTopics,
		Webhooks:          promptWebhooks,
		Crons:             promptCrons,
		Routes:            promptRoutes,
		MCPServers:        promptMCPServers,
	})
	if err != nil {
		h.logger.Error("render agent prompt failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to render prompt")
		return
	}

	writeJSON(w, http.StatusOK, agentsdk.SyncResponse{
		SystemPrompt:  rendered,
		MCPAuthStatus: mcpAuthStatus,
		MCPSchemas:    mcpSchemas,
	})
}
