package agentapi

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
	"github.com/airlockrun/airlock/execproxy"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// scheduleReconciler is the subset of trigger.Scheduler the Sync handler needs:
// re-seed cron fire rows and orphan removed schedules after a sync.
type scheduleReconciler interface {
	ReconcileAgent(ctx context.Context, agentID uuid.UUID) error
}

type Handler struct {
	db                     *db.DB
	encryptor              secrets.Store
	oauthClient            *oauth.Client
	s3                     *storage.S3Client
	builder                *builder.BuildService
	pubsub                 *realtime.PubSub
	bridgeMgr              BridgePartsDeliverer // for output()/topic bridge delivery
	scheduler              scheduleReconciler   // nil until trigger system is wired
	publicURL              string
	agentBaseURL           func(slug string) string // {scheme}://{slug}.{domain}[:port] — from config.Config (single source)
	llmProxyURL            string                   // optional: route LLM calls through this proxy
	forceInlineAttachments bool                     // dev escape hatch — ignore provider URL capability, send everything as base64
	jwtSecret              string                   // shared with auth middleware; read by mcp_server.go to validate incoming A2A JWTs
	dispatcher             *trigger.Dispatcher      // forward-prompt + ensure-running for A2A
	execDialer             ExecDialerService        // SSH dialer for RegisterExecEndpoint; nil-safe via implements-or-stub adapter
	logger                 *zap.Logger
}

// Config bundles the dependencies New requires. Mirrors the struct
// fields of Handler one-for-one; api/router.go's RouterConfig
// translates its own merged config into this on wire-up.
type Config struct {
	DB                     *db.DB
	Encryptor              secrets.Store
	OAuthClient            *oauth.Client
	S3                     *storage.S3Client
	Builder                *builder.BuildService
	PubSub                 *realtime.PubSub
	BridgeMgr              BridgePartsDeliverer
	Scheduler              scheduleReconciler
	PublicURL              string
	AgentBaseURL           func(slug string) string
	LLMProxyURL            string
	ForceInlineAttachments bool
	JWTSecret              string
	Dispatcher             *trigger.Dispatcher
	ExecDialer             ExecDialerService
	Logger                 *zap.Logger
}

// New constructs the agent-internal HTTP surface. Fail-loud on nil
// deps — every required field is mandatory (airlock fail-loud rule).
func New(c Config) *Handler {
	if c.DB == nil {
		panic("agentapi: db is required")
	}
	if c.PubSub == nil {
		panic("agentapi: pubsub is required")
	}
	if c.Dispatcher == nil {
		panic("agentapi: dispatcher is required")
	}
	if c.Logger == nil {
		panic("agentapi: logger is required")
	}
	return &Handler{
		db:                     c.DB,
		encryptor:              c.Encryptor,
		oauthClient:            c.OAuthClient,
		s3:                     c.S3,
		builder:                c.Builder,
		pubsub:                 c.PubSub,
		bridgeMgr:              c.BridgeMgr,
		scheduler:              c.Scheduler,
		publicURL:              c.PublicURL,
		agentBaseURL:           c.AgentBaseURL,
		llmProxyURL:            c.LLMProxyURL,
		forceInlineAttachments: c.ForceInlineAttachments,
		jwtSecret:              c.JWTSecret,
		dispatcher:             c.Dispatcher,
		execDialer:             c.ExecDialer,
		logger:                 c.Logger,
	}
}

// ExecDialerService is the subset of *execproxy.SSHDialer the agent
// exec handler needs. Defined here so tests can stub it without
// dragging in golang.org/x/crypto/ssh, and exported so router.go
// can wire the concrete dialer through Config.
type ExecDialerService interface {
	Exec(ctx context.Context, ep *dbq.AgentExecEndpoint, req execproxy.ExecRequest, w http.ResponseWriter) error
	EvictCache(id uuid.UUID)
}

// BridgePartsDeliverer is the subset of trigger.BridgeManager needed for message delivery.
type BridgePartsDeliverer interface {
	SendParts(ctx context.Context, bridgeID uuid.UUID, externalID string, parts []agentsdk.DisplayPart) error
}

// recordConnectionNeed upserts the agent's connection need, carrying the full
// declared template as spec so the resource can be instantiated from it on
// configure. It does not create or bind a resource — that happens when a user
// configures credentials.
func (h *Handler) recordConnectionNeed(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, slug string, def agentsdk.ConnectionDef, scopes string, authInjection, authParams, headers []byte) error {
	spec, err := json.Marshal(map[string]any{
		"name":               def.Name,
		"auth_mode":          string(def.AuthMode),
		"auth_url":           def.AuthURL,
		"token_url":          def.TokenURL,
		"base_url":           def.BaseURL,
		"scopes":             scopes,
		"auth_injection":     json.RawMessage(authInjection),
		"auth_params":        json.RawMessage(authParams),
		"headers":            json.RawMessage(headers),
		"llm_hint":           def.LLMHint,
		"access":             string(def.Access),
		"setup_instructions": def.SetupInstructions,
	})
	if err != nil {
		return err
	}
	return q.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID:           toPgUUID(agentID),
		Type:              "connection",
		Slug:              slug,
		Description:       def.Description,
		SetupInstructions: def.SetupInstructions,
		ExpectedUrl:       def.BaseURL,
		ExpectedScopes:    scopes,
		Spec:              spec,
	})
}

// CreateRun handles POST /api/agent/run/create.
// Called by agent containers to create a run record for programmatic runs (e.g. from route handlers).
func (h *Handler) CreateRun(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
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

	// Sync is authoritative for instructions — absent field resets to
	// empty so removing an AddInstruction call and resyncing wipes stale
	// fragments.
	extrasJSON := []byte("[]")
	if len(req.Instructions) > 0 {
		if b, err := json.Marshal(req.Instructions); err == nil {
			extrasJSON = b
		}
	}
	_ = q.UpdateAgentInstructions(ctx, dbq.UpdateAgentInstructionsParams{
		ID:           pgAgentID,
		Instructions: extrasJSON,
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

	// Upsert schedule handlers (crons + schedules), then delete stale.
	handlerSlugs := make([]string, len(req.ScheduleHandlers))
	for i, sh := range req.ScheduleHandlers {
		timeoutMs := sh.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = 120000
		}
		if err := q.UpsertScheduleHandler(ctx, dbq.UpsertScheduleHandlerParams{
			AgentID:     pgAgentID,
			Slug:        sh.Slug,
			Kind:        sh.Kind,
			Recurrence:  sh.Recurrence,
			TimeoutMs:   timeoutMs,
			Description: sh.Description,
		}); err != nil {
			h.logger.Error("upsert schedule handler failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync schedules")
			return
		}
		handlerSlugs[i] = sh.Slug
	}
	if err := q.DeleteScheduleHandlersByAgentExcept(ctx, dbq.DeleteScheduleHandlersByAgentExceptParams{
		AgentID: pgAgentID,
		Slugs:   handlerSlugs,
	}); err != nil {
		h.logger.Error("delete stale schedule handlers failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync schedules")
		return
	}

	// Reconcile fire rows: re-seed cron fires, orphan removed schedules.
	if h.scheduler != nil {
		if err := h.scheduler.ReconcileAgent(ctx, agentID); err != nil {
			h.logger.Error("reconcile scheduler failed", zap.Error(err))
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
			PerUser:     t.PerUser,
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
		// Record the agent's need (spec = declared template). The resource is
		// created (owned by the configuring user) when a user configures
		// credentials; a no-auth MCP server has no configure step, so it is
		// auto-created + bound here. A bound resource has its declaration
		// refreshed.
		mcpSpec, _ := json.Marshal(map[string]any{
			"name": mcp.Name, "url": mcp.URL, "auth_mode": string(mcp.AuthMode),
			"auth_url": mcp.AuthURL, "token_url": mcp.TokenURL, "scopes": scopes,
			"auth_injection": json.RawMessage(authInjection), "access": string(mcp.Access),
		})
		if err := q.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
			AgentID: pgAgentID, Type: "mcp_server", Slug: mcp.Slug,
			Description: mcp.Name, SetupInstructions: "", ExpectedUrl: mcp.URL,
			ExpectedScopes: scopes, Spec: mcpSpec,
		}); err != nil {
			h.logger.Error("record mcp need failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
			return
		}
		need, nerr := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pgAgentID, Type: "mcp_server", Slug: mcp.Slug})
		bound := nerr == nil && need.BoundMcpID.Valid
		if bound || mcp.AuthMode == agentsdk.MCPAuthNone || mcp.AuthMode == "" {
			srv, err := q.UpsertMCPServer(ctx, dbq.UpsertMCPServerParams{
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
			})
			if err != nil {
				h.logger.Error("upsert MCP server failed", zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
				return
			}
			if !bound {
				if err := q.BindMCPServerNeed(ctx, dbq.BindMCPServerNeedParams{AgentID: pgAgentID, Slug: mcp.Slug, ResourceID: srv.ID}); err != nil {
					h.logger.Error("bind mcp need failed", zap.Error(err))
					writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
					return
				}
			}
		}
		mcpSlugs[i] = mcp.Slug
	}
	// Drop needs for slugs the agent no longer declares. The backing MCP server
	// resource is owner-owned and shared, so it is not deleted here — it outlives
	// this agent's declaration and may back another agent's binding.
	if err := q.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "mcp_server", Slugs: mcpSlugs,
	}); err != nil {
		h.logger.Error("delete stale mcp needs failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync MCP servers")
		return
	}

	// Connections: record the agent's need. The resource is created (owned by
	// the configuring user) when a user first sets credentials — sync never
	// auto-creates it. If one is already bound, refresh its declaration fields
	// (UpsertConnection preserves the stored credentials).
	connSlugs := make([]string, len(req.Connections))
	for i, c := range req.Connections {
		authInjection, err := json.Marshal(c.AuthInjection)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid auth_injection for connection "+c.Slug)
			return
		}
		authParams := []byte("{}")
		if len(c.AuthParams) > 0 {
			if authParams, err = json.Marshal(c.AuthParams); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid auth_params for connection "+c.Slug)
				return
			}
		}
		headers := []byte("{}")
		if len(c.Headers) > 0 {
			if headers, err = json.Marshal(c.Headers); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid headers for connection "+c.Slug)
				return
			}
		}
		scopes := strings.Join(c.Scopes, ",")
		if err := h.recordConnectionNeed(ctx, q, agentID, c.Slug, c, scopes, authInjection, authParams, headers); err != nil {
			h.logger.Error("record connection need failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync connections")
			return
		}
		need, nerr := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pgAgentID, Type: "connection", Slug: c.Slug})
		bound := nerr == nil && need.BoundConnectionID.Valid
		// A bound resource gets its declaration refreshed; a no-auth connection
		// has no configure step (no credentials to own), so it is auto-created +
		// bound here. Credential-bearing connections wait for a user to
		// configure, which creates the resource owned by that user.
		if bound || c.AuthMode == agentsdk.ConnectionAuthNone {
			conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
				AgentID: pgAgentID, Slug: c.Slug, Name: c.Name, Description: c.Description, LlmHint: c.LLMHint,
				AuthMode: string(c.AuthMode), AuthUrl: c.AuthURL, TokenUrl: c.TokenURL, BaseUrl: c.BaseURL,
				Scopes: scopes, AuthInjection: authInjection, SetupInstructions: c.SetupInstructions,
				Config: []byte("{}"), AuthParams: authParams, Headers: headers, Access: string(c.Access),
			})
			if err != nil {
				h.logger.Error("upsert connection failed", zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to sync connections")
				return
			}
			if !bound {
				if err := q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: pgAgentID, Slug: c.Slug, ResourceID: conn.ID}); err != nil {
					h.logger.Error("bind no-auth connection failed", zap.Error(err))
					writeJSONError(w, http.StatusInternalServerError, "failed to sync connections")
					return
				}
			}
		}
		connSlugs[i] = c.Slug
	}
	if err := q.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "connection", Slugs: connSlugs,
	}); err != nil {
		h.logger.Error("delete stale connection needs failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync connections")
		return
	}

	// Exec endpoints: record the agent's need. The resource is created (owned
	// by the configuring user) on first operator configure — sync never
	// auto-creates it. If one is already bound, refresh its declaration fields
	// (preserving the operator-configured columns).
	execSlugs := make([]string, len(req.ExecEndpoints))
	for i, e := range req.ExecEndpoints {
		access := string(e.Access)
		if access == "" {
			access = string(agentsdk.AccessAdmin)
		}
		execSpec, _ := json.Marshal(map[string]any{"llm_hint": e.LLMHint, "access": access})
		if err := q.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
			AgentID: pgAgentID, Type: "exec_endpoint", Slug: e.Slug, Description: e.Description,
			SetupInstructions: "", ExpectedUrl: "", ExpectedScopes: "", Spec: execSpec,
		}); err != nil {
			h.logger.Error("record exec need failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to sync exec endpoints")
			return
		}
		need, nerr := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pgAgentID, Type: "exec_endpoint", Slug: e.Slug})
		if nerr == nil && need.BoundExecID.Valid {
			if _, err := q.UpsertExecEndpointDeclaration(ctx, dbq.UpsertExecEndpointDeclarationParams{
				AgentID: pgAgentID, Slug: e.Slug, Description: e.Description, LlmHint: e.LLMHint, Access: access,
			}); err != nil {
				h.logger.Error("refresh exec declaration failed", zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to sync exec endpoints")
				return
			}
		}
		execSlugs[i] = e.Slug
	}
	if err := q.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "exec_endpoint", Slugs: execSlugs,
	}); err != nil {
		h.logger.Error("delete stale exec needs failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to sync exec endpoints")
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
	mcpServers, _ := q.ListBoundMCPServersByAgent(ctx, pgAgentID)
	mcpStatuses := h.discoverAllMCPStatus(ctx, q, agentID, mcpServers)
	mcpServers, _ = q.ListBoundMCPServersByAgent(ctx, pgAgentID)

	// Index the (possibly-refreshed) server rows by the agent's need slug so we
	// can decode tool_schemas once and reuse for both the prompt template and the
	// SyncResponse payload.
	serverBySlug := make(map[string]dbq.ListBoundMCPServersByAgentRow, len(mcpServers))
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
	routeURL := h.agentBaseURL(agentRecord.Slug)

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
	publicStorageBase := routeURL + "/__air/storage"

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
			AgentRouteURL:       routeURL,
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
func (h *Handler) resolveAgentCapabilities(ctx context.Context, q *dbq.Queries, ag dbq.Agent) (agentsdk.Capabilities, []string, error) {
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
func (h *Handler) buildSiblingInfos(ctx context.Context, q *dbq.Queries, parentAgentID pgtype.UUID) ([]agentsdk.SiblingInfo, error) {
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
