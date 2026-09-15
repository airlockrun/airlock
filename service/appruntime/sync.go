package appruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/airlockrun/airlock/apperr"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/compat"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/storage"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func (h *Service) recordConnectionNeed(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, slug string, def wire.ConnectionDef, scopes string, authInjection, authParams, headers []byte) error {
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

func normalizeToolInputSchema(raw []byte, tool string, agentID uuid.UUID, lg *zap.Logger) []byte {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		if t, _ := m["type"].(string); t == "object" {
			return raw
		}
	}
	if s := strings.TrimSpace(string(raw)); s != "" && s != "{}" {
		lg.Warn("agent tool has a non-object input schema; coercing to object for MCP/tool compatibility",
			zap.String("agent_id", agentID.String()),
			zap.String("tool", tool),
			zap.ByteString("input_schema", raw),
			zap.String("hint", "rebuild the agent against an agentsdk that emits object-typed tool inputs"))
	}
	return []byte(`{"type":"object","properties":{}}`)
}

func validDirectoryAccess(access wire.Access) bool {
	return access == wire.Access(agentsdk.AccessPublic) || access == wire.Access(agentsdk.AccessUser) || access == wire.Access(agentsdk.AccessAdmin)
}

func validDirectoryScope(scope wire.DirectoryScope) bool {
	return scope == "" || scope == "user" || scope == "conv" || scope == "run"
}

// resolveAgentCapabilities walks the agent's six optional model
// slots (vision/stt/tts/image_gen/embedding/search) plus the
// system-settings defaults and emits a Capabilities matrix + the
// chat model's input modality list. Each slot is "bound" iff
// (agent has provider+model) OR (system default has provider+model).
func (h *Service) resolveAgentCapabilities(ctx context.Context, q *dbq.Queries, ag dbq.Agent) (wire.Capabilities, []string, error) {
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return wire.Capabilities{}, nil, sErr
	}

	bound := func(agentPID pgtype.UUID, agentModel string, defaultPID pgtype.UUID, defaultModel string) bool {
		if agentPID.Valid && agentModel != "" {
			return true
		}
		if defaultPID.Valid && defaultModel != "" {
			return true
		}
		return false
	}

	caps := wire.Capabilities{
		Vision:        bound(ag.VisionProviderID, ag.VisionModel, settings.DefaultVisionProviderID, settings.DefaultVisionModel),
		Transcription: bound(ag.SttProviderID, ag.SttModel, settings.DefaultSttProviderID, settings.DefaultSttModel),
		Speech:        bound(ag.TtsProviderID, ag.TtsModel, settings.DefaultTtsProviderID, settings.DefaultTtsModel),
		Embedding:     bound(ag.EmbeddingProviderID, ag.EmbeddingModel, settings.DefaultEmbeddingProviderID, settings.DefaultEmbeddingModel),
		Image:         bound(ag.ImageGenProviderID, ag.ImageGenModel, settings.DefaultImageGenProviderID, settings.DefaultImageGenModel),
		Search:        bound(ag.SearchProviderID, ag.SearchModel, settings.DefaultSearchProviderID, settings.DefaultSearchModel),
	}

	// Chat-model modalities: same agent → default fallback for the
	// exec slot, then look up the model in the active catalog.
	execModel := ag.ExecModel
	var execProvider pgtype.UUID = ag.ExecProviderID
	if execModel == "" || !execProvider.Valid {
		execModel = settings.DefaultExecModel
		execProvider = settings.DefaultExecProviderID
	}
	var modalities []string
	if execModel != "" && execProvider.Valid {
		prov, err := q.GetProviderByID(ctx, execProvider)
		if err != nil {
			return wire.Capabilities{}, nil, err
		}
		if m := solprovider.GetModalities(prov.CatalogID, execModel); m != nil {
			modalities = m.Input
		}
	}

	return caps, modalities, nil
}

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
func (h *Service) Sync(ctx context.Context, req wire.SyncRequest) (wire.SyncResponse, error) {
	agentID, admissionErr := h.admit(ctx, dbq.New(h.db.Pool()))
	if admissionErr != nil {
		return wire.SyncResponse{}, admissionErr
	}
	pgAgentID := toPgUUID(agentID)

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return wire.SyncResponse{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := h.admit(ctx, q); err != nil {
		return wire.SyncResponse{}, err
	}
	if err := wire.CheckAppRuntimeProtocol(req.RuntimeProtocol); err != nil {
		return wire.SyncResponse{}, apperr.Detail(apperr.ErrConflict, "%s", err.Error())
	}
	if _, err := capability.Catalog(req, capability.Discovery{}); err != nil {
		return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid capability catalogue: "+err.Error())
	}
	if err := wire.ValidateAgentDefinitions(req); err != nil {
		return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", err)
	}
	jobHandlers, err := preflightJobHandlers(ctx, q, agentID, req.JobHandlers)
	if err != nil {
		return wire.SyncResponse{}, jobManifestError(err)
	}
	req.JobHandlers = jobHandlers
	for _, directory := range req.Directories {
		canonical, pathErr := storage.CleanAgentPath(directory.Path)
		if pathErr != nil || canonical != directory.Path ||
			!validDirectoryAccess(directory.Read) || !validDirectoryAccess(directory.Write) || !validDirectoryAccess(directory.List) ||
			!validDirectoryScope(directory.Scope) || directory.RetentionHours < 0 {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid directory declaration: "+directory.Path)
		}
	}

	// Validate the reported agentsdk version against what this airlock
	// process was built against. A mismatch means the container image is
	// stale relative to this airlock — reject the sync so the container
	// exits and surface a persistent error the operator sees in the UI.
	if req.Version != "" {
		if err := compat.CheckSDKVersion(req.Version); err != nil {
			if updateErr := q.UpdateAgentErrorMessage(ctx, dbq.UpdateAgentErrorMessageParams{
				ID:           pgAgentID,
				ErrorMessage: err.Error(),
			}); updateErr != nil {
				return wire.SyncResponse{}, updateErr
			}
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return wire.SyncResponse{}, commitErr
			}
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrConflict, "%s", err.Error())
		}
	}
	tokenVersion := auth.AgentTokenVersionFromContext(ctx)
	if err := h.reconcileJobManifestTx(ctx, tx, agentID, tokenVersion, req.JobHandlers, req.JobCrons); err != nil {
		return wire.SyncResponse{}, jobManifestError(err)
	}
	if req.Version != "" {
		if err := q.UpdateAgentSDKVersion(ctx, dbq.UpdateAgentSDKVersionParams{
			ID:         pgAgentID,
			SdkVersion: req.Version,
		}); err != nil {
			return wire.SyncResponse{}, err
		}
		// Clear any stale compatibility error now that the sync succeeded.
		if err := q.UpdateAgentErrorMessage(ctx, dbq.UpdateAgentErrorMessageParams{
			ID:           pgAgentID,
			ErrorMessage: "",
		}); err != nil {
			return wire.SyncResponse{}, err
		}
	}
	if req.Description != "" {
		if err := q.UpdateAgentDescription(ctx, dbq.UpdateAgentDescriptionParams{
			ID:          pgAgentID,
			Description: req.Description,
		}); err != nil {
			return wire.SyncResponse{}, err
		}
	}
	// Emoji is cosmetic: persist a sane value, otherwise drop it (never
	// fail the whole sync over decoration). cleanAgentEmoji bounds
	// length and strips control chars without enforcing a single rune
	// (ZWJ / skin-tone / flag emoji are multi-codepoint).
	if e, ok := cleanAgentEmoji(req.Emoji); ok {
		if err := q.UpdateAgentEmoji(ctx, dbq.UpdateAgentEmojiParams{
			ID:    pgAgentID,
			Emoji: e,
		}); err != nil {
			return wire.SyncResponse{}, err
		}
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
	if err := q.UpdateAgentInstructions(ctx, dbq.UpdateAgentInstructionsParams{
		ID:           pgAgentID,
		Instructions: extrasJSON,
	}); err != nil {
		return wire.SyncResponse{}, err
	}

	// Upsert environment declarations, then delete stale rows. The configured
	// value belongs to the operator and survives while its slug stays declared.
	envVarSlugs := make([]string, len(req.EnvVars))
	for i, envVar := range req.EnvVars {
		if envVar.Slug == "" {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid environment variable declaration: slug is required")
		}
		if envVar.Pattern != "" {
			if _, err := regexp.Compile(envVar.Pattern); err != nil {
				return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid environment variable pattern: "+err.Error())
			}
		}
		if _, err := q.UpsertAgentEnvVar(ctx, dbq.UpsertAgentEnvVarParams{
			AgentID:      pgAgentID,
			Slug:         envVar.Slug,
			Description:  envVar.Description,
			IsSecret:     envVar.Secret,
			DefaultValue: envVar.Default,
			Pattern:      envVar.Pattern,
		}); err != nil {
			h.logger.Error("upsert environment variable failed", zap.Error(err))
			return wire.SyncResponse{}, errors.New("failed to sync environment variables")
		}
		envVarSlugs[i] = envVar.Slug
	}
	if err := q.DeleteStaleAgentEnvVars(ctx, dbq.DeleteStaleAgentEnvVarsParams{
		AgentID: pgAgentID,
		Slugs:   envVarSlugs,
	}); err != nil {
		h.logger.Error("delete stale environment variables failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync environment variables")
	}

	// Upsert tools, then delete stale.
	toolNames := make([]string, len(req.Tools))
	for i, t := range req.Tools {
		toolNames[i] = t.Name
		inSchema := normalizeToolInputSchema([]byte(t.InputSchema), t.Name, agentID, h.logger)
		outSchema := []byte(t.OutputSchema)
		if len(outSchema) == 0 {
			outSchema = []byte("{}")
		}
		if err := q.UpsertAgentTool(ctx, dbq.UpsertAgentToolParams{
			AgentID:      pgAgentID,
			Name:         t.Name,
			Description:  t.Description,
			LlmHint:      t.LLMHint,
			Access:       string(t.Access),
			InputSchema:  inSchema,
			OutputSchema: outSchema,
		}); err != nil {
			return wire.SyncResponse{}, err
		}
	}
	if err := q.DeleteStaleAgentTools(ctx, dbq.DeleteStaleAgentToolsParams{
		AgentID: pgAgentID,
		Names:   toolNames,
	}); err != nil {
		return wire.SyncResponse{}, err
	}

	// Upsert model slots, then delete stale. Upsert preserves the admin's
	// assigned_model across syncs — only the declaration fields update.
	slotSlugs := make([]string, len(req.ModelSlots))
	for i, s := range req.ModelSlots {
		slotSlugs[i] = s.Slug
		if err := q.UpsertAgentModelSlot(ctx, dbq.UpsertAgentModelSlotParams{
			AgentID:     pgAgentID,
			Slug:        s.Slug,
			Capability:  s.Capability,
			Description: s.Description,
		}); err != nil {
			return wire.SyncResponse{}, err
		}
	}
	if err := q.DeleteStaleAgentModelSlots(ctx, dbq.DeleteStaleAgentModelSlotsParams{
		AgentID: pgAgentID,
		Slugs:   slotSlugs,
	}); err != nil {
		return wire.SyncResponse{}, err
	}

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
			return wire.SyncResponse{}, errors.New("failed to sync webhooks")
		}
		if wh.Verify != "" && wh.Verify != "none" {
			row, err := q.GetWebhookByAgentAndPath(ctx, dbq.GetWebhookByAgentAndPathParams{
				AgentID: pgAgentID,
				Path:    wh.Path,
			})
			if err != nil {
				h.logger.Error("load webhook after upsert failed", zap.Error(err))
				return wire.SyncResponse{}, errors.New("failed to sync webhooks")
			}
			if row.Secret == "" {
				secretBytes := make([]byte, 32)
				if _, err := rand.Read(secretBytes); err != nil {
					h.logger.Error("generate webhook secret failed", zap.Error(err))
					return wire.SyncResponse{}, errors.New("failed to sync webhooks")
				}
				ref := "webhook/" + pgUUID(row.ID).String() + "/secret"
				stored, err := h.encryptor.Put(ctx, ref, hex.EncodeToString(secretBytes))
				if err != nil {
					h.logger.Error("encrypt webhook secret failed", zap.Error(err))
					return wire.SyncResponse{}, errors.New("failed to sync webhooks")
				}
				if err := q.UpdateWebhookSecret(ctx, dbq.UpdateWebhookSecretParams{ID: row.ID, Secret: stored}); err != nil {
					h.logger.Error("persist webhook secret failed", zap.Error(err))
					return wire.SyncResponse{}, errors.New("failed to sync webhooks")
				}
			}
		}
		paths[i] = wh.Path
	}
	if err := q.DeleteWebhooksByAgentExcept(ctx, dbq.DeleteWebhooksByAgentExceptParams{
		AgentID: pgAgentID,
		Paths:   paths,
	}); err != nil {
		h.logger.Error("delete stale webhooks failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync webhooks")
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
			return wire.SyncResponse{}, errors.New("failed to sync routes")
		}
		routeKeys[i] = rt.Path + "|" + rt.Method
	}
	if err := q.DeleteRoutesByAgentExcept(ctx, dbq.DeleteRoutesByAgentExceptParams{
		AgentID: pgAgentID,
		Keys:    routeKeys,
	}); err != nil {
		h.logger.Error("delete stale routes failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync routes")
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
			return wire.SyncResponse{}, errors.New("failed to sync topics")
		}
		topicSlugs[i] = t.Slug
	}
	if err := q.DeleteTopicsByAgentExcept(ctx, dbq.DeleteTopicsByAgentExceptParams{
		AgentID: pgAgentID,
		Slugs:   topicSlugs,
	}); err != nil {
		h.logger.Error("delete stale topics failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync topics")
	}

	// Upsert MCP servers, then delete stale.
	// Resource-need mutations share the agent -> ordered need -> resource lock
	// hierarchy with operator binding and OAuth transactions. Keeping all three
	// declaration types in one short transaction also makes scope expansion
	// visible atomically to runtime token checks.
	needsQ := q
	if _, err := needsQ.GetAgentByIDForUpdate(ctx, pgAgentID); err != nil {
		return wire.SyncResponse{}, errors.New("failed to lock agent for resource sync")
	}
	if _, err := needsQ.LockResourceNeedsByAgent(ctx, pgAgentID); err != nil {
		return wire.SyncResponse{}, err
	}
	mcpSlugs := make([]string, len(req.MCPServers))
	for i, mcp := range req.MCPServers {
		scopes := oauth.CanonicalScopeSet(mcp.Scopes)
		authInjection, err := json.Marshal(mcp.AuthInjection)
		if err != nil {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid auth_injection for MCP "+mcp.Slug)
		}
		// Sync owns only the agent-local declaration. Resource authorization and
		// bindings are operator-managed state and are never changed here.
		mcpSpec, _ := json.Marshal(map[string]any{
			"name": mcp.Name, "url": mcp.URL, "auth_mode": string(mcp.AuthMode),
			"auth_url": mcp.AuthURL, "token_url": mcp.TokenURL, "scopes": scopes,
			"auth_injection": json.RawMessage(authInjection), "access": string(mcp.Access),
		})
		if err := needsQ.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
			AgentID: pgAgentID, Type: "mcp_server", Slug: mcp.Slug,
			Description: mcp.Name, SetupInstructions: "", ExpectedUrl: mcp.URL,
			ExpectedScopes: scopes, Spec: mcpSpec,
		}); err != nil {
			h.logger.Error("record mcp need failed", zap.Error(err))
			return wire.SyncResponse{}, errors.New("failed to sync MCP servers")
		}
		mcpSlugs[i] = mcp.Slug
	}
	// Drop needs for slugs the agent no longer declares. The backing MCP server
	// resource is owner-owned and shared, so it is not deleted here — it outlives
	// this agent's declaration and may back another agent's binding.
	if err := needsQ.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "mcp_server", Slugs: mcpSlugs,
	}); err != nil {
		h.logger.Error("delete stale mcp needs failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync MCP servers")
	}

	connectorSlugs := make([]string, len(req.Connectors))
	for i, connector := range req.Connectors {
		if connector.Slug == "" || connector.Description == "" {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid connector declaration")
		}
		requirement, err := json.Marshal(connector.Requirement)
		if err != nil {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid connector declaration")
		}
		need, err := connectorssvc.ParseNeedSpec(requirement)
		if err != nil {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", err.Error())
		}
		need.Multiple = connector.Multiple
		spec, err := json.Marshal(need)
		if err != nil {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid connector declaration")
		}
		if err := needsQ.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
			AgentID: pgAgentID, Type: "connector", Slug: connector.Slug, Description: connector.Description,
			SetupInstructions: "", ExpectedUrl: "", ExpectedScopes: "", Spec: spec,
		}); err != nil {
			h.logger.Error("record connector need failed", zap.Error(err))
			return wire.SyncResponse{}, errors.New("failed to sync connectors")
		}
		connectorSlugs[i] = connector.Slug
	}
	if err := needsQ.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "connector", Slugs: connectorSlugs,
	}); err != nil {
		h.logger.Error("delete stale connector needs failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync connectors")
	}

	// Connections are declarations only. A sync can make one binding unready by
	// expanding its need scopes, but cannot mutate the shared resource.
	connSlugs := make([]string, len(req.Connections))
	for i, c := range req.Connections {
		authInjection, err := json.Marshal(c.AuthInjection)
		if err != nil {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid auth_injection for connection "+c.Slug)
		}
		authParams := []byte("{}")
		if len(c.AuthParams) > 0 {
			if authParams, err = json.Marshal(c.AuthParams); err != nil {
				return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid auth_params for connection "+c.Slug)
			}
		}
		headers := []byte("{}")
		if len(c.Headers) > 0 {
			if headers, err = json.Marshal(c.Headers); err != nil {
				return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid headers for connection "+c.Slug)
			}
		}
		scopes := oauth.CanonicalScopeSet(c.Scopes)
		if err := h.recordConnectionNeed(ctx, needsQ, agentID, c.Slug, c, scopes, authInjection, authParams, headers); err != nil {
			h.logger.Error("record connection need failed", zap.Error(err))
			return wire.SyncResponse{}, errors.New("failed to sync connections")
		}
		connSlugs[i] = c.Slug
	}
	if err := needsQ.DeleteResourceNeedsByAgentTypeExcept(ctx, dbq.DeleteResourceNeedsByAgentTypeExceptParams{
		AgentID: pgAgentID, Type: "connection", Slugs: connSlugs,
	}); err != nil {
		h.logger.Error("delete stale connection needs failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync connections")
	}

	// Upsert directories, then delete stale.
	dirPaths := make([]string, len(req.Directories))
	for i, d := range req.Directories {
		canonical, pathErr := storage.CleanAgentPath(d.Path)
		if pathErr != nil || canonical != d.Path ||
			!validDirectoryAccess(d.Read) || !validDirectoryAccess(d.Write) || !validDirectoryAccess(d.List) ||
			!validDirectoryScope(d.Scope) || d.RetentionHours < 0 {
			return wire.SyncResponse{}, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid directory declaration: "+d.Path)
		}
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
			return wire.SyncResponse{}, errors.New("failed to sync directories")
		}
		dirPaths[i] = d.Path
	}
	if err := q.DeleteDirectoriesByAgentExcept(ctx, dbq.DeleteDirectoriesByAgentExceptParams{
		AgentID: pgAgentID,
		Paths:   dirPaths,
	}); err != nil {
		h.logger.Error("delete stale directories failed", zap.Error(err))
		return wire.SyncResponse{}, errors.New("failed to sync directories")
	}

	// Discover MCP status for servers with credentials. discoverAllMCPStatus
	// updates the tool_schemas JSONB column on success, so re-fetch the rows
	// afterwards to read the freshly-cached schemas into the prompt + response.
	mcpServers, err := q.ListBoundMCPServersByAgent(ctx, pgAgentID)
	if err != nil {
		return wire.SyncResponse{}, err
	}
	mcpStatuses, err := h.discoverAllMCPStatus(ctx, q, agentID, mcpServers)
	if err != nil {
		return wire.SyncResponse{}, err
	}
	mcpServers, err = q.ListBoundMCPServersByAgent(ctx, pgAgentID)
	if err != nil {
		return wire.SyncResponse{}, err
	}

	// Index the (possibly-refreshed) server rows by the agent's need slug so we
	// can decode tool_schemas once and reuse for both the prompt template and the
	// SyncResponse payload.
	serverBySlug := make(map[string]dbq.ListBoundMCPServersByAgentRow, len(mcpServers))
	for _, srv := range mcpServers {
		serverBySlug[srv.Slug] = srv
	}

	// MCP status and schemas share the same refreshed discovery snapshot.
	var mcpAuthStatus []wire.MCPAuthStatus
	mcpSchemas := make(map[string][]wire.MCPToolSchema)
	for _, s := range mcpStatuses {
		mcpAuthStatus = append(mcpAuthStatus, s.MCPAuthStatus)
		if srv, ok := serverBySlug[s.Slug]; ok && len(srv.ToolSchemas) > 0 {
			var stored []runtimesvc.McpToolInfo
			if err := json.Unmarshal(srv.ToolSchemas, &stored); err == nil {
				schemas := make([]wire.MCPToolSchema, len(stored))
				for i, t := range stored {
					schemas[i] = wire.MCPToolSchema{
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
		return wire.SyncResponse{}, errors.New("failed to load agent")
	}
	routeURL := h.agentBaseURL(agentRecord.Slug)

	// Public storage base — the prefix StorageHandle.URL joins with '/'
	// and the storage path (e.g. "reports/q1.csv") to form a URL.
	publicStorageBase := routeURL + "/__air/storage"

	// Notify subscribed clients (agent detail tabs) that the agent's
	// declared surface — tools, webhooks, crons, routes, MCP servers,
	// connections, model slots — was just refreshed. Tabs subscribed to
	// "agent.synced" can refetch instead of waiting for the user to hit
	// reload after a build/upgrade completes.

	// Resolve the agent's effective model slots (agent override →
	// system default) so the prompt template can branch on which
	// builtins are actually available at runtime.
	caps, modalities, err := h.resolveAgentCapabilities(ctx, q, agentRecord)
	if err != nil {
		return wire.SyncResponse{}, err
	}

	manifestJSON, err := json.Marshal(req)
	if err != nil {
		return wire.SyncResponse{}, errors.New("failed to encode runtime manifest")
	}
	stored, err := q.StoreRuntimeManifest(ctx, dbq.StoreRuntimeManifestParams{
		AgentID: pgAgentID, TokenVersion: tokenVersion, Manifest: manifestJSON,
	})
	if err != nil || stored != 1 {
		return wire.SyncResponse{}, apperr.Detail(apperr.ErrConflict, "runtime generation changed during sync")
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.SyncResponse{}, err
	}
	h.scheduler.Wake()

	if err := h.pubsub.Publish(ctx, agentID, realtime.NewEnvelope("agent.synced", agentID.String(), &airlockv1.AgentSyncedEvent{
		AgentId: agentID.String(),
	})); err != nil {
		h.logger.Warn("publish app sync", zap.Error(err))
	}
	return wire.SyncResponse{
		RuntimeProtocol: wire.AppRuntimeProtocol,
		PromptData: wire.PromptData{
			AgentDashboardURL:   h.publicURL + "/agents/" + agentID.String(),
			AgentRouteURL:       routeURL,
			Capabilities:        caps,
			SupportedModalities: modalities,
		},
		MCPAuthStatus:     mcpAuthStatus,
		MCPSchemas:        mcpSchemas,
		PublicStorageBase: publicStorageBase,
	}, nil
}
