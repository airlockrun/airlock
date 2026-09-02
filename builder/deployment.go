package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/compat"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	deploymentPollInterval    = 250 * time.Millisecond
	deploymentAttemptBatch    = 1000
	deploymentRollbackTimeout = container.AgentStartupHealthTimeout + time.Minute
)

func (b *BuildService) contextWithBuildCancellation(parent context.Context, agentID, buildID pgtype.UUID) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(deploymentPollInterval)
		defer ticker.Stop()
		q := dbq.New(b.db.Pool())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				requested, err := q.AgentBuildCancellationRequested(ctx, dbq.AgentBuildCancellationRequestedParams{
					BuildID: buildID, AgentID: agentID,
				})
				if errors.Is(err, pgx.ErrNoRows) {
					return
				}
				if err != nil {
					b.logger.Error("poll durable build cancellation", zap.Error(err))
					continue
				}
				if requested {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() {
		cancel()
		<-done
	}
}

func decodeAgentManifest(payload []byte) (wire.AgentManifest, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return wire.AgentManifest{}, errors.New("candidate manifest must be a JSON object")
	}
	if err := rejectDuplicateManifestFields(payload); err != nil {
		return wire.AgentManifest{}, err
	}
	var manifest wire.AgentManifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return wire.AgentManifest{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return wire.AgentManifest{}, errors.New("candidate manifest must contain exactly one JSON value")
	}
	if err := validateAgentManifest(manifest); err != nil {
		return wire.AgentManifest{}, err
	}
	return manifest, nil
}

func rejectDuplicateManifestFields(payload []byte) error {
	requiredFields := []string{
		"version", "description", "emoji", "tools", "webhooks", "jobHandlers", "jobCrons", "routes", "topics",
		"mcpServers", "connections", "envVars", "directories", "instructions", "modelSlots", "staticAssets", "startupHooks", "connectors",
	}
	allowed := make(map[string]struct{}, len(requiredFields))
	for _, name := range requiredFields {
		allowed[name] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("candidate manifest contains a non-string field name")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("candidate manifest contains duplicate field %q", name)
		}
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("candidate manifest contains unknown field %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if err := rejectDuplicateJSONFields(value); err != nil {
			return fmt.Errorf("candidate manifest field %q: %w", name, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for _, name := range requiredFields {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("candidate manifest is missing field %q", name)
		}
	}
	return nil
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("contains multiple JSON values")
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := keyToken.(string)
			if !ok {
				return errors.New("contains a non-string field name")
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("contains duplicate field %q", name)
			}
			seen[name] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("contains an unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func validateAgentManifest(manifest wire.AgentManifest) error {
	if strings.TrimSpace(manifest.Description) == "" {
		return errors.New("candidate manifest description is required")
	}
	if err := compat.CheckSDKVersion(manifest.Version); err != nil {
		return err
	}
	required := []struct {
		name    string
		missing bool
	}{
		{"tools", manifest.Tools == nil},
		{"webhooks", manifest.Webhooks == nil},
		{"jobHandlers", manifest.JobHandlers == nil},
		{"jobCrons", manifest.JobCrons == nil},
		{"routes", manifest.Routes == nil},
		{"topics", manifest.Topics == nil},
		{"mcpServers", manifest.MCPServers == nil},
		{"connections", manifest.Connections == nil},
		{"envVars", manifest.EnvVars == nil},
		{"directories", manifest.Directories == nil},
		{"instructions", manifest.Instructions == nil},
		{"modelSlots", manifest.ModelSlots == nil},
		{"staticAssets", manifest.StaticAssets == nil},
		{"startupHooks", manifest.StartupHooks == nil},
		{"connectors", manifest.Connectors == nil},
	}
	for _, field := range required {
		if field.missing {
			return fmt.Errorf("candidate manifest field %q must be a JSON array", field.name)
		}
	}
	checks := []error{
		validateSortedUnique("tools", manifest.Tools, func(v wire.ToolDef) string { return v.Name }),
		validateSortedUnique("webhooks", manifest.Webhooks, func(v wire.WebhookDef) string { return v.Path }),
		validateSortedUnique("jobCrons", manifest.JobCrons, func(v wire.JobCronDef) string { return v.Slug }),
		validateSortedUnique("routes", manifest.Routes, func(v wire.RouteDef) string { return v.Method + "\x00" + v.Path }),
		validateSortedUnique("topics", manifest.Topics, func(v wire.TopicDef) string { return v.Slug }),
		validateSortedUnique("mcpServers", manifest.MCPServers, func(v wire.MCPDef) string { return v.Slug }),
		validateSortedUnique("connections", manifest.Connections, func(v wire.ConnectionDef) string { return v.Slug }),
		validateSortedUnique("envVars", manifest.EnvVars, func(v wire.EnvVarDef) string { return v.Slug }),
		validateSortedUnique("directories", manifest.Directories, func(v wire.DirectoryDef) string { return v.Path }),
		validateSortedUnique("modelSlots", manifest.ModelSlots, func(v wire.ModelSlotDef) string { return v.Slug }),
		validateSortedUnique("staticAssets", manifest.StaticAssets, func(v wire.StaticAssetDef) string { return v.Name }),
		validateUnique("startupHooks", manifest.StartupHooks, func(v wire.StartupHookDef) string { return v.Name }),
		validateSortedUnique("connectors", manifest.Connectors, func(v wire.ConnectorNeedDef) string { return v.Slug }),
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	for _, asset := range manifest.StaticAssets {
		if _, _, err := mime.ParseMediaType(asset.ContentType); err != nil {
			return fmt.Errorf("candidate manifest static asset %q has invalid contentType", asset.Name)
		}
		if asset.Size < 0 {
			return fmt.Errorf("candidate manifest static asset %q has negative size", asset.Name)
		}
		digest, err := hex.DecodeString(asset.SHA256)
		if err != nil || len(digest) != sha256.Size || asset.SHA256 != strings.ToLower(asset.SHA256) {
			return fmt.Errorf("candidate manifest static asset %q has invalid sha256", asset.Name)
		}
	}
	for i, handler := range manifest.JobHandlers {
		if handler.Name == "" {
			return errors.New("candidate manifest jobHandlers contains an empty identifier")
		}
		if i > 0 {
			previous := manifest.JobHandlers[i-1]
			if handler.Name < previous.Name || (handler.Name == previous.Name && handler.Version <= previous.Version) {
				return errors.New("candidate manifest field \"jobHandlers\" is not in canonical order or contains duplicates")
			}
		}
	}
	return nil
}

func validateSortedUnique[T any](field string, values []T, key func(T) string) error {
	if err := validateUnique(field, values, key); err != nil {
		return err
	}
	for i := 1; i < len(values); i++ {
		if key(values[i]) < key(values[i-1]) {
			return fmt.Errorf("candidate manifest field %q is not in canonical order", field)
		}
	}
	return nil
}

func validateUnique[T any](field string, values []T, key func(T) string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		identifier := key(value)
		if identifier == "" {
			return fmt.Errorf("candidate manifest field %q contains an empty identifier", field)
		}
		if _, ok := seen[identifier]; ok {
			return fmt.Errorf("candidate manifest field %q contains duplicate identifier %q", field, identifier)
		}
		seen[identifier] = struct{}{}
	}
	return nil
}

func (b *BuildService) persistCandidateJobManifest(ctx context.Context, buildID, agentID pgtype.UUID, sourceRef, imageRef string, manifest wire.JobManifest, digest string) error {
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin candidate job manifest: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return fmt.Errorf("lock candidate build: %w", err)
	}
	if build.JobManifestExtractedAt.Valid {
		return errors.New("candidate job manifest was already extracted")
	}
	existing, err := q.ListJobHandlersByAgent(ctx, agentID)
	if err != nil {
		return fmt.Errorf("list historical job handlers: %w", err)
	}
	contracts := make(map[string]wire.JobHandlerDef, len(existing))
	for _, handler := range existing {
		contracts[jobssvc.HandlerKey(handler.Name, handler.Version)] = wire.JobHandlerDef{
			Name: handler.Name, Version: handler.Version, TimeoutMs: handler.TimeoutMs,
			MaxAttempts: handler.MaxAttempts, InputSchemaHash: handler.InputSchemaHash,
			OutputSchemaHash: handler.OutputSchemaHash,
		}
	}
	for _, handler := range manifest.JobHandlers {
		key := jobssvc.HandlerKey(handler.Name, handler.Version)
		if historical, ok := contracts[key]; ok && !jobssvc.ImmutableContractMatches(historical, handler) {
			return fmt.Errorf("%w: %s changed its immutable contract", jobssvc.ErrContractConflict, key)
		}
	}
	if err := q.DeleteAgentBuildJobHandlers(ctx, buildID); err != nil {
		return fmt.Errorf("clear candidate job handlers: %w", err)
	}
	for _, handler := range manifest.JobHandlers {
		rows, err := q.InsertAgentBuildJobHandler(ctx, dbq.InsertAgentBuildJobHandlerParams{
			BuildID: buildID, Name: handler.Name, Version: handler.Version,
			Description: handler.Description, TimeoutMs: handler.TimeoutMs,
			MaxAttempts: handler.MaxAttempts, MaxConcurrency: handler.MaxConcurrency,
			InputSchema: handler.InputSchema, OutputSchema: handler.OutputSchema,
			InputSchemaHash: handler.InputSchemaHash, OutputSchemaHash: handler.OutputSchemaHash,
		})
		if err != nil || rows != 1 {
			if err == nil {
				err = ErrDeploymentConflict
			}
			return fmt.Errorf("persist candidate handler %s: %w", jobssvc.HandlerKey(handler.Name, handler.Version), err)
		}
	}
	rows, err := q.MarkAgentBuildJobManifestExtracted(ctx, dbq.MarkAgentBuildJobManifestExtractedParams{
		JobManifestDigest: pgtype.Text{String: digest, Valid: true}, SourceRef: sourceRef, ImageRef: imageRef, BuildID: buildID, AgentID: agentID,
	})
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return fmt.Errorf("mark candidate manifest extracted: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit candidate job manifest: %w", err)
	}
	return nil
}

func (b *BuildService) deployCandidate(ctx context.Context, plan BuildPlan, buildID pgtype.UUID, agentDBURL, sourceRef, imageRef, exitStatus, exitMessage string, prepareCutover, compensateCutover func(context.Context) error) error {
	agent := plan.Agent
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	targetStatus := agent.Status
	switch plan.Kind {
	case BuildKindBuild:
		if agent.Status != "building" {
			return ErrDeploymentConflict
		}
		targetStatus = "active"
	case BuildKindUpgrade, BuildKindRollback:
		switch agent.Status {
		case "active", "failed":
			targetStatus = "active"
		case "stopped":
			targetStatus = "stopped"
		default:
			return fmt.Errorf("%w: cannot deploy %s agent from status %q", ErrDeploymentConflict, plan.Kind, agent.Status)
		}
	default:
		return fmt.Errorf("unknown build kind %q", plan.Kind)
	}

	q := dbq.New(b.db.Pool())
	deploymentToken := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	rows, err := q.SetAgentBuildDeploymentTarget(ctx, dbq.SetAgentBuildDeploymentTargetParams{
		DeploymentPhase: "manifest", DeploymentTargetStatus: pgtype.Text{String: targetStatus, Valid: true},
		DeploymentToken: deploymentToken, BuildID: buildID, AgentID: agent.ID,
	})
	if err != nil {
		return fmt.Errorf("create deployment target: %w", err)
	}
	if rows != 1 {
		if err := b.checkAgentBuildCancellation(ctx, q, agent.ID, buildID); err != nil {
			return err
		}
		return ErrDeploymentConflict
	}

	if targetStatus == "stopped" {
		return b.deployStoppedCandidate(ctx, agent.ID, buildID, deploymentToken, sourceRef, imageRef, exitStatus, exitMessage, prepareCutover, compensateCutover)
	}

	paused, err := b.waitForDeploymentPause(ctx, agent.ID, buildID, deploymentToken)
	if err != nil {
		cleanupErr := b.rollbackDeploymentIfPaused(agent, buildID, deploymentToken, agentDBURL)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		return err
	}
	rollback := func(deployErr error, tokenVersion int64) error {
		rollbackErr := b.rollbackPausedDeployment(agent, buildID, deploymentToken, agentDBURL)
		if rollbackErr != nil {
			deployErr = errors.Join(deployErr, rollbackErr)
		}
		if tokenVersion > 0 {
			return &deploymentAttemptError{err: deployErr, tokenVersion: tokenVersion}
		}
		return deployErr
	}

	if err := b.drainDeploymentAttempts(ctx, q, agent.ID, buildID, deploymentToken, paused.JobDispatchPauseDeadline.Time); err != nil {
		return rollback(err, paused.AgentTokenVersion)
	}
	if err := b.checkAgentBuildCancellation(ctx, q, agent.ID, buildID); err != nil {
		return rollback(err, paused.AgentTokenVersion)
	}

	runtimeLock, err := b.db.AcquireAdvisoryLock(ctx, "agent-runtime:"+agentUUID.String())
	if err != nil {
		return rollback(fmt.Errorf("lock agent runtime for cutover: %w", err), paused.AgentTokenVersion)
	}
	defer runtimeLock.Unlock()
	unlockSwap := b.containers.LockSwap(agentUUID)
	defer unlockSwap()
	tokenVersion, err := b.beginDeploymentCutover(ctx, agent.ID, buildID, deploymentToken, agent.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if cancelErr := b.checkAgentBuildCancellation(ctx, q, agent.ID, buildID); cancelErr != nil {
				err = cancelErr
			} else {
				err = ErrDeploymentConflict
			}
		}
		return rollback(fmt.Errorf("begin deployment cutover: %w", err), paused.AgentTokenVersion)
	}
	if agent.ImageRef != "" {
		if err := b.containers.StopAgent(ctx, agentUUID); err != nil {
			return rollback(fmt.Errorf("stop current agent: %w", err), tokenVersion)
		}
	}
	if prepareCutover != nil {
		if err := prepareCutover(ctx); err != nil {
			return rollback(err, tokenVersion)
		}
	}
	agentToken, err := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID, tokenVersion)
	if err != nil {
		return rollback(fmt.Errorf("issue candidate token: %w", err), tokenVersion)
	}
	if _, err := b.containers.StartAgent(ctx, container.AgentOpts{
		AgentID: agentUUID, Image: imageRef, Token: agentToken,
		Env: map[string]string{"AIRLOCK_AGENT_ID": agentID, "AIRLOCK_API_URL": b.cfg.APIURLAgent, "AIRLOCK_DB_URL": agentDBURL},
	}); err != nil {
		return rollback(fmt.Errorf("start candidate agent: %w", err), tokenVersion)
	}
	rows, err = q.FinalizePausedAgentDeployment(ctx, dbq.FinalizePausedAgentDeploymentParams{
		SourceRef: sourceRef, ImageRef: imageRef, NextStatus: targetStatus,
		SdkVersion: agentsdk.Version, ExitStatus: exitStatus, ExitMessage: exitMessage,
		AgentID: agent.ID, AgentTokenVersion: tokenVersion, BuildID: buildID, DeploymentToken: deploymentToken,
	})
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return rollback(fmt.Errorf("finalize candidate deployment: %w", err), tokenVersion)
	}
	if b.jobWake != nil {
		b.jobWake()
	}
	return nil
}

func (b *BuildService) beginDeploymentCutover(ctx context.Context, agentID, buildID, token pgtype.UUID, expectedStatus string) (int64, error) {
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin cutover transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, agentID); err != nil {
		return 0, err
	}
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return 0, err
	}
	if build.CancelRequestedAt.Valid {
		return 0, context.Canceled
	}
	tokenVersion, err := q.BeginAgentDeploymentCutover(ctx, dbq.BeginAgentDeploymentCutoverParams{
		AgentID: agentID, BuildID: buildID, DeploymentToken: token, ExpectedStatus: expectedStatus,
	})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tokenVersion, nil
}

func (b *BuildService) deployStoppedCandidate(ctx context.Context, agentID, buildID, token pgtype.UUID, sourceRef, imageRef, exitStatus, exitMessage string, prepareCutover, compensateCutover func(context.Context) error) error {
	for {
		runtimeLock, err := b.db.AcquireAdvisoryLock(ctx, "agent-runtime:"+uuidString(agentID))
		if err != nil {
			return fmt.Errorf("lock stopped agent runtime: %w", err)
		}
		deployed, err := b.tryFinalizeStoppedDeployment(ctx, agentID, buildID, token, sourceRef, imageRef, exitStatus, exitMessage, prepareCutover, compensateCutover)
		runtimeLock.Unlock()
		if err != nil {
			return err
		}
		if deployed {
			return nil
		}
		if err := waitDeploymentPoll(ctx); err != nil {
			return err
		}
	}
}

func (b *BuildService) tryFinalizeStoppedDeployment(ctx context.Context, agentID, buildID, token pgtype.UUID, sourceRef, imageRef, exitStatus, exitMessage string, prepareCutover, compensateCutover func(context.Context) error) (bool, error) {
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin stopped deployment: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, agentID)
	if err != nil {
		return false, fmt.Errorf("lock stopped agent deployment: %w", err)
	}
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return false, fmt.Errorf("lock stopped build deployment: %w", err)
	}
	if agent.Status != "stopped" || agent.JobDispatchPausedBuildID.Valid ||
		build.DeploymentToken != token || (build.DeploymentPhase != "manifest" && build.DeploymentPhase != "blocked") {
		return false, ErrDeploymentConflict
	}
	if build.CancelRequestedAt.Valid {
		return false, context.Canceled
	}
	blockers, err := q.SummarizeAgentBuildBlockingJobs(ctx, dbq.SummarizeAgentBuildBlockingJobsParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return false, fmt.Errorf("evaluate stopped deployment blockers: %w", err)
	}
	if len(blockers) != 0 {
		rows, err := q.UpdateAgentBuildDeploymentPhase(ctx, dbq.UpdateAgentBuildDeploymentPhaseParams{
			DeploymentPhase: "blocked", BuildID: buildID, AgentID: agentID, DeploymentToken: token,
		})
		if err != nil || rows != 1 {
			if err == nil {
				err = ErrDeploymentConflict
			}
			return false, fmt.Errorf("mark stopped deployment blocked: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit stopped deployment blockers: %w", err)
		}
		return false, nil
	}
	if prepareCutover != nil && compensateCutover == nil {
		return false, errors.New("stopped rollback cutover requires migration compensation")
	}
	rows, err := q.UpdateAgentBuildDeploymentPhase(ctx, dbq.UpdateAgentBuildDeploymentPhaseParams{
		DeploymentPhase: "starting", BuildID: buildID, AgentID: agentID, DeploymentToken: token,
	})
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return false, fmt.Errorf("mark stopped deployment starting: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit stopped deployment preparation: %w", err)
	}

	if prepareCutover != nil {
		if err := prepareCutover(ctx); err != nil {
			return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, err, compensateCutover)
		}
	}
	return b.finalizePreparedStoppedDeployment(ctx, agentID, buildID, token, sourceRef, imageRef, exitStatus, exitMessage, compensateCutover)
}

func (b *BuildService) finalizePreparedStoppedDeployment(ctx context.Context, agentID, buildID, token pgtype.UUID, sourceRef, imageRef, exitStatus, exitMessage string, compensateCutover func(context.Context) error) (bool, error) {
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin stopped deployment finalization: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, agentID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, err, compensateCutover)
	}
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		_ = tx.Rollback(ctx)
		return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, err, compensateCutover)
	}
	if agent.Status != "stopped" || agent.JobDispatchPausedBuildID.Valid || build.DeploymentToken != token || build.DeploymentPhase != "starting" {
		_ = tx.Rollback(ctx)
		return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, ErrDeploymentConflict, compensateCutover)
	}
	if _, err := q.FinalizeStoppedAgentDeployment(ctx, dbq.FinalizeStoppedAgentDeploymentParams{
		SourceRef: sourceRef, ImageRef: imageRef, SdkVersion: agentsdk.Version,
		ExitStatus: exitStatus, ExitMessage: exitMessage,
		AgentID: agentID, BuildID: buildID, DeploymentToken: token,
	}); err != nil {
		_ = tx.Rollback(ctx)
		return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, fmt.Errorf("finalize stopped deployment: %w", err), compensateCutover)
	}
	if err := tx.Commit(ctx); err != nil {
		stored, loadErr := dbq.New(b.db.Pool()).GetAgentBuild(context.Background(), buildID)
		if loadErr == nil && stored.Status == "complete" && stored.DeploymentPhase == "complete" {
			return true, nil
		}
		return false, b.failStoppedDeploymentPreparation(agentID, buildID, token, errors.Join(fmt.Errorf("commit stopped deployment: %w", err), loadErr), compensateCutover)
	}
	return true, nil
}

func (b *BuildService) failStoppedDeploymentPreparation(agentID, buildID, token pgtype.UUID, cause error, compensate func(context.Context) error) error {
	if compensate != nil {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		restoreErr := compensate(restoreCtx)
		cancel()
		if restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("restore stopped deployment schema: %w", restoreErr))
		}
	}
	q := dbq.New(b.db.Pool())
	rows, err := q.UpdateAgentBuildDeploymentPhase(context.Background(), dbq.UpdateAgentBuildDeploymentPhaseParams{
		DeploymentPhase: "failed", BuildID: buildID, AgentID: agentID, DeploymentToken: token,
	})
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return errors.Join(cause, fmt.Errorf("fail stopped deployment: %w", err))
	}
	return cause
}

func (b *BuildService) waitForDeploymentPause(ctx context.Context, agentID, buildID, token pgtype.UUID) (dbq.PauseAgentJobDispatchRow, error) {
	for {
		paused, ready, err := b.tryPauseDeployment(ctx, agentID, buildID, token)
		if err != nil {
			return dbq.PauseAgentJobDispatchRow{}, err
		}
		if ready {
			return paused, nil
		}
		if err := waitDeploymentPoll(ctx); err != nil {
			return dbq.PauseAgentJobDispatchRow{}, err
		}
	}
}

// tryPauseDeployment serializes the blocker check with enqueue through the
// agent row. The blocker query runs after the row lock is acquired, so it sees
// every enqueue that committed before the pause and later enqueues see the
// persisted candidate gate.
func (b *BuildService) tryPauseDeployment(ctx context.Context, agentID, buildID, token pgtype.UUID) (dbq.PauseAgentJobDispatchRow, bool, error) {
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("begin deployment pause: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, agentID); err != nil {
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("lock agent for deployment pause: %w", err)
	}
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("lock build for deployment pause: %w", err)
	}
	if build.CancelRequestedAt.Valid {
		return dbq.PauseAgentJobDispatchRow{}, false, context.Canceled
	}
	blockers, err := q.SummarizeAgentBuildBlockingJobs(ctx, dbq.SummarizeAgentBuildBlockingJobsParams{BuildID: buildID, AgentID: agentID})
	if err != nil {
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("evaluate deployment blockers: %w", err)
	}
	if len(blockers) != 0 {
		rows, err := q.UpdateAgentBuildDeploymentPhase(ctx, dbq.UpdateAgentBuildDeploymentPhaseParams{
			DeploymentPhase: "blocked", BuildID: buildID, AgentID: agentID, DeploymentToken: token,
		})
		if err != nil || rows != 1 {
			if err == nil {
				err = ErrDeploymentConflict
			}
			return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("mark deployment blocked: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("commit blocked deployment: %w", err)
		}
		return dbq.PauseAgentJobDispatchRow{}, false, nil
	}
	paused, err := q.PauseAgentJobDispatch(ctx, dbq.PauseAgentJobDispatchParams{BuildID: buildID, AgentID: agentID, DeploymentToken: token})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.PauseAgentJobDispatchRow{}, false, ErrDeploymentConflict
		}
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("pause job dispatch: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.PauseAgentJobDispatchRow{}, false, fmt.Errorf("commit deployment pause: %w", err)
	}
	return paused, true, nil
}

func (b *BuildService) drainDeploymentAttempts(ctx context.Context, q *dbq.Queries, agentID, buildID, token pgtype.UUID, deadline time.Time) error {
	for {
		if err := b.checkAgentBuildCancellation(ctx, q, agentID, buildID); err != nil {
			return err
		}
		attempts, err := q.ListActiveAgentJobAttempts(ctx, dbq.ListActiveAgentJobAttemptsParams{AgentID: agentID, Lim: deploymentAttemptBatch})
		if err != nil {
			return fmt.Errorf("list active job attempts: %w", err)
		}
		if len(attempts) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			for _, attempt := range attempts {
				_, err := q.ForceInterruptAgentJobAttemptForDeployment(ctx, dbq.ForceInterruptAgentJobAttemptForDeploymentParams{
					ErrorMessage: pgtype.Text{String: "interrupted for agent deployment", Valid: true},
					AgentID:      agentID, BuildID: buildID, DeploymentToken: token,
					JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber, LeaseToken: attempt.LeaseToken,
				})
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("interrupt job attempt for deployment: %w", err)
				}
			}
			continue
		}
		wait := minDuration(deploymentPollInterval, time.Until(deadline))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (b *BuildService) checkAgentBuildCancellation(ctx context.Context, q *dbq.Queries, agentID, buildID pgtype.UUID) error {
	requested, err := q.AgentBuildCancellationRequested(ctx, dbq.AgentBuildCancellationRequestedParams{
		BuildID: buildID, AgentID: agentID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeploymentConflict
		}
		return fmt.Errorf("check build cancellation: %w", err)
	}
	if requested {
		return context.Canceled
	}
	return nil
}

func (b *BuildService) rollbackDeploymentIfPaused(agent dbq.Agent, buildID, token pgtype.UUID, agentDBURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	live, err := dbq.New(b.db.Pool()).GetAgentByID(ctx, agent.ID)
	if err != nil {
		return fmt.Errorf("check deployment pause cleanup: %w", err)
	}
	if !live.JobDispatchPausedBuildID.Valid || live.JobDispatchPausedBuildID.Bytes != buildID.Bytes {
		return nil
	}
	return b.rollbackPausedDeployment(agent, buildID, token, agentDBURL)
}

func (b *BuildService) rollbackPausedDeployment(agent dbq.Agent, buildID, token pgtype.UUID, agentDBURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), deploymentRollbackTimeout)
	defer cancel()
	q := dbq.New(b.db.Pool())
	build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agent.ID})
	if err != nil {
		return fmt.Errorf("load deployment rollback state: %w", err)
	}
	runtimeChanged := build.DeploymentPhase != "paused"
	if rows, err := q.SetAgentDeploymentRollback(ctx, dbq.SetAgentDeploymentRollbackParams{BuildID: buildID, AgentID: agent.ID, DeploymentToken: token}); err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return fmt.Errorf("enter deployment rollback: %w", err)
	}
	agentUUID := uuid.UUID(agent.ID.Bytes)
	var rollbackErr error
	if runtimeChanged {
		if err := b.containers.StopAgent(ctx, agentUUID); err != nil {
			rollbackErr = fmt.Errorf("stop failed candidate: %w", err)
		}
	}
	live, err := q.GetAgentByID(ctx, agent.ID)
	if err != nil {
		rollbackErr = errors.Join(rollbackErr, fmt.Errorf("load rollback generation: %w", err))
	} else {
		if runtimeChanged && agent.ImageRef != "" && live.Status != "stopped" {
			agentToken, issueErr := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID, live.AgentTokenVersion)
			if issueErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("issue rollback token: %w", issueErr))
			} else if _, startErr := b.containers.StartAgent(ctx, container.AgentOpts{
				AgentID: agentUUID, Image: agent.ImageRef, Token: agentToken,
				Env: map[string]string{"AIRLOCK_AGENT_ID": agentUUID.String(), "AIRLOCK_API_URL": b.cfg.APIURLAgent, "AIRLOCK_DB_URL": agentDBURL},
			}); startErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restart rollback agent: %w", startErr))
			}
		}
	}
	if rollbackErr != nil {
		// Keep the durable pause and rollback phase in place. Recovery can retry
		// restoration, but dispatch must not resume against an unknown runtime or
		// schema state.
		return rollbackErr
	}
	rows, err := q.FailPausedAgentDeployment(ctx, dbq.FailPausedAgentDeploymentParams{
		RollbackStatus: agent.Status, AgentID: agent.ID, BuildID: buildID, DeploymentToken: token,
	})
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrDeploymentConflict
		}
		return fmt.Errorf("resume dispatch after rollback: %w", err)
	}
	if b.jobWake != nil {
		b.jobWake()
	}
	return nil
}

func waitDeploymentPoll(ctx context.Context) error {
	timer := time.NewTimer(deploymentPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
