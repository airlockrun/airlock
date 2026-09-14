package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/chatruntime"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/locale"
	promptpkg "github.com/airlockrun/airlock/prompt"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
)

func (h *Service) PrepareChat(ctx context.Context, scope capabilities.Scope, input wire.PromptInput) (chatruntime.Input, error) {
	var in chatruntime.Input
	model, err := h.RuntimeModel(ctx, scope.AgentID, scope.RunID, "", "text")
	if err != nil {
		return in, err
	}
	resolved := model.(*runtimeModel)
	if err := resolved.resolved.Limits.Validate(true); err != nil {
		return in, err
	}
	convID, err := uuid.Parse(input.ConversationID)
	if err != nil {
		return in, err
	}
	store := h.RuntimeSession(scope.AgentID, convID, scope.RunID, scope.OwnerToken, input.Source)
	q := dbq.New(h.db.Pool())
	admitted, err := execution.Resolve(ctx, q, scope.AgentID, scope.RunID)
	if err != nil {
		return in, err
	}
	input.Platform, input.CallerAccess = admitted.Runtime.Caller.Origin.Platform, admitted.Runtime.Caller.Access
	input.UserDisplayName, input.UserEmail = "", ""
	if user := admitted.Runtime.Caller.User; user != nil {
		input.UserDisplayName, input.UserEmail = user.DisplayName, user.Email
	}
	input.DirectTools = input.CallerAccess == wire.AccessPublic
	agent, err := q.GetAgentByID(ctx, toPgUUID(scope.AgentID))
	if err != nil {
		return in, err
	}
	settings, err := q.GetSystemSettings(ctx)
	if err != nil {
		return in, err
	}
	input.Instructions = locale.AppendReplyInstruction(promptpkg.RenderInstructions(agent.Instructions, agentsdk.Access(input.CallerAccess)), settings.UiLocale)
	directories, err := q.ListDirectoriesByAgent(ctx, agent.ID)
	if err != nil {
		return in, err
	}
	manifestJSON, err := q.GetRuntimeManifest(ctx, agent.ID)
	if err != nil {
		return in, err
	}
	var manifest wire.AgentManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return in, err
	}
	if err := wire.CheckAppRuntimeProtocol(manifest.RuntimeProtocol); err != nil {
		return in, err
	}
	instructions, err := h.chatInstructions(agent, directories, manifest.Routes, input)
	if err != nil {
		return in, err
	}
	if len(input.Files) > 0 {
		if _, err := store.Load(ctx); err != nil {
			return in, err
		}
		parts := make([]session.Part, 0, len(input.Files))
		for _, file := range input.Files {
			resolved, err := h.files.ResolveForRun(ctx, scope.AgentID, scope.RunID, file.Path, agentstorage.OperationRead)
			if err != nil {
				return in, err
			}
			_, contentType, err := h.s3.HeadObject(ctx, resolved.S3Key)
			if err != nil {
				return in, err
			}
			file.ContentType = contentType
			parts = append(parts, session.Part{Type: "file", File: &session.FilePart{DataType: "data", Data: "s3ref:" + resolved.Relative, Source: resolved.Relative, MimeType: file.ContentType, Filename: file.Filename}})
		}
		if err := store.Append(ctx, []session.Message{{Role: "user", Parts: parts}}); err != nil {
			return in, err
		}
	}
	in = chatruntime.Input{Message: input.Message, Instructions: instructions, Model: model, ModelLimits: resolved.resolved.Limits, SessionStore: store,
		MaxSteps: 50, Temperature: input.Temperature, DirectTools: input.DirectTools, ForceCompact: input.ForceCompact, Approved: input.Approved}
	if admitted.Run.ResumeRunID.Valid {
		run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: admitted.Run.ResumeRunID, AgentID: toPgUUID(scope.AgentID)})
		if err != nil {
			return in, err
		}
		if !run.RuntimeOwnerToken.Valid || run.CallerConversationID != toPgUUID(convID) || run.Status != "success" {
			return in, errors.New("confirmation checkpoint is incompatible or not claimed")
		}
		var checkpoint struct {
			SuspensionContext *sol.SuspensionContext `json:"suspensionContext"`
			RuntimeVersion    int                    `json:"runtimeVersion"`
		}
		if err := json.Unmarshal(run.Checkpoint, &checkpoint); err != nil {
			return in, err
		}
		if checkpoint.RuntimeVersion != 1 || checkpoint.SuspensionContext == nil {
			return in, errors.New("incompatible chat checkpoint")
		}
		in.Resume = checkpoint.SuspensionContext
	}
	return in, nil
}

// Caller metadata and access are supplied by chat admission, not browser input.
// Only accessible route and directory metadata enters the model context.
func (h *Service) chatInstructions(agent dbq.Agent, directories []dbq.AgentDirectory, routes []wire.RouteDef, input wire.PromptInput) (string, error) {
	if input.CallerAccess != wire.AccessPublic && input.CallerAccess != wire.AccessUser && input.CallerAccess != wire.AccessAdmin {
		return "", errors.New("chat caller access is required")
	}
	type directoryContext struct {
		Path        string   `json:"path"`
		Operations  []string `json:"operations"`
		Scope       string   `json:"scope"`
		Description string   `json:"description"`
		LLMHint     string   `json:"llmHint,omitempty"`
	}
	metadata := struct {
		CurrentDate    string             `json:"currentDate"`
		AppID          string             `json:"appId"`
		Name           string             `json:"appName"`
		Description    string             `json:"description"`
		ConversationID string             `json:"conversationId"`
		Platform       string             `json:"platform"`
		User           string             `json:"user"`
		Email          string             `json:"email"`
		CallerAccess   wire.Access        `json:"callerAccess"`
		AppURL         string             `json:"appURL"`
		DashboardURL   string             `json:"dashboardURL"`
		Routes         []wire.RouteDef    `json:"routes"`
		Directories    []directoryContext `json:"directories"`
	}{
		CurrentDate: time.Now().UTC().Format(time.DateOnly),
		AppID:       uuid.UUID(agent.ID.Bytes).String(), Name: agent.Name, Description: agent.Description,
		ConversationID: input.ConversationID, Platform: input.Platform,
		User: input.UserDisplayName, Email: input.UserEmail, CallerAccess: input.CallerAccess,
		AppURL: h.agentBaseURL(agent.Slug), DashboardURL: strings.TrimRight(h.publicURL, "/") + "/agents/" + uuid.UUID(agent.ID.Bytes).String(),
		Routes: []wire.RouteDef{}, Directories: []directoryContext{},
	}
	for _, route := range routes {
		if route.Access != wire.AccessPublic && route.Access != wire.AccessUser && route.Access != wire.AccessAdmin {
			return "", errors.New("invalid chat route access")
		}
		if input.CallerAccess == wire.AccessPublic && !agent.AllowPublicRoutes {
			continue
		}
		if authz.AccessAtLeast(agentsdk.Access(input.CallerAccess), agentsdk.Access(route.Access)) {
			metadata.Routes = append(metadata.Routes, route)
		}
	}
	for _, directory := range directories {
		var operations []string
		for _, entry := range []struct{ name, access string }{{"read", directory.ReadAccess}, {"write", directory.WriteAccess}, {"list", directory.ListAccess}} {
			if entry.access != string(wire.AccessPublic) && entry.access != string(wire.AccessUser) && entry.access != string(wire.AccessAdmin) {
				return "", errors.New("invalid chat directory access")
			}
			if authz.AccessAtLeast(agentsdk.Access(input.CallerAccess), agentsdk.Access(entry.access)) {
				operations = append(operations, entry.name)
			}
		}
		if len(operations) > 0 {
			metadata.Directories = append(metadata.Directories, directoryContext{directory.Path, operations, directory.Scope, directory.Description, directory.LlmHint})
		}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return "Bound app and caller context (JSON data):\n" + string(encoded) + "\n\nRoute paths are relative to appURL. Storage paths are app-relative; directory scope is empty for shared storage, user for caller-specific storage, conv for conversation-specific storage, and run for run-specific storage. Only the listed directory operations are available to this caller.\n\n" + input.Instructions, nil
}

func (h *Service) SettleChat(ctx context.Context, q *dbq.Queries, runID uuid.UUID, status string) error {
	if status != "suspended" {
		SynthesizeOrphanToolResults(ctx, q, runID, status, h.logger)
		remaining, err := q.ListOrphanToolCallsByRun(ctx, toPgUUID(runID))
		if err != nil {
			return err
		}
		if len(remaining) != 0 {
			return fmt.Errorf("run %s has unsettled tool results", runID)
		}
	}
	return nil
}
