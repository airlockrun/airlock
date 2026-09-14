// Package execution admits runs with immutable host-derived origin and rechecks
// their credential and grant state across replicas. Input payloads are never identity.
package execution

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type Kind string

const (
	Prompt  Kind = "prompt"
	Tool    Kind = "tool"
	Route   Kind = "route"
	Webhook Kind = "webhook"
	Job     Kind = "job"
	App     Kind = "app"
	Agent   Kind = "agent"
)

type Service struct{ db *db.DB }

func New(database *db.DB) *Service {
	if database == nil {
		panic("execution: database is required")
	}
	return &Service{db: database}
}

// Request contains operation coordinates, not user or access assertions.
// Route requests copy Path and RawPath together from the incoming URL.
type Request struct {
	AgentID               uuid.UUID
	Kind                  Kind
	Ref                   string
	Input                 json.RawMessage
	ConversationID        uuid.UUID
	ResumeRunID           uuid.UUID
	Method, Path, RawPath string
}

type Context struct {
	Run       dbq.Run
	Origin    dbq.ExecutionOrigin
	Principal authz.Principal
	Runtime   wire.RuntimeContext
}

type runtimeOwnerKey struct{}
type runtimeOwner struct{ runID, token uuid.UUID }

// WithRuntimeOwner adds an ownership ceiling to internal host operations. It
// conveys no authority: Resolve still restores the admitted run from the DB.
// Nested broker/model operations cannot borrow a replacement worker's lease.
func WithRuntimeOwner(ctx context.Context, runID, token uuid.UUID) context.Context {
	if runID == uuid.Nil || token == uuid.Nil {
		panic("execution: runtime run and owner token are required")
	}
	if owner, ok := ctx.Value(runtimeOwnerKey{}).(runtimeOwner); ok && (owner.runID != runID || owner.token != token) {
		panic("execution: cannot replace an existing runtime ownership ceiling")
	}
	return context.WithValue(ctx, runtimeOwnerKey{}, runtimeOwner{runID: runID, token: token})
}

// Principal validates a supplied opaque admission proof before policy evaluation.
func Principal(ctx context.Context, q *dbq.Queries, p authz.Principal) (authz.Principal, error) {
	if p.Kind == authz.KindAnonymousUser && p.Valid() {
		return p, nil
	}
	if p.Kind != authz.KindRegisteredUser || p.Identity == nil {
		return authz.Principal{}, service.ErrUnauthorized
	}
	live, err := p.Identity.Resolve(ctx, q)
	if err != nil {
		return authz.Principal{}, err
	}
	if err := auth.RequireSecuredAccount(live); err != nil {
		return authz.Principal{}, err
	}
	resolved := authz.PrincipalFromClaims(live)
	if resolved.UserID != p.UserID {
		return authz.Principal{}, service.ErrUnauthorized
	}
	return resolved, nil
}

// Access provides verified ingress policy for transport-side presentation.
func Access(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID) (agentsdk.Access, error) {
	p, err := Principal(ctx, q, p)
	if err != nil {
		return "", err
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, agentID); err != nil {
		return "", err
	}
	access, _, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
	return access, err
}

func origin(ctx context.Context, q *dbq.Queries, p authz.Principal, req Request) (dbq.CreateExecutionOriginParams, error) {
	params := dbq.CreateExecutionOriginParams{ID: pgID(uuid.New()), AgentID: pgID(req.AgentID), ConversationID: pgID(req.ConversationID), Actor: "anonymous", CredentialProfile: "none"}
	switch req.Kind {
	case Prompt:
		params.Ingress = "web"
	case Tool:
		params.Ingress = "mcp"
	case Route:
		params.Ingress = "route"
	default:
		return dbq.CreateExecutionOriginParams{}, service.ErrInvalidInput
	}
	if p.Kind == authz.KindRegisteredUser {
		proof := p.Identity.Provenance()
		params.Actor, params.CredentialProfile, params.UserID = "user", proof.Profile, pgID(proof.UserID)
		params.SessionID, params.AuthEpoch = pgID(proof.SessionID), pgtype.Int8{Int64: proof.AuthEpoch, Valid: true}
		params.CredentialExpiresAt, params.AuthenticatedAt = timestamp(proof.ExpiresAt), timestamp(proof.AuthenticatedAt)
		params.Audience, params.ClientID, params.Scope = text(proof.Audience), text(proof.ClientID), text(proof.Scope)
		params.CredentialAgentID = pgID(proof.AgentID)
		if proof.AgentID != uuid.Nil && proof.AgentID != req.AgentID {
			return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
		}
		switch proof.Profile {
		case "bridge":
			if req.Kind != Prompt || proof.BridgeID == uuid.Nil || proof.AgentID != req.AgentID {
				return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
			}
			params.Ingress, params.BridgeID, params.PlatformIdentityID = "bridge", pgID(proof.BridgeID), pgID(proof.PlatformIdentityID)
			params.SenderID, params.ChatID = text(proof.SenderID), text(proof.ChatID)
		case "oauth_mcp":
			u, err := url.Parse(proof.Audience)
			if err != nil || req.Kind != Tool || u.Path != "/api/agent/"+req.AgentID.String()+"/mcp" {
				return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
			}
		case "user_access", "subdomain":
		default:
			return dbq.CreateExecutionOriginParams{}, service.ErrUnauthorized
		}
	}
	if req.Kind == Prompt {
		if p.Kind != authz.KindRegisteredUser || req.ConversationID == uuid.Nil {
			return dbq.CreateExecutionOriginParams{}, service.ErrUnauthorized
		}
		conv, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{ID: pgID(req.ConversationID), AgentID: pgID(req.AgentID)})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return dbq.CreateExecutionOriginParams{}, err
		}
		if err != nil || conv.UserID != params.UserID {
			return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
		}
		if params.Ingress == "bridge" {
			if conv.Source != "bridge" || conv.BridgeID != params.BridgeID || conv.ExternalID.String != params.ChatID.String {
				return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
			}
		} else if conv.Source != "web" || conv.BridgeID.Valid {
			return dbq.CreateExecutionOriginParams{}, service.ErrForbidden
		}
	}
	return params, nil
}

// Admit validates ingress and commits origin, run, resume claim, and hosted lease
// atomically. A failed admission cannot consume a pending confirmation.
func (s *Service) Admit(ctx context.Context, p authz.Principal, req Request) (dbq.Run, error) {
	if req.AgentID == uuid.Nil || !json.Valid(req.Input) {
		return dbq.Run{}, service.ErrInvalidInput
	}
	if req.Kind != Prompt && req.ConversationID != uuid.Nil {
		return dbq.Run{}, service.ErrInvalidInput
	}
	var err error
	p, err = Principal(ctx, dbq.New(s.db.Pool()), p)
	if err != nil {
		return dbq.Run{}, err
	}
	if req.Kind == Prompt {
		if p.Identity == nil {
			return dbq.Run{}, service.ErrUnauthorized
		}
		_, granted, err := p.EffectiveAgentAccessChecked(ctx, dbq.New(s.db.Pool()), req.AgentID)
		if err != nil {
			return dbq.Run{}, err
		}
		if !granted {
			return dbq.Run{}, service.ErrForbidden
		}
	}
	if req.ResumeRunID != uuid.Nil {
		deadline := time.Now().Add(10 * time.Second)
		for {
			r, err := dbq.New(s.db.Pool()).GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(req.ResumeRunID), AgentID: pgID(req.AgentID)})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return dbq.Run{}, err
			}
			if err != nil || r.CallerConversationID != pgID(req.ConversationID) {
				return dbq.Run{}, service.ErrForbidden
			}
			if r.Status != "running" {
				break
			}
			if time.Now().After(deadline) {
				return dbq.Run{}, service.ErrConflict
			}
			select {
			case <-ctx.Done():
				return dbq.Run{}, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.Run{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	p, err = Principal(ctx, q, p)
	if err != nil {
		return dbq.Run{}, err
	}
	access, err := Access(ctx, q, p, req.AgentID)
	if err != nil {
		return dbq.Run{}, err
	}
	agent, err := q.GetAgentByID(ctx, pgID(req.AgentID))
	if err != nil {
		return dbq.Run{}, err
	}
	if req.Kind != Route && p.Kind == authz.KindRegisteredUser {
		_, granted, err := p.EffectiveAgentAccessChecked(ctx, q, req.AgentID)
		if err != nil {
			return dbq.Run{}, err
		}
		if !granted {
			return dbq.Run{}, service.ErrForbidden
		}
	}
	if req.Kind == Tool {
		if !agent.McpEnabled || p.Kind == authz.KindAnonymousUser && !agent.AllowPublicMcp {
			return dbq.Run{}, service.ErrForbidden
		}
		tools, err := q.ListAgentTools(ctx, agent.ID)
		if err != nil {
			return dbq.Run{}, err
		}
		allowed := false
		for _, t := range tools {
			if t.Name == req.Ref && authz.AccessAtLeast(access, agentsdk.Access(t.Access)) {
				allowed = true
			}
		}
		if !allowed {
			return dbq.Run{}, service.ErrForbidden
		}
		if p.Kind == authz.KindAnonymousUser {
			conv, err := q.CreateAnonymousToolConversation(ctx, dbq.CreateAnonymousToolConversationParams{AgentID: agent.ID, Title: req.Ref})
			if err != nil {
				return dbq.Run{}, err
			}
			req.ConversationID = uuid.UUID(conv.ID.Bytes)
		}
	}
	if req.Kind == Route {
		selection, err := authorizeRoute(ctx, q, p, agent, req.Method, req.Path, req.RawPath)
		if err != nil {
			return dbq.Run{}, err
		}
		if selection.Asset {
			return dbq.Run{}, service.ErrInvalidInput
		}
		req.Ref = selection.Ref
	}
	if err := RequireRuntimeProtocol(ctx, q, req.AgentID); err != nil {
		return dbq.Run{}, err
	}
	params, err := origin(ctx, q, p, req)
	if err != nil {
		return dbq.Run{}, err
	}
	var o dbq.ExecutionOrigin
	if req.Kind == Prompt {
		if req.ResumeRunID == uuid.Nil {
			r, err := q.LatestExecutionSuspension(ctx, dbq.LatestExecutionSuspensionParams{AgentID: agent.ID, ConversationID: params.ConversationID})
			if err == nil {
				req.ResumeRunID = uuid.UUID(r.ID.Bytes)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return dbq.Run{}, err
			}
		}
		if req.ResumeRunID != uuid.Nil {
			r, err := q.LockExecutionResume(ctx, dbq.LockExecutionResumeParams{ID: pgID(req.ResumeRunID), AgentID: agent.ID, ConversationID: params.ConversationID})
			if err != nil {
				if !errors.Is(err, pgx.ErrNoRows) {
					return dbq.Run{}, err
				}
				return dbq.Run{}, service.ErrConflict
			}
			prior, err := q.GetRunOrigin(ctx, r.ID)
			if err != nil {
				return dbq.Run{}, err
			}
			if !sameAuthority(prior, params) {
				return dbq.Run{}, service.ErrForbidden
			}
			claims, err := auth.RestoreRunIdentity(ctx, q, uuid.UUID(r.ID.Bytes))
			if err != nil {
				return dbq.Run{}, err
			}
			originalAccess, err := Access(ctx, q, authz.PrincipalFromClaims(claims), req.AgentID)
			if err != nil {
				return dbq.Run{}, err
			}
			// Confirmation authorizes the response, not a new credential or grant.
			o = prior
			if !authz.AccessAtLeast(originalAccess, access) {
				access = originalAccess
			}
			if !authz.AccessAtLeast(agentsdk.Access(r.CallerAccess), access) {
				access = agentsdk.Access(r.CallerAccess)
			}
			var checkpoint struct {
				RuntimeVersion    int `json:"runtimeVersion"`
				SuspensionContext struct {
					Reason string `json:"reason"`
				} `json:"suspensionContext"`
			}
			if json.Unmarshal(r.Checkpoint, &checkpoint) != nil || checkpoint.RuntimeVersion != 1 || checkpoint.SuspensionContext.Reason != "permission" {
				return dbq.Run{}, service.ErrConflict
			}
			if n, err := q.ClaimExecutionResume(ctx, r.ID); err != nil {
				return dbq.Run{}, err
			} else if n != 1 {
				return dbq.Run{}, service.ErrConflict
			}
		}
	} else if req.ResumeRunID != uuid.Nil {
		return dbq.Run{}, service.ErrInvalidInput
	}
	if !o.ID.Valid {
		o, err = q.CreateExecutionOrigin(ctx, params)
		if err != nil {
			return dbq.Run{}, err
		}
	}
	trigger := string(req.Kind)
	if req.Kind == Tool {
		trigger = "mcp"
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{AgentID: agent.ID, OriginID: o.ID, ExecutionKind: string(req.Kind), ResumeRunID: pgID(req.ResumeRunID), CallerUserID: o.UserID, CallerConversationID: o.ConversationID, BridgeID: o.BridgeID, CallerAccess: string(access), InputPayload: req.Input, SourceRef: agent.SourceRef, TriggerType: trigger, TriggerRef: req.Ref})
	if err != nil {
		return dbq.Run{}, err
	}
	if req.Kind == Prompt {
		token := pgID(uuid.New())
		if n, err := q.AcquireConversationRunLease(ctx, dbq.AcquireConversationRunLeaseParams{ConversationID: o.ConversationID, RunID: run.ID, OwnerToken: token}); err != nil {
			return dbq.Run{}, err
		} else if n != 1 {
			return dbq.Run{}, service.ErrConflict
		}
		run.RuntimeOwnerToken = token
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.Run{}, err
	}
	return run, nil
}

func sameAuthority(a dbq.ExecutionOrigin, b dbq.CreateExecutionOriginParams) bool {
	return a.Actor == b.Actor && a.Ingress == b.Ingress && a.CredentialProfile == b.CredentialProfile && a.UserID == b.UserID && a.SessionID == b.SessionID && a.AuthEpoch == b.AuthEpoch && a.ClientID == b.ClientID && a.Audience == b.Audience && a.Scope == b.Scope && a.CredentialAgentID == b.CredentialAgentID && a.AgentID == b.AgentID && a.BridgeID == b.BridgeID && a.PlatformIdentityID == b.PlatformIdentityID && a.SenderID == b.SenderID && a.ChatID == b.ChatID && a.ConversationID == b.ConversationID
}

// Resolve rechecks live credential state and current grants from immutable origin.
func Resolve(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID) (Context, error) {
	var out Context
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(runID), AgentID: pgID(agentID)})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err != nil || run.Status != "running" {
		return out, service.ErrConflict
	}
	if owner, ok := ctx.Value(runtimeOwnerKey{}).(runtimeOwner); ok && (owner.runID != runID || run.RuntimeOwnerToken != pgID(owner.token)) {
		return out, service.ErrConflict
	}
	if run.RuntimeOwnerToken.Valid {
		live, err := q.IsRuntimeLeaseLive(ctx, dbq.IsRuntimeLeaseLiveParams{RunID: run.ID, OwnerToken: run.RuntimeOwnerToken})
		if err != nil {
			return out, err
		}
		if !live {
			return out, service.ErrConflict
		}
	}
	o, err := q.GetRunOrigin(ctx, run.ID)
	if err != nil {
		return out, err
	}
	if o.AgentID != run.AgentID || o.Actor == "unknown" {
		return out, service.ErrUnauthorized
	}
	access := agentsdk.AccessPublic
	p := authz.AnonymousPrincipal()
	var email, name string
	switch o.Actor {
	case "user":
		claims, err := auth.RestoreRunIdentity(ctx, q, runID)
		if err != nil {
			return out, err
		}
		p = authz.PrincipalFromClaims(claims)
		if run.ExecutionKind == string(Job) && claims.Identity() == nil {
			// Durable authorization is a per-operation database decision, never
			// a reconstructed transferable browser or OAuth credential.
			p = authz.UserPrincipal(uuid.UUID(o.UserID.Bytes), auth.Role(claims.TenantRole))
		}
		email, name = claims.Email, claims.DisplayName
		if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, agentID); err != nil {
			return out, err
		}
		var granted bool
		access, granted, err = p.EffectiveAgentAccessChecked(ctx, q, agentID)
		if err != nil {
			return out, err
		}
		if !granted && o.Ingress != "route" {
			return out, errors.Join(auth.ErrRunAuthorityRevoked, service.ErrForbidden)
		}
	case "anonymous":
		if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, agentID); err != nil {
			return out, err
		}
		a, err := q.GetAgentByID(ctx, run.AgentID)
		if err != nil {
			return out, err
		}
		if o.Ingress == "mcp" && (!a.McpEnabled || !a.AllowPublicMcp) || o.Ingress == "route" && !a.AllowPublicRoutes {
			return out, service.ErrForbidden
		}
	case "app":
		a, err := q.GetAgentByID(ctx, run.AgentID)
		if err != nil {
			return out, err
		}
		if a.Status != "active" && a.Status != "building" {
			return out, errors.Join(auth.ErrRunAuthorityRevoked, service.ErrForbidden)
		}
		if run.ExecutionKind != string(Job) && run.ExecutionKind != string(Agent) && a.AgentTokenVersion != o.RuntimeGeneration.Int64 {
			return out, service.ErrUnauthorized
		}
		p, access = authz.TriggerPrincipal(), agentsdk.AccessAdmin
		if run.ExecutionKind == string(Agent) {
			p, err = authz.AppRunPrincipal(ctx, q, agentID, runID)
			if err != nil {
				return out, err
			}
		}
	default:
		return out, service.ErrUnauthorized
	}
	if !authz.AccessAtLeast(agentsdk.Access(run.CallerAccess), access) {
		access = agentsdk.Access(run.CallerAccess)
	}
	if !authz.AccessAtLeast(access, agentsdk.AccessPublic) {
		return out, service.ErrForbidden
	}
	if run.ExecutionKind == string(Route) {
		required, err := q.GetExecutionRouteAccess(ctx, dbq.GetExecutionRouteAccessParams{AgentID: run.AgentID, RouteRef: run.TriggerRef})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		if err != nil || !authz.AccessAtLeast(access, agentsdk.Access(required)) {
			return out, service.ErrForbidden
		}
		a, err := q.GetAgentByID(ctx, run.AgentID)
		if err != nil {
			return out, err
		}
		if !a.AllowPublicRoutes && !authz.AccessAtLeast(access, agentsdk.AccessUser) {
			return out, service.ErrForbidden
		}
	}
	if run.ExecutionKind == string(Tool) && o.Ingress == "mcp" {
		a, err := q.GetAgentByID(ctx, run.AgentID)
		if err != nil {
			return out, err
		}
		if !a.McpEnabled {
			return out, service.ErrForbidden
		}
		tools, err := q.ListAgentTools(ctx, run.AgentID)
		if err != nil {
			return out, err
		}
		allowed := false
		for _, t := range tools {
			if t.Name == run.TriggerRef && authz.AccessAtLeast(access, agentsdk.Access(t.Access)) {
				allowed = true
			}
		}
		if !allowed {
			return out, service.ErrForbidden
		}
	}
	caller := wire.Caller{Kind: o.Actor, Access: wire.Access(access)}
	if o.Actor == "app" {
		caller.Kind = "application"
	}
	if o.Actor == "user" {
		user := wire.CallerUser{ID: optionalID(o.UserID), Email: email, DisplayName: name, PlatformMember: true}
		initiator := user
		caller.User, caller.Initiator = &user, &initiator
	}
	switch o.Ingress {
	case "route", "webhook":
		caller.Origin.Interface = "http"
	case "web", "bridge":
		caller.Origin.Interface = "chat"
	case "mcp":
		caller.Origin.Interface = "mcp"
	case "cron":
		caller.Origin.Interface = "schedule"
	case "app":
		caller.Origin.Interface = "application"
	default:
		return out, service.ErrUnauthorized
	}
	if o.Ingress == "bridge" {
		caller.Origin.Platform = "telegram"
	}
	if o.CredentialProfile == "oauth_mcp" {
		caller.Origin.ClientID = o.ClientID.String
	}
	switch Kind(run.ExecutionKind) {
	case Prompt, Tool, Route, Webhook:
		caller.Origin.Execution = "request"
	case Job:
		caller.Origin.Execution = "job"
	case App, Agent:
		caller.Origin.Execution = "background"
	default:
		return out, service.ErrUnauthorized
	}
	if err := caller.Validate(); err != nil {
		return out, err
	}
	runtime := wire.RuntimeContext{AgentID: agentID.String(), RunID: runID.String(), ConversationID: optionalID(o.ConversationID), BridgeID: optionalID(o.BridgeID), Caller: caller}
	if run.ExecutionKind == string(Agent) {
		call, err := q.GetAgentTaskCall(ctx, run.ID)
		if err != nil {
			return out, err
		}
		runtime.Definition = &wire.RuntimeAgentDefinition{Slug: call.Definition, ContractHash: call.ContractHash}
	}
	if run.ExecutionKind == string(Job) {
		a, err := q.GetExecutionJobAttempt(ctx, run.ID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return out, err
			}
			return out, service.ErrConflict
		}
		runtime.Job = &wire.RuntimeJobContext{ID: uuid.UUID(a.JobID.Bytes).String(), Attempt: int(a.AttemptNumber), LeaseToken: uuid.UUID(a.LeaseToken.Bytes).String()}
	}
	out = Context{Run: run, Origin: o, Principal: p, Runtime: runtime}
	return out, nil
}

func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
func optionalID(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}
func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }
func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}
