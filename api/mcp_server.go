package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/trigger"
	"github.com/airlockrun/goai/mcp"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// jsonrpcMessage is the JSON-RPC 2.0 envelope used by MCP over HTTP.
// Either id+method (request), id+result/error (response), or just
// method (notification, no id).
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP JSON-RPC error codes. -32602 = Invalid params (we use it to
// merge "not found" with "no access" so attackers can't enumerate the
// conversation / run namespace). -32000 = Server error (our timeout).
const (
	rpcErrParse          = -32700
	rpcErrInvalidRequest = -32600
	rpcErrMethodNotFound = -32601
	rpcErrInvalidParams  = -32602
	rpcErrInternal       = -32603
	rpcErrServerError    = -32000
)

// MCPServer is the JSON-RPC 2.0 server exposed at
// /api/agent/{identifier}/mcp. Each Airlock agent becomes an MCP
// server: its registered tools surface plus a built-in `prompt`
// meta-tool that drives the agent's full LLM loop.
type MCPServer struct {
	dispatcher *trigger.Dispatcher
	pubsub     *realtime.PubSub
	logger     *zap.Logger
}

// NewMCPServer wires the MCP handler to its dependencies. Mounted at
// POST /api/agent/{identifier}/mcp by router.go. pubsub is required:
// when an A2A child run streams its events back through here, the
// MCP server also mirrors them to the parent agent's WS topic with a
// SubagentInfo tag so the parent's chat UI shows sub-run progress.
func NewMCPServer(dispatcher *trigger.Dispatcher, pubsub *realtime.PubSub, logger *zap.Logger) *MCPServer {
	if dispatcher == nil {
		panic("api: NewMCPServer: dispatcher is required")
	}
	if pubsub == nil {
		panic("api: NewMCPServer: pubsub is required")
	}
	if logger == nil {
		panic("api: NewMCPServer: logger is required")
	}
	return &MCPServer{dispatcher: dispatcher, pubsub: pubsub, logger: logger}
}

// ServeHTTP handles one JSON-RPC message. Notification methods (no
// id) get a 202 with no body; request methods return either a single
// JSON-RPC response (most methods) or an SSE stream of notifications
// terminated by a final response (the `prompt` meta-tool).
//
// The handler reads its dependencies — DB pool, JWT secret — from
// the agentHandler stored on the request via a closure in router.go.
func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request, h *agentHandler) {
	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	identifier := chi.URLParam(r, "identifier")
	target, err := resolveAgent(ctx, q, identifier)
	if err != nil {
		writeJSONRPCError(w, nil, rpcErrInvalidParams, "agent not found")
		return
	}

	// Resolve the caller principal from headers BEFORE access checks
	// so we can return the right HTTP status (401 vs 403) and emit the
	// MCP-spec WWW-Authenticate handshake on missing/bad credentials.
	principal, principalErr := resolvePrincipal(ctx, r, q, h.jwtSecret, uuid.UUID(target.ID.Bytes), h.publicURL)
	if principalErr != nil {
		writeMCPAuthError(w, h.publicURL, identifier, principalErr)
		return
	}

	// The protected /mcp endpoint never serves anon — public access
	// has its own /public-mcp route. An anon principal here means
	// "no bearer presented"; convert to the OAuth-spec 401 handshake.
	if principal.Kind == MCPPrincipalAnon {
		writeMCPAuthError(w, h.publicURL, identifier, errInvalidToken)
		return
	}

	access, err := computeA2ACallerAccess(ctx, q, target, principal)
	if err != nil {
		switch {
		case errors.Is(err, ErrMCPUnauthenticated):
			writeMCPAuthError(w, h.publicURL, identifier, errInvalidToken)
		case errors.Is(err, ErrMCPForbidden):
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		default:
			s.logger.Error("mcp access check", zap.Error(err))
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		}
		return
	}

	s.serveDispatch(w, r, h, q, target, access, principal)
}

// serveDispatch is the JSON-RPC parse + method dispatch loop shared
// between the protected /mcp route (ServeHTTP) and the no-auth
// /public-mcp route (ServePublicHTTP). By this point the caller has
// already been resolved to a principal and access tier.
func (s *MCPServer) serveDispatch(w http.ResponseWriter, r *http.Request, h *agentHandler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal) {
	ctx := r.Context()

	// 16 MiB ceiling: large enough for `tools/call` requests that carry
	// inline base64 file uploads (capped at maxInlineResourceBytes = 10
	// MiB raw, ~13.4 MiB after b64) plus envelope overhead. Other
	// JSON-RPC methods are tiny — a uniform cap is simpler than peeking
	// at `method` to decide.
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeJSONRPCError(w, nil, rpcErrParse, "read body")
		return
	}
	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil || msg.JSONRPC != "2.0" {
		writeJSONRPCError(w, nil, rpcErrParse, "invalid JSON-RPC envelope")
		return
	}

	switch msg.Method {
	case "initialize":
		s.handleInitialize(w, msg)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "notifications/cancelled":
		s.handleCancelled(msg)
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.handleToolsList(ctx, w, q, target, access, msg)
	case "tools/call":
		s.handleToolsCall(ctx, w, r, h, q, target, access, principal, msg)
	case "resources/list":
		s.handleResourcesList(ctx, w, h, q, target, access, msg)
	case "resources/read":
		s.handleResourcesRead(ctx, w, h, q, target, access, msg)
	case "resources/templates/list":
		s.handleResourcesTemplatesList(ctx, w, q, target, access, msg)
	default:
		writeJSONRPCError(w, msg.ID, rpcErrMethodNotFound, "unknown method: "+msg.Method)
	}
}

// resolveAgent accepts the identifier as a UUID or a slug. Internal
// callers (sibling agents) use the UUID — rename-safe. External
// clients pasting a config URL typically use the slug. Either form
// resolves to the same dbq.Agent row.
func resolveAgent(ctx context.Context, q *dbq.Queries, identifier string) (dbq.Agent, error) {
	if id, err := uuid.Parse(identifier); err == nil {
		return q.GetAgentByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
	}
	return q.GetAgentBySlug(ctx, identifier)
}

// resolvePrincipal classifies the request by the Authorization header.
// Returns:
//   - Anon (no header) — the protected /mcp handler converts this to a
//     401 + WWW-Authenticate handshake; the /public-mcp handler accepts
//     it as-is.
//   - Agent JWT → MCPPrincipalAgent (A2A path; X-Run-ID required).
//   - OAuth access token (JWT with client_id claim) → MCPPrincipalOAuthClient.
//     Audience binding (aud == this agent's canonical resource URL) is
//     verified here so the MCP handler's access-ladder code stays
//     unchanged. Mandatory `mcp` scope check.
//   - Plain user JWT → MCPPrincipalUser (web SPA path, unchanged).
//
// targetAgentID is the agent the request is hitting; needed for the
// OAuth audience check. publicURL is the canonical origin used to
// build the audience.
func resolvePrincipal(ctx context.Context, r *http.Request, q *dbq.Queries, jwtSecret string, targetAgentID uuid.UUID, publicURL string) (MCPPrincipal, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return MCPPrincipal{Kind: MCPPrincipalAnon}, nil
	}
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || token == "" {
		return MCPPrincipal{}, errors.New("invalid Authorization header")
	}

	// Try agent token first — agent JWTs carry an agent_id claim and
	// ValidateAgentToken is strict; anything else falls through.
	if claims, err := auth.ValidateAgentToken(jwtSecret, token); err == nil {
		callerAgentID, err := uuid.Parse(claims.AgentID)
		if err != nil {
			return MCPPrincipal{}, errors.New("invalid agent claim")
		}
		runIDStr := r.Header.Get("X-Run-ID")
		if runIDStr == "" {
			return MCPPrincipal{}, errors.New("agent JWT requires X-Run-ID header")
		}
		parentRunID, err := uuid.Parse(runIDStr)
		if err != nil {
			return MCPPrincipal{}, errors.New("invalid X-Run-ID")
		}
		run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: parentRunID, Valid: true})
		if err != nil || uuid.UUID(run.AgentID.Bytes) != callerAgentID {
			return MCPPrincipal{}, errors.New("X-Run-ID not accessible")
		}
		userID, err := chaseOriginalUser(ctx, q, run)
		if err != nil {
			return MCPPrincipal{}, errors.New("X-Run-ID not accessible")
		}
		return MCPPrincipal{
			Kind:          MCPPrincipalAgent,
			UserID:        userID,
			CallerAgentID: callerAgentID,
			ParentRunID:   parentRunID,
		}, nil
	}

	// Parse as a user/OAuth JWT — the wire shape is the same; the
	// presence of the ClientID claim picks OAuth, absence picks the
	// legacy web-login path. See auth/jwt.go for the invariant.
	claims, err := auth.ValidateToken(jwtSecret, token)
	if err != nil {
		return MCPPrincipal{}, errInvalidToken
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return MCPPrincipal{}, errors.New("invalid user claim")
	}

	if claims.ClientID != "" {
		// OAuth access token. Audience MUST be the canonical URL for
		// THIS agent — `aud` reflects the agent the token was issued
		// for. Scope must include `mcp`.
		canonAud := fmt.Sprintf("%s/api/agent/%s/mcp", strings.TrimRight(publicURL, "/"), targetAgentID.String())
		if !auth.AudienceContains(claims.Audience, canonAud) {
			return MCPPrincipal{}, errAudienceMismatch
		}
		if !auth.ScopeContains(claims.Scope, "mcp") {
			return MCPPrincipal{}, errInsufficientScope
		}
		// Client must still exist; a revoked-from-the-table client
		// fails closed.
		if _, err := q.GetOAuthClient(ctx, claims.ClientID); err != nil {
			return MCPPrincipal{}, errClientRevoked
		}
		return MCPPrincipal{
			Kind:     MCPPrincipalOAuthClient,
			UserID:   userID,
			ClientID: claims.ClientID,
		}, nil
	}

	// Plain user JWT (web SPA).
	return MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID}, nil
}

// Sentinel errors so the MCP handler can map each one to the
// appropriate WWW-Authenticate response (invalid_token vs.
// insufficient_scope) for OAuth-aware MCP clients.
var (
	errInvalidToken      = errors.New("invalid token")
	errAudienceMismatch  = errors.New("audience mismatch")
	errInsufficientScope = errors.New("insufficient scope")
	errClientRevoked     = errors.New("client revoked")
)

// writeMCPAuthError emits the RFC 9728 + OAuth 2.1 401 handshake an
// MCP client expects when its bearer is missing, invalid, or
// audience-/scope-mismatched. The `resource_metadata` URL echoes the
// identifier the client typed (slug or UUID) so the discovery flow
// keeps working through slug renames.
//
// errInsufficientScope is the only branch that returns 403; everything
// else is 401 so the client triggers the OAuth dance.
func writeMCPAuthError(w http.ResponseWriter, publicURL, identifier string, cause error) {
	publicURL = strings.TrimRight(publicURL, "/")
	resourceMeta := fmt.Sprintf("%s/.well-known/oauth-protected-resource/api/agent/%s/mcp", publicURL, identifier)
	errCode, errDesc, status := "invalid_token", "", http.StatusUnauthorized
	switch {
	case errors.Is(cause, errAudienceMismatch):
		errDesc = "audience mismatch"
	case errors.Is(cause, errInsufficientScope):
		errCode, errDesc, status = "insufficient_scope", "scope `mcp` required", http.StatusForbidden
	case errors.Is(cause, errClientRevoked):
		errDesc = "oauth client revoked"
	case cause != nil && cause != errInvalidToken:
		errDesc = cause.Error()
	}
	header := fmt.Sprintf(`Bearer realm="MCP", resource_metadata="%s", error="%s"`, resourceMeta, errCode)
	if errDesc != "" {
		header += fmt.Sprintf(`, error_description="%s"`, errDesc)
	}
	w.Header().Set("WWW-Authenticate", header)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + errCode + `"}`))
}

// ServePublicHTTP is the no-auth /public-mcp route. Mounted always;
// 404s unless the target agent has allow_public_mcp = true. Skips
// principal resolution entirely — every caller is Anon, which the
// access ladder maps to AccessPublic on agents that opted in.
func (s *MCPServer) ServePublicHTTP(w http.ResponseWriter, r *http.Request, h *agentHandler) {
	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	identifier := chi.URLParam(r, "identifier")
	target, err := resolveAgent(ctx, q, identifier)
	if err != nil {
		writeJSONRPCError(w, nil, rpcErrInvalidParams, "agent not found")
		return
	}
	if !target.AllowPublicMcp {
		http.NotFound(w, r)
		return
	}

	principal := MCPPrincipal{Kind: MCPPrincipalAnon}
	access, err := computeA2ACallerAccess(ctx, q, target, principal)
	if err != nil {
		// Should be unreachable given AllowPublicMcp above, but
		// fail closed if the access ladder rejects.
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	s.serveDispatch(w, r, h, q, target, access, principal)
}

// chaseOriginalUser walks up the parent_run_id chain to find the
// original (human) user. For top-level prompt runs the conversation
// carries user_id; for A2A child runs we recurse on parent_run_id.
// Bounded depth — abort after 16 hops as a defense against cycles
// (the schema doesn't enforce acyclicity).
func chaseOriginalUser(ctx context.Context, q *dbq.Queries, run dbq.Run) (uuid.UUID, error) {
	current := run
	for i := 0; i < 16; i++ {
		// For prompt runs the trigger_ref is the conversation id.
		if current.TriggerType == "prompt" || current.TriggerType == "a2a" {
			if current.TriggerRef != "" {
				if convID, err := uuid.Parse(current.TriggerRef); err == nil {
					conv, err := q.GetConversationByID(ctx, pgtype.UUID{Bytes: convID, Valid: true})
					if err == nil && conv.UserID.Valid {
						return uuid.UUID(conv.UserID.Bytes), nil
					}
				}
			}
		}
		// No conversation-derived user yet. If we have a parent run,
		// chase it; otherwise this run has no user (cron / webhook).
		if !current.ParentRunID.Valid {
			return uuid.Nil, errors.New("run has no original user")
		}
		parent, err := q.GetRunByID(ctx, current.ParentRunID)
		if err != nil {
			return uuid.Nil, err
		}
		current = parent
	}
	return uuid.Nil, errors.New("parent chain too deep")
}

func (s *MCPServer) handleInitialize(w http.ResponseWriter, msg jsonrpcMessage) {
	result, _ := json.Marshal(map[string]any{
		"protocolVersion": mcp.LatestProtocolVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"subscribe": false, "listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "airlock",
			"version": "1.0",
		},
	})
	writeJSONRPCResult(w, msg.ID, result)
}

func (s *MCPServer) handleCancelled(_ jsonrpcMessage) {
	// MCP `notifications/cancelled` carries `{requestId}` but our
	// run-cancel path keys on the HTTP connection closing, which fires
	// automatically when the JSON-RPC peer disconnects. The
	// notification is purely advisory.
}

func (s *MCPServer) handleToolsList(ctx context.Context, w http.ResponseWriter, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, msg jsonrpcMessage) {
	rows, err := q.ListAgentTools(ctx, target.ID)
	if err != nil {
		s.logger.Error("mcp: list agent tools", zap.Error(err), zap.String("agent_id", uuid.UUID(target.ID.Bytes).String()))
		writeJSONRPCError(w, msg.ID, rpcErrInternal, "list tools")
		return
	}
	type toolEntry struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	var tools []toolEntry
	for _, t := range rows {
		// Filter out tools the caller's access can't reach. Same rule
		// the system prompt applies, just enforced at the API edge so
		// external MCP clients see the same shape an embedded LLM does.
		if !accessSatisfies(string(access), t.Access) {
			continue
		}
		tools = append(tools, toolEntry{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	// Built-in `prompt` meta-tool. Available at every access level —
	// invoking it just funnels into the agent's normal prompt path,
	// which re-applies access on its own surface.
	tools = append(tools, toolEntry{
		Name:        "prompt",
		Description: "Send a natural-language prompt to this agent. The agent runs its own LLM loop and returns the final assistant message. Streams progress via notifications/progress over SSE.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string","description":"User-facing message"},"conversationId":{"type":"string","description":"Optional: continue an existing conversation"},"files":{"type":"array","items":{"type":"object","properties":{"path":{"type":"string"},"filename":{"type":"string"},"contentType":{"type":"string"},"size":{"type":"integer"}}}}},"required":["message"]}`),
	})
	result, _ := json.Marshal(map[string]any{"tools": tools})
	writeJSONRPCResult(w, msg.ID, result)
}

func (s *MCPServer) handleToolsCall(ctx context.Context, w http.ResponseWriter, r *http.Request, h *agentHandler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "decode params")
		return
	}

	switch params.Name {
	case "prompt":
		s.handlePromptCall(ctx, w, r, h, q, target, access, principal, msg, params.Arguments)
	default:
		s.handleUserToolCall(ctx, w, h, q, target, access, principal, msg, params.Name, params.Arguments)
	}
}

// handlePromptCall drives ForwardA2APrompt, opens an SSE stream, and
// translates the agent's NDJSON timeline into JSON-RPC
// notifications/progress messages. A final response (or error) lands
// on the same SSE channel when the run terminates.
func (s *MCPServer) handlePromptCall(ctx context.Context, w http.ResponseWriter, r *http.Request, h *agentHandler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage, args json.RawMessage) {
	// files: accept either legacy {path, filename, contentType, size}
	// (A2A caller / web-uploaded refs) or new inline {filename, mimeType,
	// data} (external MCP uploads). Discriminate by presence of `data`.
	var promptArgs struct {
		Message        string            `json:"message"`
		ConversationID string            `json:"conversationId,omitempty"`
		Files          []json.RawMessage `json:"files,omitempty"`
	}
	if err := json.Unmarshal(args, &promptArgs); err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "decode prompt args")
		return
	}
	if promptArgs.Message == "" {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "message is required")
		return
	}

	// Materialization happens after conversation validation below so we
	// can scope inbound files by conv-{id} when a valid conversation is
	// in play. Files placeholder for the post-validation call site.
	var files []agentsdk.FileInfo

	// Cron / webhook agents can't A2A in v1 — no original user.
	if principal.Kind == MCPPrincipalAgent && principal.UserID == uuid.Nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "agent caller has no original user (cron/webhook can't A2A)")
		return
	}

	// If the caller continues an existing conversation, verify access
	// to it. Merge "doesn't exist" and "not accessible" into one
	// error (don't leak existence).
	if promptArgs.ConversationID != "" {
		convID, err := uuid.Parse(promptArgs.ConversationID)
		if err != nil {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "invalid conversationId format")
			return
		}
		conv, err := q.GetConversationByID(ctx, pgtype.UUID{Bytes: convID, Valid: true})
		if err != nil || uuid.UUID(conv.AgentID.Bytes) != uuid.UUID(target.ID.Bytes) {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "conversationId not accessible")
			return
		}
		// Conversation user must match the principal's user (or be
		// non-member-open). We piggy-back on the access decision: if
		// the conv owner != caller, the caller would need member
		// access to the agent to peek — which is what `access` checks.
		if conv.UserID.Valid && principal.UserID != uuid.Nil && uuid.UUID(conv.UserID.Bytes) != principal.UserID {
			if access != agentsdk.AccessAdmin && access != agentsdk.AccessUser {
				writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "conversationId not accessible")
				return
			}
		}
	}

	// Pick the inbound-file scope: conv-<id> when a validated
	// conversation is in play (prompt continuity across A2A turns),
	// else fall through to caller-run scope. Materialize now that we
	// know which scope key to use.
	scopeKey := scopeKeyForCaller(principal)
	if promptArgs.ConversationID != "" {
		scopeKey = scopeKeyForConversation(promptArgs.ConversationID)
	}
	var mErr *materializeError
	files, mErr = s.materializePromptFiles(ctx, h, q, target, principal, scopeKey, promptArgs.Files)
	if mErr != nil {
		writeJSONRPCError(w, msg.ID, mErr.Code, mErr.Message)
		return
	}

	// Build PromptInput. CallerAccess and VisibleSiblings are filled
	// by ForwardA2APrompt; we just supply the message + files.
	input := agentsdk.PromptInput{
		Message:        promptArgs.Message,
		ConversationID: promptArgs.ConversationID,
		Files:          files,
	}

	// parentRunID is the caller's X-Run-ID for agent principals; for
	// user / anon callers there is no parent run, so we synthesize a
	// uuid.Nil (ForwardA2APrompt then plumbs NULL parent_run_id; the
	// run is top-level from airlock's POV).
	parentRunID := principal.ParentRunID

	// Original user — anchor for sibling visibility on the target.
	var userID *uuid.UUID
	if principal.UserID != uuid.Nil {
		u := principal.UserID
		userID = &u
	}

	// Bridge timeouts: the chat-prompt context timeout is the cap on
	// any A2A prompt as well. Bound the underlying ctx so even if the
	// caller hangs, the server eventually surrenders the run.
	timeout := trigger.PromptHTTPCeiling
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rc, runID, err := s.dispatcher.ForwardA2APrompt(cctx, uuid.UUID(target.ID.Bytes), parentRunID, access, userID, input)
	if err != nil {
		s.logger.Error("mcp: forward prompt",
			zap.Error(err),
			zap.String("agent_id", uuid.UUID(target.ID.Bytes).String()),
			zap.String("agent_slug", target.Slug),
			zap.Int("principal_kind", int(principal.Kind)),
		)
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "forward prompt: "+err.Error())
		return
	}
	defer rc.Close()

	// Build parentInfo so each NDJSON event from the child run also
	// mirrors onto the parent's WS topic with a SubagentInfo tag —
	// powering the parent's chat UI sub-run-progress card. Only
	// applicable when an agent (not user) is calling: agent
	// principals have a ParentRunID; user / anon principals do not.
	var parentInfo *ParentRunInfo
	if principal.Kind == MCPPrincipalAgent && principal.ParentRunID != uuid.Nil {
		parentRun, perr := q.GetRunByID(cctx, pgtype.UUID{Bytes: principal.ParentRunID, Valid: true})
		if perr == nil {
			parentConvID := ""
			if parentRun.TriggerType == "prompt" || parentRun.TriggerType == "a2a" {
				parentConvID = parentRun.TriggerRef
			}
			parentInfo = &ParentRunInfo{
				AgentID:        uuid.UUID(parentRun.AgentID.Bytes),
				ConvID:         parentConvID,
				UserID:         principal.UserID.String(),
				ChildAgentID:   uuid.UUID(target.ID.Bytes),
				ChildRunID:     runID,
				ChildAgentSlug: target.Slug,
			}
		}
	}

	// Resolve the child run's conversation user for the on-topic
	// envelope's UserID. Defaults to the principal user — A2A child
	// conversations propagate user_id from the parent's user via the
	// dispatcher, so the principal user is correct.
	childUserID := principal.UserID.String()

	// SSE response from here on — translate NDJSON timeline events
	// into MCP notifications/progress and a final result.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	// Watch for caller disconnect — closing the HTTP connection (or
	// the caller's own run getting cancelled, which propagates via
	// context.Cancel into its outbound request) closes this writer's
	// ctx.Done. We then call CancelRun on the child to cascade the
	// cancel down the chain.
	go func() {
		<-cctx.Done()
		s.dispatcher.CancelRun(runID)
	}()

	// mirror is the WS-publish twin of the SSE-translate path below.
	// Each agent NDJSON event we surface to the caller also publishes
	// to the child agent's topic (gated by the original user) and, if
	// this is an A2A child of another agent's run, to the parent
	// agent's topic with a SubagentInfo tag.
	childTopic := uuid.UUID(target.ID.Bytes)
	mirror := func(eventType string, payload proto.Message) {
		env := realtime.NewEnvelopeForUser(eventType, childTopic.String(), childUserID, promptArgs.ConversationID, payload)
		_ = s.pubsub.Publish(cctx, childTopic, env)
		if parentInfo != nil {
			parentEnv := realtime.NewEnvelopeForUser(eventType, parentInfo.AgentID.String(), parentInfo.UserID, parentInfo.ConvID, payload).
				WithSubagent(realtime.SubagentInfo{
					AgentID: parentInfo.ChildAgentID.String(),
					RunID:   parentInfo.ChildRunID.String(),
					Slug:    parentInfo.ChildAgentSlug,
				})
			_ = s.pubsub.Publish(cctx, parentInfo.AgentID, parentEnv)
		}
	}

	// run.started — emitted up-front so the parent's chat UI can show
	// the sub-run card before the first text-delta lands.
	mirror("run.started", &airlockv1.RunStartedEvent{
		RunId:          runID.String(),
		AgentId:        uuid.UUID(target.ID.Bytes).String(),
		ConversationId: promptArgs.ConversationID,
	})

	progressToken := msg.ID
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var finalText strings.Builder
	var finalErr string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var evt struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data,omitempty"`
		}
		raw := json.RawMessage(line)
		if err := json.Unmarshal(raw, &evt); err != nil {
			continue
		}
		switch evt.Type {
		case "text-delta", "text_delta":
			var d struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(evt.Data, &d)
			finalText.WriteString(d.Text)
			sendSSE(w, flusher, "notifications/progress", map[string]any{
				"progressToken": progressToken,
				"message":       d.Text,
			})
			mirror("run.text_delta", &airlockv1.TextDeltaEvent{
				RunId: runID.String(),
				Text:  d.Text,
			})
		case "tool-call", "tool_call":
			var tc struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Input      json.RawMessage `json:"input"`
			}
			_ = json.Unmarshal(evt.Data, &tc)
			sendSSE(w, flusher, "notifications/progress", map[string]any{
				"progressToken": progressToken,
				"event":         raw,
			})
			mirror("run.tool_call", &airlockv1.ToolCallEvent{
				RunId:      runID.String(),
				ToolCallId: tc.ToolCallID,
				ToolName:   tc.ToolName,
				Input:      string(tc.Input),
			})
		case "tool-result", "tool_result":
			var tr struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Output     json.RawMessage `json:"output"`
			}
			_ = json.Unmarshal(evt.Data, &tr)
			sendSSE(w, flusher, "notifications/progress", map[string]any{
				"progressToken": progressToken,
				"event":         raw,
			})
			mirror("run.tool_result", &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: tr.ToolCallID,
				ToolName:   tr.ToolName,
				Output:     string(tr.Output),
			})
		case "error":
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(evt.Data, &e)
			finalErr = e.Error
			mirror("run.error", &airlockv1.RunErrorEvent{
				RunId: runID.String(),
				Error: e.Error,
			})
		case "complete", "finish", "run.complete":
			mirror("run.complete", &airlockv1.RunCompleteEvent{
				RunId: runID.String(),
			})
		}
	}

	// Bound timeout outcome: ctx done before the agent finished. Emit
	// the timeout error and ensure the run is cancelled. The disconnect
	// goroutine above already does the cancel; we just emit the error.
	if cctx.Err() != nil && finalErr == "" {
		finalErr = "task exceeded sync timeout; cancelled"
	}

	if finalErr != "" {
		writeSSEJSONRPCError(w, flusher, msg.ID, rpcErrServerError, finalErr)
		return
	}
	resultPayload, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{
			"type": "text",
			"text": finalText.String(),
		}},
		"isError": false,
	})
	writeSSEJSONRPCResult(w, flusher, msg.ID, resultPayload)
}

// handleUserToolCall forwards a user-registered tool call to the
// agent container's /__air/tool/{name} endpoint. Single inline JSON
// response, no SSE — user tools are short-running by design.
//
// Boundary materializer runs before forwarding (rewriting FilePath
// args: cross-bucket copy for A2A, base64-to-S3 for external) and
// after the agent responds (rewriting FilePath results: cross-bucket
// copy for A2A, resource_link content blocks for external).
func (s *MCPServer) handleUserToolCall(ctx context.Context, w http.ResponseWriter, h *agentHandler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage, name string, args json.RawMessage) {
	// Load this tool's input/output schemas + the caller's slug (for
	// A2A outbound a2a/{slug}/ destinations). We could cache these per
	// (agentID, toolName) but per-call DB hits are cheap and the freshness
	// guarantees something is genuinely loaded.
	var inSchema, outSchema []byte
	var callerSlug string
	tools, terr := q.ListAgentTools(ctx, target.ID)
	if terr == nil {
		for _, t := range tools {
			if t.Name == name {
				inSchema = t.InputSchema
				outSchema = t.OutputSchema
				break
			}
		}
	}
	if principal.Kind == MCPPrincipalAgent && principal.CallerAgentID != uuid.Nil {
		if caller, err := q.GetAgentByID(ctx, toPgUUID(principal.CallerAgentID)); err == nil {
			callerSlug = caller.Slug
		}
	}
	// Non-prompt tool calls scope inbound files by the caller's run ID
	// (the run on whose behalf this tool fires). prompt() picks
	// conv-scope when a conversation is in play — see handlePromptCall.
	scopeKey := scopeKeyForCaller(principal)
	rc := newRewriterCtx(ctx, h.s3, s.logger, target, principal, callerSlug, scopeKey)

	// Inbound: rewrite agent-file args for cross-bucket / inline upload.
	if rew, mErr := materializeInbound(rc, args, inSchema); mErr != nil {
		writeJSONRPCError(w, msg.ID, mErr.Code, mErr.Message)
		return
	} else {
		args = rew
	}

	c, err := s.dispatcher.EnsureRunning(ctx, uuid.UUID(target.ID.Bytes))
	if err != nil {
		s.logger.Error("mcp: ensure running",
			zap.Error(err),
			zap.String("agent_id", uuid.UUID(target.ID.Bytes).String()),
			zap.String("tool", name),
		)
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "ensure running: "+err.Error())
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/__air/tool/"+name, bytes.NewReader(args))
	if err != nil {
		s.logger.Error("mcp: build tool request", zap.Error(err), zap.String("tool", name))
		writeJSONRPCError(w, msg.ID, rpcErrInternal, "build tool request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Caller-Access", string(access))
	if principal.ParentRunID != uuid.Nil {
		req.Header.Set("X-Parent-Run-ID", principal.ParentRunID.String())
	}
	if principal.UserID != uuid.Nil {
		req.Header.Set("X-User-ID", principal.UserID.String())
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("mcp: tool dispatch",
			zap.Error(err),
			zap.String("agent_id", uuid.UUID(target.ID.Bytes).String()),
			zap.String("tool", name),
		)
		writeJSONRPCError(w, msg.ID, rpcErrServerError, "tool dispatch: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode == http.StatusNotFound {
		writeJSONRPCError(w, msg.ID, rpcErrMethodNotFound, "unknown tool: "+name)
		return
	}
	if resp.StatusCode >= 400 {
		// Agent itself returned 4xx/5xx (e.g. tool panicked, access
		// denied at the agent layer). Warn — it's not airlock that's
		// broken, but operators want visibility into agent-side failures.
		s.logger.Warn("mcp: agent tool error",
			zap.Int("status", resp.StatusCode),
			zap.String("agent_id", uuid.UUID(target.ID.Bytes).String()),
			zap.String("tool", name),
			zap.ByteString("body", body),
		)
		writeJSONRPCError(w, msg.ID, rpcErrServerError, fmt.Sprintf("agent returned %d: %s", resp.StatusCode, body))
		return
	}

	// Outbound: rewrite agent-file results. For A2A, paths are rewritten
	// in-place in the JSON body. For external, the path stays but
	// rc.extraContent gains a resource_link block per FilePath.
	if rew, mErr := materializeOutbound(rc, body, outSchema); mErr != nil {
		writeJSONRPCError(w, msg.ID, mErr.Code, mErr.Message)
		return
	} else {
		body = rew
	}

	contentBlocks := []map[string]any{{"type": "text", "text": string(body)}}
	contentBlocks = append(contentBlocks, rc.extraContent...)
	resultPayload, _ := json.Marshal(map[string]any{
		"content": contentBlocks,
		"isError": false,
	})
	writeJSONRPCResult(w, msg.ID, resultPayload)
}

// accessSatisfies mirrors the prompt-side rank logic: admin > user >
// public > "". A caller at level c can see surface registered at
// level r when rank(c) >= rank(r). Empty caller treated as admin
// (matches prompt rendering's "" semantics).
func accessSatisfies(caller, required string) bool {
	rank := func(s string) int {
		switch s {
		case "admin":
			return 3
		case "user":
			return 2
		case "public":
			return 1
		case "":
			return 3
		}
		return -1
	}
	return rank(caller) >= rank(required)
}

// --- JSON-RPC + SSE wire helpers ---

func writeJSONRPCResult(w http.ResponseWriter, id json.RawMessage, result json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := jsonrpcMessage{JSONRPC: "2.0", ID: id, Result: result}
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := jsonrpcMessage{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: message}}
	_ = json.NewEncoder(w).Encode(resp)
}

func sendSSE(w http.ResponseWriter, flusher http.Flusher, method string, params any) {
	msg := jsonrpcMessage{JSONRPC: "2.0", Method: method}
	if params != nil {
		raw, _ := json.Marshal(params)
		msg.Params = raw
	}
	payload, _ := json.Marshal(msg)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
	if flusher != nil {
		flusher.Flush()
	}
}

func writeSSEJSONRPCResult(w http.ResponseWriter, flusher http.Flusher, id json.RawMessage, result json.RawMessage) {
	msg := jsonrpcMessage{JSONRPC: "2.0", ID: id, Result: result}
	payload, _ := json.Marshal(msg)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
	if flusher != nil {
		flusher.Flush()
	}
}

func writeSSEJSONRPCError(w http.ResponseWriter, flusher http.Flusher, id json.RawMessage, code int, message string) {
	msg := jsonrpcMessage{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: message}}
	payload, _ := json.Marshal(msg)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
	if flusher != nil {
		flusher.Flush()
	}
}

// Compile-time guard against unused imports (convert + time are used
// in helpers that may be inlined; keep visible so a refactor that
// trims them throws a build error rather than silent drift).
var _ = convert.PgUUIDToString
var _ = time.Second
