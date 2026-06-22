package agentapi

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
	"github.com/airlockrun/airlock/service"
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
// the Handler stored on the request via a closure in router.go.
func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request, h *Handler) {
	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	identifier := chi.URLParam(r, "identifier")
	target, err := resolveAgent(ctx, q, identifier)
	if err != nil {
		writeJSONRPCError(w, nil, rpcErrInvalidParams, "agent not found")
		return
	}
	// mcp_enabled is the master switch: a disabled MCP surface 404s for
	// every caller (members and A2A included).
	if !target.McpEnabled {
		http.NotFound(w, r)
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
func (s *MCPServer) serveDispatch(w http.ResponseWriter, r *http.Request, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal) {
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
		s.handleInitialize(w, target, msg)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "notifications/cancelled":
		s.handleCancelled(msg)
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.handleToolsList(ctx, w, q, target, access, principal, msg)
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

// resolveAgent is kept as a package-local thin alias for readability at
// the call sites — delegates to service.ResolveAgent, the canonical
// slug-or-UUID resolver shared with the OAuth server handler.
func resolveAgent(ctx context.Context, q *dbq.Queries, identifier string) (dbq.Agent, error) {
	return service.ResolveAgent(ctx, q, identifier)
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
func (s *MCPServer) ServePublicHTTP(w http.ResponseWriter, r *http.Request, h *Handler) {
	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	identifier := chi.URLParam(r, "identifier")
	target, err := resolveAgent(ctx, q, identifier)
	if err != nil {
		writeJSONRPCError(w, nil, rpcErrInvalidParams, "agent not found")
		return
	}
	if !target.McpEnabled || !target.AllowPublicMcp {
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

func (s *MCPServer) handleInitialize(w http.ResponseWriter, target dbq.Agent, msg jsonrpcMessage) {
	// This MCP server fronts a specific agent, so advertise that agent's
	// identity (not a generic "airlock"). serverInfo.name is the stable
	// machine id (slug); title is the human display name, emoji-prefixed
	// when set. instructions is the spec's server-level usage hint — we
	// surface the agent's own description so connecting clients/siblings
	// understand what this server is for. Omitted when empty.
	title := target.Name
	if target.Emoji != "" {
		title = target.Emoji + " " + target.Name
	}
	resultMap := map[string]any{
		"protocolVersion": mcp.LatestProtocolVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"subscribe": false, "listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    target.Slug,
			"title":   title,
			"version": "1.0",
		},
	}
	if target.Description != "" {
		resultMap["instructions"] = target.Description
	}
	result, _ := json.Marshal(resultMap)
	writeJSONRPCResult(w, msg.ID, result)
}

func (s *MCPServer) handleCancelled(_ jsonrpcMessage) {
	// MCP `notifications/cancelled` carries `{requestId}` but our
	// run-cancel path keys on the HTTP connection closing, which fires
	// automatically when the JSON-RPC peer disconnects. The
	// notification is purely advisory.
}

func (s *MCPServer) handleToolsList(ctx context.Context, w http.ResponseWriter, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
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
	// Built-in `prompt` meta-tool. First-party surfaces (web SPA users,
	// sibling agents over A2A) always see it. External surfaces (OAuth
	// clients, /public-mcp anon) are gated by per-agent flags that
	// default off — see promptAllowed.
	if promptAllowed(target, principal) {
		tools = append(tools, toolEntry{
			Name:        "prompt",
			Description: "Delegate a natural-language task to this agent. It runs its own LLM loop and returns {text, taskId, contextId, state, artifacts}. Progress streams via notifications/progress over SSE.",
			// Files schema is inline-upload-only on purpose: external MCP
			// clients have no agent storage to reference a path in, and A2A
			// callers bypass this schema (they use agentsdk's
			// promptAgentInput, which carries []FilePath). The materializer
			// still accepts {path}-shape on the wire for A2A — that path is
			// just never advertised here.
			InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string","description":"The message / task to send"},"contextId":{"type":"string","description":"Optional: continue an existing conversation thread"},"taskId":{"type":"string","description":"Optional: resume a task that returned state=input-required; put the answer in message"},"files":{"type":"array","description":"Files to attach (base64 inline upload).","items":{"type":"object","additionalProperties":false,"required":["filename","mimeType","data"],"properties":{"filename":{"type":"string"},"mimeType":{"type":"string"},"data":{"type":"string","description":"base64-encoded file bytes (max 10 MiB)"}}}}},"required":["message"]}`),
		})
	}
	result, _ := json.Marshal(map[string]any{"tools": tools})
	writeJSONRPCResult(w, msg.ID, result)
}

// promptAllowed gates the built-in `prompt` meta-tool per (target, caller).
//
// Always allowed:
//   - MCPPrincipalUser  — the web SPA; airlock's own UX depends on it.
//   - MCPPrincipalAgent — sibling agent over A2A; prompt() IS the A2A
//     surface, no point exposing this knob there.
//
// Gated (default off, per-agent opt-in):
//   - MCPPrincipalOAuthClient — Claude Desktop, Cursor, and other
//     external MCP clients that authenticated via this agent's OAuth
//     flow. Gated by agents.allow_oauth_mcp_prompt.
//   - MCPPrincipalAnon — unauthenticated /public-mcp callers. Gated by
//     agents.allow_public_mcp_prompt.
//
// Open prompt() delegation to external callers is metered LLM work on
// the operator's tokens with weak attribution; the operator opts in
// explicitly per surface (no UI yet — flip via psql).
func promptAllowed(target dbq.Agent, principal MCPPrincipal) bool {
	switch principal.Kind {
	case MCPPrincipalUser, MCPPrincipalAgent:
		return true
	case MCPPrincipalOAuthClient:
		return target.AllowOauthMcpPrompt
	case MCPPrincipalAnon:
		return target.AllowPublicMcpPrompt
	default:
		return false
	}
}

func (s *MCPServer) handleToolsCall(ctx context.Context, w http.ResponseWriter, r *http.Request, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage) {
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
		// Same gate as handleToolsList — a client that cached an older
		// tools/list (or guessed the name) must not bypass the per-
		// surface opt-in. -32601 (method-not-found) matches what they'd
		// see for any other unadvertised tool.
		if !promptAllowed(target, principal) {
			writeJSONRPCError(w, msg.ID, rpcErrMethodNotFound, "tool not available: prompt")
			return
		}
		s.handlePromptCall(ctx, w, r, h, q, target, access, principal, msg, params.Arguments)
	default:
		s.handleUserToolCall(ctx, w, h, q, target, access, principal, msg, params.Name, params.Arguments)
	}
}

// handlePromptCall drives ForwardA2APrompt, opens an SSE stream, and
// translates the agent's NDJSON timeline into JSON-RPC
// notifications/progress messages. A final response (or error) lands
// on the same SSE channel when the run terminates.
func (s *MCPServer) handlePromptCall(ctx context.Context, w http.ResponseWriter, r *http.Request, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage, args json.RawMessage) {
	// files: accept either legacy {path, filename, contentType, size}
	// (A2A caller / web-uploaded refs) or new inline {filename, mimeType,
	// data} (external MCP uploads). Discriminate by presence of `data`.
	var promptArgs struct {
		Message   string            `json:"message"`
		ContextID string            `json:"contextId,omitempty"`
		TaskID    string            `json:"taskId,omitempty"`
		Decision  string            `json:"decision,omitempty"` // "approve"|"deny" — resumes a taskId that was input-required
		Files     []json.RawMessage `json:"files,omitempty"`
	}
	if err := json.Unmarshal(args, &promptArgs); err != nil {
		writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "decode prompt args")
		return
	}
	// A taskId+decision call is a resume control action, not a fresh
	// prompt: approve carries no message, deny may carry a re-reason.
	// Only a genuinely new turn needs message text.
	isDecisionResume := promptArgs.TaskID != "" && promptArgs.Decision != ""
	if promptArgs.Message == "" && !isDecisionResume {
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
	if promptArgs.ContextID != "" {
		convID, err := uuid.Parse(promptArgs.ContextID)
		if err != nil {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "invalid contextId format")
			return
		}
		conv, err := q.GetConversationByID(ctx, pgtype.UUID{Bytes: convID, Valid: true})
		// Source gate: A2A may only ever continue an A2A thread. A
		// contextId pointing at this agent's web or bridge conversation
		// (even one the same user owns) must NOT be resumable over A2A —
		// that would let a sibling agent read and inject turns into the
		// human's real web/bridge chat. Merge wrong-agent and
		// wrong-surface into the one not-accessible error (don't leak
		// which conversations exist on which surface).
		if err != nil || uuid.UUID(conv.AgentID.Bytes) != uuid.UUID(target.ID.Bytes) || conv.Source != "a2a" {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "contextId not accessible — it must be a contextId this agent returned to you from a prior call. Do not pass your own run/conversation id or a fabricated value. Retry with contextId omitted to start a fresh thread.")
			return
		}
		// The conversation must belong to the same principal that is
		// continuing it — no cross-user (or user↔anon) A2A thread
		// resumption. Owned conv → caller must be that exact user.
		// Anonymous conv (no owner) → only an anonymous caller may
		// continue it. Per-anon-identity gating for bridge callers
		// (external_user_id, possibly a group-chat id) is deferred —
		// see todo/a2a-anon-conversation-gating.md; today all anon
		// callers are one tier.
		if conv.UserID.Valid {
			if principal.UserID == uuid.Nil || uuid.UUID(conv.UserID.Bytes) != principal.UserID {
				writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "contextId not accessible — it must be a contextId this agent returned to you from a prior call. Do not pass your own run/conversation id or a fabricated value. Retry with contextId omitted to start a fresh thread.")
				return
			}
		} else if principal.UserID != uuid.Nil {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "contextId not accessible — it must be a contextId this agent returned to you from a prior call. Do not pass your own run/conversation id or a fabricated value. Retry with contextId omitted to start a fresh thread.")
			return
		}
	}

	// taskId resumes a specific prior run (one that returned
	// state=input-required / suspended). Validate it belongs to this
	// agent before handing it to the resume path; merge not-found and
	// not-yours into one error (don't leak existence).
	var taskRun dbq.Run
	if promptArgs.TaskID != "" {
		taskUUID, err := uuid.Parse(promptArgs.TaskID)
		if err != nil {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "invalid taskId format")
			return
		}
		tr, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: taskUUID, Valid: true})
		// Surface gate: a taskId must reference an A2A run on this agent.
		// A web/bridge run's trigger_ref is its own web/bridge
		// conversation id; without this check, `convID =
		// taskRun.TriggerRef` below would resume the human's real
		// web/bridge thread over A2A. Merge wrong-agent and
		// wrong-surface into the one not-accessible error.
		if err != nil || uuid.UUID(tr.AgentID.Bytes) != uuid.UUID(target.ID.Bytes) || tr.TriggerType != "a2a" {
			writeJSONRPCError(w, msg.ID, rpcErrInvalidParams, "taskId not accessible — it must be a taskId this agent returned to you with state=input-required. Do not invent one; omit taskId unless you are resuming such a task.")
			return
		}
		taskRun = tr
	}

	// Resolve the conversation this A2A turn runs in. contextId ≡
	// agent_conversations.id on the *called* agent (validated above to
	// belong to target). No contextId → mint a fresh thread owned by
	// the original user (NULL user for anonymous external-MCP callers).
	// taskId-resume continues that task's own conversation — its
	// run.trigger_ref, which for a2a/prompt runs is the conv id.
	var convID string
	switch {
	case promptArgs.ContextID != "":
		convID = promptArgs.ContextID
	case promptArgs.TaskID != "":
		convID = taskRun.TriggerRef
	default:
		var convUser pgtype.UUID
		if principal.UserID != uuid.Nil {
			convUser = pgtype.UUID{Bytes: principal.UserID, Valid: true}
		}
		conv, cerr := q.CreateA2AConversation(ctx, dbq.CreateA2AConversationParams{
			AgentID: pgtype.UUID{Bytes: uuid.UUID(target.ID.Bytes), Valid: true},
			UserID:  convUser,
			Title:   truncate(promptArgs.Message, 100),
		})
		if cerr != nil {
			writeJSONRPCError(w, msg.ID, rpcErrServerError, "create a2a conversation: "+cerr.Error())
			return
		}
		convID = convert.PgUUIDToString(conv.ID)
	}

	// Inbound files scope to the resolved conversation so they persist
	// with the thread across A2A turns.
	scopeKey := scopeKeyForConversation(convID)
	var mErr *materializeError
	files, mErr = s.materializePromptFiles(ctx, h, q, target, principal, scopeKey, promptArgs.Files)
	if mErr != nil {
		writeJSONRPCError(w, msg.ID, mErr.Code, mErr.Message)
		return
	}

	// Attached-files manifest — same canonical producer as web/bridge.
	// Pre-dispatch so it's in the called agent's history when its
	// SessionStore loads.
	if cu, perr := uuid.Parse(convID); perr == nil {
		if err := trigger.PostFilesManifest(ctx, q, pgtype.UUID{Bytes: cu, Valid: true}, files); err != nil {
			s.logger.Warn("post files manifest failed", zap.String("conversation_id", convID), zap.Error(err))
		}
	}

	// Build PromptInput. CallerAccess and VisibleSiblings are filled
	// by ForwardA2APrompt; we just supply the message + files.
	input := agentsdk.PromptInput{
		Message:        promptArgs.Message,
		ConversationID: convID,
		ResumeRunID:    promptArgs.TaskID,
		Files:          files,
	}
	// decision resumes a taskId that returned input-required: map to
	// the agentsdk approve/deny resume contract (same as web/bridge
	// confirmations). On deny the message rides along so the agent's
	// LLM can re-reason. Only meaningful with taskId.
	if promptArgs.TaskID != "" && promptArgs.Decision != "" {
		approved := promptArgs.Decision == "approve"
		input.Approved = &approved
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
		if m, notRunnable := notRunnableMCPMessage(err, target.Slug); notRunnable {
			writeJSONRPCError(w, msg.ID, rpcErrServerError, m)
			return
		}
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
	//
	// A2A child run (parentInfo != nil): publish ONLY to the caller's
	// topic, tagged as a sub-run. Also publishing to the child agent's
	// own topic would double every delta for a user who is a member of
	// both agents — the socket auto-subscribes to every member agent and
	// the chat store isn't topic-scoped — and an A2A invocation isn't a
	// conversation in the sibling, so it has no business surfacing in
	// the sibling's own chat.
	//
	// Non-A2A (external MCP / user / anon prompt, parentInfo == nil):
	// the child agent's own topic is the only audience.
	childTopic := uuid.UUID(target.ID.Bytes)
	mirror := func(eventType string, payload proto.Message) {
		if parentInfo != nil {
			parentEnv := realtime.NewEnvelopeForUser(eventType, parentInfo.AgentID.String(), parentInfo.UserID, parentInfo.ConvID, payload).
				WithSubagent(realtime.SubagentInfo{
					AgentID: parentInfo.ChildAgentID.String(),
					RunID:   parentInfo.ChildRunID.String(),
					Slug:    parentInfo.ChildAgentSlug,
				})
			_ = s.pubsub.Publish(cctx, parentInfo.AgentID, parentEnv)
			return
		}
		env := realtime.NewEnvelopeForUser(eventType, childTopic.String(), childUserID, promptArgs.ContextID, payload)
		_ = s.pubsub.Publish(cctx, childTopic, env)
	}

	// run.started — emitted up-front so the parent's chat UI can show
	// the sub-run card before the first text-delta lands.
	mirror("run.started", &airlockv1.RunStartedEvent{
		RunId:          runID.String(),
		AgentId:        uuid.UUID(target.ID.Bytes).String(),
		ConversationId: promptArgs.ContextID,
	})

	progressToken := msg.ID
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var finalText strings.Builder
	var finalErr string
	var suspended bool
	var confirmation map[string]any // leaf gate detail for human-facing attribution up the chain
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
			// tr.Output is the discriminated ToolResultOutput; resolve it
			// to display text + structured outcome (legacy shapes still
			// decode during the migration window).
			out, outcome, errText := decodeToolOutput(tr.Output)
			sendSSE(w, flusher, "notifications/progress", map[string]any{
				"progressToken": progressToken,
				"event":         raw,
			})
			mirror("run.tool_result", &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: tr.ToolCallID,
				ToolName:   tr.ToolName,
				Output:     out,
				Error:      errText,
				Outcome:    outcome,
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
		case "confirmation_required":
			// Capture the leaf gate detail so it can ride up the
			// delegated-suspension chain — the human at the root needs
			// to see WHAT the sibling wants to do, not a blank gate.
			var c struct {
				Permission string   `json:"permission"`
				Patterns   []string `json:"patterns"`
				Code       string   `json:"code"`
				ToolCallID string   `json:"toolCallId"`
			}
			if json.Unmarshal(evt.Data, &c) == nil {
				confirmation = map[string]any{
					"agent":      target.Slug,
					"permission": c.Permission,
					"patterns":   c.Patterns,
					"code":       c.Code,
				}
			}
		case "suspended":
			// The child run paused for input (tool confirmation / auth).
			// Not an error — the task is resumable via taskId.
			suspended = true
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

	// Hard failure / cancel stays on the JSON-RPC error channel — that
	// surfaces as a thrown error in the caller's run_js (A2A states
	// failed/canceled map onto the transport error; the message names
	// the cause). Suspension is NOT an error: it returns a normal
	// result with state=input-required and the taskId so the caller can
	// resume.
	if finalErr != "" {
		writeSSEJSONRPCError(w, flusher, msg.ID, rpcErrServerError, finalErr)
		return
	}

	state := "completed"
	if suspended {
		state = "input-required"
	}

	// contextId is the conversation thread the caller continues with —
	// the conversation resolved/minted above. The caller echoes this
	// back as contextId next turn to continue this same thread.
	contextID := convID

	artifacts := collectPromptArtifacts(ctx, h.s3, s.logger, q, target, principal, runID)

	content := []map[string]any{{"type": "text", "text": finalText.String()}}
	// External (non-agent) clients get a resource_link per artifact with
	// a public presigned URL as the uri. The agent:// scheme would force
	// the client through resources/read, which only resolves files under
	// a registered agent_directories row — output() writes into a raw
	// media/{mediaID}/ S3 prefix that nothing registers, so the agent://
	// link 404s. A presigned URL sidesteps that entirely: the client
	// (Claude Desktop, Cursor, etc.) treats the link as a direct fetch.
	// Agent callers don't get resource_links — they read the artifact
	// from siblings/<slug>/... in their own bucket, copied during
	// collectPromptArtifacts.
	if principal.Kind != MCPPrincipalAgent {
		targetID := uuid.UUID(target.ID.Bytes)
		for _, a := range artifacts {
			s3Key := "agents/" + targetID.String() + "/" + a.Path
			url, perr := h.s3.PublicPresignGetURL(ctx, s3Key, presignedURLTTL)
			if perr != nil {
				s.logger.Warn("mcp prompt: presign artifact",
					zap.String("path", a.Path), zap.Error(perr))
				continue
			}
			content = append(content, map[string]any{
				"type":     "resource_link",
				"uri":      url,
				"name":     a.Filename,
				"mimeType": a.ContentType,
			})
		}
	}
	if artifacts == nil {
		artifacts = []a2aArtifact{}
	}
	a2aMeta := map[string]any{
		"taskId":    runID.String(),
		"contextId": contextID,
		"state":     state,
		"artifacts": artifacts,
	}
	// On input-required, carry the leaf gate detail (which sibling
	// wants to do what) so the caller's promptAgent tool can stamp it
	// into ErrDelegatedSuspend — it then rides up the chain to the
	// root run's confirmation card so the human approves something
	// meaningful, not a blank "delegated" gate.
	if state == "input-required" && confirmation != nil {
		a2aMeta["confirmation"] = confirmation
	}
	resultPayload, _ := json.Marshal(map[string]any{
		"content": content,
		"isError": false,
		"_meta": map[string]any{
			"airlock.run/a2a": a2aMeta,
		},
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
func (s *MCPServer) handleUserToolCall(ctx context.Context, w http.ResponseWriter, h *Handler, q *dbq.Queries, target dbq.Agent, access agentsdk.Access, principal MCPPrincipal, msg jsonrpcMessage, name string, args json.RawMessage) {
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
		if m, notRunnable := notRunnableMCPMessage(err, target.Slug); notRunnable {
			writeJSONRPCError(w, msg.ID, rpcErrServerError, m)
			return
		}
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
