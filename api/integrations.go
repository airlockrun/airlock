package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	integrationservice "github.com/airlockrun/airlock/service/integrations"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type integrationContextKey struct{}

type integrationContext struct {
	principal authz.Principal
	agentID   uuid.UUID
}

type integrationsHandler struct {
	svc *integrationservice.Service
}

func newIntegrationsHandler(svc *integrationservice.Service) *integrationsHandler {
	if svc == nil {
		panic("api: integrations service is required")
	}
	return &integrationsHandler{svc: svc}
}

func integrationUserContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil || claims.ClientID != "" || claims.Email == "" {
			writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
			return
		}
		agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
		if err != nil {
			writeServiceError(w, service.Detail(service.ErrInvalidInput, "invalid agent ID"), "invalid integration request")
			return
		}
		ctx := context.WithValue(r.Context(), integrationContextKey{}, integrationContext{
			principal: principalFromRequest(r),
			agentID:   agentID,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func codegenIntegrationAuth(database *db.DB) func(http.Handler) http.Handler {
	if database == nil {
		panic("api: database is required for codegen integration auth")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := auth.BearerToken(r.Header.Get("Authorization"))
			if err != nil {
				writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
				return
			}
			hash := auth.HashIntegrationToken(token)
			if hash == nil {
				writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
				return
			}
			// airlockvet:allow-dbq reason: pre-Principal authentication resolves a short-lived opaque build token; the resulting codegen Principal is service-authorized below
			build, err := dbq.New(database.Pool()).GetAgentBuildByIntegrationToken(r.Context(), hash)
			if err != nil || !build.ID.Valid || !build.AgentID.Valid {
				writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
				return
			}
			buildID := uuid.UUID(build.ID.Bytes)
			agentID := uuid.UUID(build.AgentID.Bytes)
			ctx := context.WithValue(r.Context(), integrationContextKey{}, integrationContext{
				principal: authz.CodegenPrincipal(buildID, agentID),
				agentID:   agentID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func mountIntegrationRoutes(r chi.Router, h *integrationsHandler) {
	r.Get("/", h.List)
	r.Post("/connections/{slug}/request", h.RequestConnection)
	r.Post("/exec/{slug}/run", h.RunExec)
	r.Get("/mcp/{slug}/tools", h.ListMCPTools)
	r.Post("/mcp/{slug}/call", h.CallMCPTool)
}

func (h *integrationsHandler) List(w http.ResponseWriter, r *http.Request) {
	ic, ok := integrationContextFromRequest(r)
	if !ok {
		writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
		return
	}
	items, err := h.svc.List(r.Context(), ic.principal, ic.agentID)
	if err != nil {
		writeServiceError(w, err, "failed to list integrations")
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Type == items[j].Type {
			return items[i].Slug < items[j].Slug
		}
		return items[i].Type < items[j].Type
	})
	out := make([]*airlockv1.IntegrationInfo, len(items))
	for i, item := range items {
		out[i] = &airlockv1.IntegrationInfo{Type: item.Type, Slug: item.Slug, Description: item.Description, Configured: item.Configured}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListIntegrationsResponse{Integrations: out})
}

func (h *integrationsHandler) RequestConnection(w http.ResponseWriter, r *http.Request) {
	ic, ok := integrationContextFromRequest(r)
	if !ok {
		writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
		return
	}
	var req airlockv1.InvokeConnectionRequest
	if err := decodeProto(r, &req); err != nil {
		writeServiceError(w, service.Detail(service.ErrInvalidInput, "invalid request"), "invalid connection request")
		return
	}
	result, err := h.svc.RequestConnection(r.Context(), ic.principal, ic.agentID, chi.URLParam(r, "slug"), wire.ProxyRequest{
		Method: req.Method, Path: req.Path, Body: string(req.Body), Headers: req.Headers,
	})
	if err != nil {
		writeServiceError(w, err, "connection request failed")
		return
	}
	headerNames := make([]string, 0, len(result.Headers))
	for name := range result.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	headers := make([]*airlockv1.IntegrationHTTPHeader, 0, len(headerNames))
	for _, name := range headerNames {
		headers = append(headers, &airlockv1.IntegrationHTTPHeader{Name: name, Values: result.Headers[name]})
	}
	writeProto(w, http.StatusOK, &airlockv1.InvokeConnectionResponse{StatusCode: int32(result.StatusCode), Headers: headers, Body: result.Body})
}

func (h *integrationsHandler) RunExec(w http.ResponseWriter, r *http.Request) {
	ic, ok := integrationContextFromRequest(r)
	if !ok {
		writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
		return
	}
	var req airlockv1.InvokeExecRequest
	if err := decodeProto(r, &req); err != nil {
		writeServiceError(w, service.Detail(service.ErrInvalidInput, "invalid request"), "invalid exec request")
		return
	}
	result, err := h.svc.RunExec(r.Context(), ic.principal, ic.agentID, chi.URLParam(r, "slug"), wire.ExecRequest{
		Command: req.Command, Args: req.Args, StdinB64: base64Encode(req.Stdin), TimeoutMs: req.TimeoutMs,
	})
	if err != nil {
		writeServiceError(w, err, "exec request failed")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.InvokeExecResponse{
		Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: int32(result.ExitCode), DurationMs: result.DurationMs,
	})
}

func (h *integrationsHandler) ListMCPTools(w http.ResponseWriter, r *http.Request) {
	ic, ok := integrationContextFromRequest(r)
	if !ok {
		writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
		return
	}
	result, err := h.svc.ListMCPTools(r.Context(), ic.principal, ic.agentID, chi.URLParam(r, "slug"))
	if err != nil {
		writeServiceError(w, err, "failed to list MCP tools")
		return
	}
	tools := make([]*airlockv1.IntegrationMCPTool, len(result.Tools))
	for i, item := range result.Tools {
		tools[i] = &airlockv1.IntegrationMCPTool{Name: item.Name, Description: item.Description, InputSchemaJson: item.InputSchema}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	writeProto(w, http.StatusOK, &airlockv1.ListIntegrationMCPToolsResponse{Tools: tools, Instructions: result.Instructions})
}

func (h *integrationsHandler) CallMCPTool(w http.ResponseWriter, r *http.Request) {
	ic, ok := integrationContextFromRequest(r)
	if !ok {
		writeServiceError(w, service.ErrUnauthorized, "integration authentication failed")
		return
	}
	var req airlockv1.InvokeMCPToolRequest
	if err := decodeProto(r, &req); err != nil {
		writeServiceError(w, service.Detail(service.ErrInvalidInput, "invalid request"), "invalid MCP request")
		return
	}
	if len(req.ArgumentsJson) == 0 {
		req.ArgumentsJson = []byte("{}")
	}
	if !json.Valid(req.ArgumentsJson) {
		writeServiceError(w, service.Detail(service.ErrInvalidInput, "arguments must be valid JSON"), "invalid MCP request")
		return
	}
	result, err := h.svc.CallMCPTool(r.Context(), ic.principal, ic.agentID, chi.URLParam(r, "slug"), wire.MCPToolCallRequest{
		Tool: req.Tool, Arguments: json.RawMessage(req.ArgumentsJson),
	})
	if err != nil {
		writeServiceError(w, err, "MCP tool call failed")
		return
	}
	content := make([]*airlockv1.IntegrationMCPContent, len(result.Content))
	for i, item := range result.Content {
		content[i] = &airlockv1.IntegrationMCPContent{Type: item.Type, Text: item.Text, Uri: item.URI, Name: item.Name, MimeType: item.MimeType, Data: item.Data}
	}
	writeProto(w, http.StatusOK, &airlockv1.InvokeMCPToolResponse{Content: content, IsError: result.IsError})
}

func integrationContextFromRequest(r *http.Request) (integrationContext, bool) {
	ic, ok := r.Context().Value(integrationContextKey{}).(integrationContext)
	return ic, ok
}

func base64Encode(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(value)
}
