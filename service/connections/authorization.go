package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/needs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// AuthorizationStart identifies the durable resource being authorized.
type AuthorizationStart struct {
	AuthorizeURL string
	ResourceID   uuid.UUID
}

type authorizationResource struct {
	typ                  string
	id                   pgtype.UUID
	lifecycle            string
	authMode             string
	authURL              string
	tokenURL             string
	clientID             string
	clientSecret         string
	pendingClientID      string
	pendingClientSecret  string
	refreshToken         string
	authParams           []byte
	scopes               string
	revision             int64
	registrationEndpoint string
	name                 string
	connection           dbq.Connection
	mcp                  dbq.AgentMcpServer
}

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func resourceFromConnection(connection dbq.Connection) authorizationResource {
	return authorizationResource{
		typ: "connection", id: connection.ID, lifecycle: connection.Lifecycle,
		authMode: connection.AuthMode, authURL: connection.AuthUrl, tokenURL: connection.TokenUrl,
		clientID: connection.ClientID, clientSecret: connection.ClientSecret,
		pendingClientID: connection.PendingClientID, pendingClientSecret: connection.PendingClientSecret,
		refreshToken: connection.RefreshToken, authParams: connection.AuthParams,
		scopes: connection.Scopes, revision: connection.AuthorizationRevision,
		name: connection.Name, connection: connection,
	}
}

func resourceFromMCP(server dbq.AgentMcpServer) authorizationResource {
	return authorizationResource{
		typ: "mcp_server", id: server.ID, lifecycle: server.Lifecycle,
		authMode: server.AuthMode, authURL: server.AuthUrl, tokenURL: server.TokenUrl,
		clientID: server.ClientID, clientSecret: server.ClientSecret,
		pendingClientID: server.PendingClientID, pendingClientSecret: server.PendingClientSecret,
		refreshToken: server.RefreshToken, scopes: server.Scopes,
		revision: server.AuthorizationRevision, registrationEndpoint: server.RegistrationEndpoint,
		name: server.Name, mcp: server,
	}
}

func loadAuthorizationResource(ctx context.Context, q *dbq.Queries, typ string, id pgtype.UUID, forUpdate bool) (authorizationResource, error) {
	switch typ {
	case "connection":
		var row dbq.Connection
		var err error
		if forUpdate {
			row, err = q.GetConnectionByIDForUpdate(ctx, id)
		} else {
			row, err = q.GetConnectionByID(ctx, id)
		}
		return resourceFromConnection(row), err
	case "mcp_server":
		var row dbq.AgentMcpServer
		var err error
		if forUpdate {
			row, err = q.GetMCPServerByIDForUpdate(ctx, id)
		} else {
			row, err = q.GetMCPServerByID(ctx, id)
		}
		return resourceFromMCP(row), err
	default:
		return authorizationResource{}, service.Detail(service.ErrInvalidInput, "resource type does not support OAuth")
	}
}

func compatible(need dbq.AgentResourceNeed, resource authorizationResource) bool {
	switch resource.typ {
	case "connection":
		return needs.ConnectionCompatible(need.Spec, resource.connection)
	case "mcp_server":
		return needs.MCPCompatible(need.Spec, resource.mcp)
	default:
		return false
	}
}

func requiredScopeUnion(ctx context.Context, q *dbq.Queries, resource authorizationResource, needID pgtype.UUID) (string, error) {
	var rows []string
	var err error
	if resource.typ == "connection" {
		rows, err = q.ListRequiredConnectionScopes(ctx, dbq.ListRequiredConnectionScopesParams{ResourceID: resource.id, TargetNeedID: needID})
	} else {
		rows, err = q.ListRequiredMCPScopes(ctx, dbq.ListRequiredMCPScopesParams{ResourceID: resource.id, TargetNeedID: needID})
	}
	if err != nil {
		return "", err
	}
	return oauth.UnionScopes(rows...), nil
}

func (s *Service) selectAuthorizationResource(ctx context.Context, q *dbq.Queries, ownerID uuid.UUID, need dbq.AgentResourceNeed, typ string, resourceID uuid.UUID, createNew bool) (authorizationResource, error) {
	if createNew && resourceID != uuid.Nil {
		return authorizationResource{}, service.Detail(service.ErrInvalidInput, "create_new cannot target an existing resource")
	}
	if resourceID != uuid.Nil {
		return loadAuthorizationResource(ctx, q, typ, pgUUID(resourceID), false)
	}
	var bound pgtype.UUID
	if typ == "connection" {
		bound = need.BoundConnectionID
	} else {
		bound = need.BoundMcpID
	}
	if bound.Valid && !createNew {
		return loadAuthorizationResource(ctx, q, typ, bound, false)
	}
	owner := pgUUID(ownerID)
	if typ == "connection" {
		row, err := q.GetProvisionalConnectionForNeedOwner(ctx, dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner})
		if err == nil {
			return resourceFromConnection(row), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return authorizationResource{}, err
		}
	} else if typ == "mcp_server" {
		row, err := q.GetProvisionalMCPServerForNeedOwner(ctx, dbq.GetProvisionalMCPServerForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner})
		if err == nil {
			return resourceFromMCP(row), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return authorizationResource{}, err
		}
	}
	return authorizationResource{}, pgx.ErrNoRows
}

func (s *Service) prepareMCPAuthorization(ctx context.Context, q *dbq.Queries, resource authorizationResource) (authorizationResource, error) {
	if resource.typ != "mcp_server" || resource.authMode != "oauth_discovery" {
		return resource, nil
	}
	if resource.authURL == "" || resource.tokenURL == "" || (resource.clientID == "" && resource.pendingClientID == "" && resource.registrationEndpoint == "") {
		discovery, err := s.discoverAuth(ctx, resource.mcp.Url)
		if err != nil {
			return authorizationResource{}, service.Detail(service.ErrInvalidInput, "OAuth discovery failed: %v", err)
		}
		if discovery.AuthorizationURL != "" {
			resource.authURL = discovery.AuthorizationURL
		}
		if discovery.TokenURL != "" {
			resource.tokenURL = discovery.TokenURL
		}
		if discovery.RegistrationEndpoint != "" {
			resource.registrationEndpoint = discovery.RegistrationEndpoint
		}
		if err := q.UpdateMCPServerDiscoveryByID(ctx, dbq.UpdateMCPServerDiscoveryByIDParams{
			ID: resource.id, AuthUrl: resource.authURL, TokenUrl: resource.tokenURL, RegistrationEndpoint: resource.registrationEndpoint,
		}); err != nil {
			return authorizationResource{}, err
		}
	}
	if resource.clientID != "" || resource.pendingClientID != "" {
		return resource, nil
	}
	if resource.registrationEndpoint == "" {
		return authorizationResource{}, service.Detail(service.ErrInvalidInput, "server does not advertise a dynamic client registration endpoint")
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	registration, err := oauth.RegisterClient(ctx, s.mcpHTTP, resource.registrationEndpoint, "airlock:"+resource.name, callbackURL, resource.scopes)
	if err != nil {
		return authorizationResource{}, service.Detail(service.ErrInvalidInput, "dynamic client registration failed: %v", err)
	}
	if registration.TokenEndpointAuthMethod == "none" {
		registration.ClientSecret = ""
	}
	ref := "mcp/" + uuid.UUID(resource.id.Bytes).String()
	clientID, err := s.encryptor.Put(ctx, ref+"/client_id", registration.ClientID)
	if err != nil {
		return authorizationResource{}, err
	}
	clientSecret, err := s.encryptor.Put(ctx, ref+"/client_secret", registration.ClientSecret)
	if err != nil {
		return authorizationResource{}, err
	}
	if _, err := q.StageMCPServerOAuthAppByID(ctx, dbq.StageMCPServerOAuthAppByIDParams{ID: resource.id, ClientID: clientID, ClientSecret: clientSecret}); err != nil {
		return authorizationResource{}, err
	}
	resource.pendingClientID = clientID
	resource.pendingClientSecret = clientSecret
	return resource, nil
}

// StartAuthorizationForNeed authorizes the scope union for all existing
// bindings plus the prospective target. The target binding is written only by
// a successful callback.
func (s *Service) StartAuthorizationForNeed(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, needSlug string, resourceID uuid.UUID, displayName, redirectURI string, createNew bool) (AuthorizationStart, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return AuthorizationStart{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pgUUID(agentID)); err != nil {
		return AuthorizationStart{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return AuthorizationStart{}, err
	}
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: typ, Slug: needSlug})
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationStart{}, service.Detail(service.ErrNotFound, "resource need not found")
	}
	if err != nil {
		return AuthorizationStart{}, err
	}
	resource, err := s.selectAuthorizationResource(ctx, q, p.UserID, need, typ, resourceID, createNew)
	created := false
	if errors.Is(err, pgx.ErrNoRows) {
		need, err = q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pgUUID(agentID), Type: typ, Slug: needSlug})
		if err != nil {
			return AuthorizationStart{}, err
		}
		currentBinding := need.BoundConnectionID
		if typ == "mcp_server" {
			currentBinding = need.BoundMcpID
		}
		if !createNew && resourceID == uuid.Nil && currentBinding.Valid {
			return AuthorizationStart{}, service.Detail(service.ErrConflict, "target need binding changed; retry authorization")
		}
		id, createErr := needs.CreateForNeed(ctx, q, p, agentID, typ, needSlug, displayName, createNew)
		if createErr != nil {
			return AuthorizationStart{}, createErr
		}
		resource, err = loadAuthorizationResource(ctx, q, typ, pgUUID(id), false)
		created = true
	}
	if err != nil {
		return AuthorizationStart{}, err
	}
	var lockedNeeds []dbq.AgentResourceNeed
	if typ == "connection" {
		lockedNeeds, err = q.LockConnectionAuthorizationNeeds(ctx, dbq.LockConnectionAuthorizationNeedsParams{ResourceID: resource.id, TargetNeedID: need.ID})
	} else if typ == "mcp_server" {
		lockedNeeds, err = q.LockMCPAuthorizationNeeds(ctx, dbq.LockMCPAuthorizationNeedsParams{ResourceID: resource.id, TargetNeedID: need.ID})
	} else {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "resource type does not support OAuth")
	}
	if err != nil {
		return AuthorizationStart{}, err
	}
	targetLocked := false
	for _, lockedNeed := range lockedNeeds {
		if lockedNeed.ID == need.ID {
			need = lockedNeed
			targetLocked = true
			break
		}
	}
	if !targetLocked {
		return AuthorizationStart{}, service.Detail(service.ErrConflict, "target need changed; retry authorization")
	}
	expectedPrior := need.BoundConnectionID
	if typ == "mcp_server" {
		expectedPrior = need.BoundMcpID
	}
	if !created && resourceID == uuid.Nil && !createNew && expectedPrior.Valid && expectedPrior != resource.id {
		return AuthorizationStart{}, service.Detail(service.ErrConflict, "target need binding changed; retry authorization")
	}
	resource, err = loadAuthorizationResource(ctx, q, typ, resource.id, true)
	if err != nil {
		return AuthorizationStart{}, err
	}
	if resource.lifecycle == "provisional" {
		provisionalNeedID := resource.connection.ProvisionalNeedID
		if typ == "mcp_server" {
			provisionalNeedID = resource.mcp.ProvisionalNeedID
		}
		if need.ID != provisionalNeedID {
			return AuthorizationStart{}, service.Detail(service.ErrConflict, "provisional resource belongs to another need")
		}
	}
	if !compatible(need, resource) {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "resource shape does not match the need")
	}
	if resource.authMode != "oauth" && resource.authMode != "oauth_discovery" {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "resource is not OAuth")
	}
	resource, err = s.prepareMCPAuthorization(ctx, q, resource)
	if err != nil {
		return AuthorizationStart{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, typ, uuid.UUID(resource.id.Bytes)); err != nil {
		return AuthorizationStart{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, uuid.UUID(resource.id.Bytes)); err != nil {
		return AuthorizationStart{}, err
	}
	requestedScopes, err := requiredScopeUnion(ctx, q, resource, need.ID)
	if err != nil {
		return AuthorizationStart{}, err
	}
	usesPendingClient := resource.pendingClientID != ""
	clientIDRef := resource.clientID
	if usesPendingClient {
		clientIDRef = resource.pendingClientID
	}
	if clientIDRef == "" {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "OAuth app not configured")
	}
	completionRedirect, err := s.completionRedirect(redirectURI, agentID)
	if err != nil {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "invalid completion redirect: %v", err)
	}
	ref := resourceSecretRef(resource)
	clientID, err := s.encryptor.Get(ctx, ref+"/client_id", clientIDRef)
	if err != nil {
		return AuthorizationStart{}, err
	}
	verifier, challenge, err := oauth.GeneratePKCE()
	if err != nil {
		return AuthorizationStart{}, err
	}
	state, err := oauth.GenerateState()
	if err != nil {
		return AuthorizationStart{}, err
	}
	storedVerifier, err := s.encryptor.Put(ctx, "oauth_state/"+state+"/code_verifier", verifier)
	if err != nil {
		return AuthorizationStart{}, err
	}
	var params map[string]string
	if typ == "connection" {
		params = map[string]string{"access_type": "offline", "prompt": "consent"}
		if len(resource.authParams) > 0 {
			var declared map[string]string
			if err := json.Unmarshal(resource.authParams, &declared); err != nil {
				return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "invalid OAuth authorization parameters")
			}
			for key, value := range declared {
				if value == "" {
					delete(params, key)
				} else {
					params[key] = value
				}
			}
		}
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	authorizeURL, err := s.oauthClient.BuildAuthURL(resource.authURL, clientID, callbackURL, state, challenge, requestedScopes, params)
	if err != nil {
		return AuthorizationStart{}, service.Detail(service.ErrInvalidInput, "build OAuth authorization URL: %v", err)
	}
	var revision int64
	if typ == "connection" {
		revision, err = q.AdvanceConnectionAuthorizationRevision(ctx, resource.id)
	} else {
		revision, err = q.AdvanceMCPServerAuthorizationRevision(ctx, resource.id)
	}
	if err != nil {
		return AuthorizationStart{}, err
	}
	sourceType := "connection"
	if typ == "mcp_server" {
		sourceType = "mcp"
	}
	if err := q.CreateOAuthState(ctx, dbq.CreateOAuthStateParams{
		State: state, AgentID: pgUUID(agentID), UserID: pgUUID(p.UserID), ResourceID: resource.id,
		NeedID: need.ID, Slug: needSlug, CodeVerifier: storedVerifier, RedirectUri: completionRedirect,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(10 * time.Minute), Valid: true}, SourceType: sourceType,
		RequestedScopes: requestedScopes, AuthorizationRevision: revision,
		ExpectedPriorResourceID: expectedPrior, UsesPendingClient: usesPendingClient,
	}); err != nil {
		return AuthorizationStart{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthorizationStart{}, err
	}
	return AuthorizationStart{AuthorizeURL: authorizeURL, ResourceID: uuid.UUID(resource.id.Bytes)}, nil
}

func resourceSecretRef(resource authorizationResource) string {
	prefix := "connection"
	if resource.typ == "mcp_server" {
		prefix = "mcp"
	}
	return prefix + "/" + uuid.UUID(resource.id.Bytes).String()
}

func (s *Service) callbackPrincipal(ctx context.Context, q *dbq.Queries, state dbq.OauthState) (authz.Principal, error) {
	user, err := q.GetUserByID(ctx, state.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Principal{}, service.ErrForbidden
	}
	if err != nil {
		return authz.Principal{}, err
	}
	return authz.UserPrincipal(uuid.UUID(user.ID.Bytes), auth.Role(user.TenantRole)), nil
}

func (s *Service) validateCallback(ctx context.Context, q *dbq.Queries, state dbq.OauthState, forUpdate bool) (authorizationResource, dbq.AgentResourceNeed, error) {
	typ := "connection"
	if state.SourceType == "mcp" {
		typ = "mcp_server"
	} else if state.SourceType != "connection" {
		return authorizationResource{}, dbq.AgentResourceNeed{}, ErrOAuthInvalidState
	}
	var lockedNeeds []dbq.AgentResourceNeed
	var err error
	if forUpdate {
		if _, err := q.GetAgentByIDForUpdate(ctx, state.AgentID); err != nil {
			return authorizationResource{}, dbq.AgentResourceNeed{}, err
		}
		if typ == "connection" {
			lockedNeeds, err = q.LockConnectionAuthorizationNeeds(ctx, dbq.LockConnectionAuthorizationNeedsParams{ResourceID: state.ResourceID, TargetNeedID: state.NeedID})
		} else {
			lockedNeeds, err = q.LockMCPAuthorizationNeeds(ctx, dbq.LockMCPAuthorizationNeedsParams{ResourceID: state.ResourceID, TargetNeedID: state.NeedID})
		}
		if err != nil {
			return authorizationResource{}, dbq.AgentResourceNeed{}, err
		}
	}
	resource, err := loadAuthorizationResource(ctx, q, typ, state.ResourceID, forUpdate)
	if err != nil {
		return authorizationResource{}, dbq.AgentResourceNeed{}, err
	}
	if resource.revision != state.AuthorizationRevision {
		return authorizationResource{}, dbq.AgentResourceNeed{}, service.Detail(service.ErrConflict, "OAuth authorization is stale")
	}
	var need dbq.AgentResourceNeed
	if forUpdate {
		for _, candidate := range lockedNeeds {
			if candidate.ID == state.NeedID {
				need = candidate
				break
			}
		}
		if !need.ID.Valid {
			err = pgx.ErrNoRows
		}
	} else {
		need, err = q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: state.AgentID, Type: typ, Slug: state.Slug})
	}
	if err != nil || need.ID != state.NeedID {
		if errors.Is(err, pgx.ErrNoRows) {
			return resource, dbq.AgentResourceNeed{}, service.Detail(service.ErrConflict, "target need was removed")
		}
		return resource, dbq.AgentResourceNeed{}, err
	}
	if !compatible(need, resource) {
		return resource, need, service.Detail(service.ErrConflict, "resource no longer matches target need")
	}
	currentBinding := need.BoundConnectionID
	if typ == "mcp_server" {
		currentBinding = need.BoundMcpID
	}
	if currentBinding != state.ExpectedPriorResourceID {
		return resource, need, service.Detail(service.ErrConflict, "target need binding changed")
	}
	var principal authz.Principal
	if forUpdate {
		user, userErr := q.GetUserByIDForUpdate(ctx, state.UserID)
		if errors.Is(userErr, pgx.ErrNoRows) {
			return resource, need, service.ErrForbidden
		}
		if userErr != nil {
			return resource, need, userErr
		}
		principal = authz.UserPrincipal(uuid.UUID(user.ID.Bytes), auth.Role(user.TenantRole))
	} else {
		principal, err = s.callbackPrincipal(ctx, q, state)
	}
	if err != nil {
		return resource, need, err
	}
	agentID := uuid.UUID(state.AgentID.Bytes)
	if err := authz.Authorize(ctx, q, principal, authz.AgentConnections, agentID); err != nil {
		return resource, need, err
	}
	if err := authz.AuthorizeResource(ctx, q, principal, authz.ResourceBind, typ, uuid.UUID(resource.id.Bytes)); err != nil {
		return resource, need, err
	}
	if err := authz.AuthorizeResource(ctx, q, principal, authz.ResourceManage, typ, uuid.UUID(resource.id.Bytes)); err != nil {
		return resource, need, err
	}
	required, err := requiredScopeUnion(ctx, q, resource, need.ID)
	if err != nil {
		return resource, need, err
	}
	if required != oauth.CanonicalScopes(state.RequestedScopes) {
		return resource, need, service.Detail(service.ErrConflict, "required OAuth scopes changed")
	}
	if state.UsesPendingClient && (resource.pendingClientID == "" || resource.pendingClientSecret == "") {
		return resource, need, service.Detail(service.ErrConflict, "staged OAuth app changed")
	}
	return resource, need, nil
}

func authorizationErrorRedirect(raw, status string, cause error) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic("connections: validated OAuth redirect is invalid")
	}
	query := u.Query()
	query.Set("oauth_status", status)
	if cause != nil {
		message := cause.Error()
		if len(message) > 1024 {
			message = message[:1024]
		}
		query.Set("message", message)
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *Service) discardAuthorization(ctx context.Context, stateToken, status string, cause error) (OAuthCallbackResult, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	state, err := q.GetOAuthStateForUpdate(ctx, stateToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthCallbackResult{}, ErrOAuthInvalidState
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	resource, loadErr := loadAuthorizationResource(ctx, q, mapSourceType(state.SourceType), state.ResourceID, true)
	if loadErr == nil && resource.revision == state.AuthorizationRevision && resource.lifecycle == "provisional" {
		if resource.typ == "connection" {
			_, err = q.DeleteProvisionalConnection(ctx, dbq.DeleteProvisionalConnectionParams{ID: resource.id, AuthorizationRevision: resource.revision})
		} else {
			_, err = q.DeleteProvisionalMCPServer(ctx, dbq.DeleteProvisionalMCPServerParams{ID: resource.id, AuthorizationRevision: resource.revision})
		}
		if err != nil {
			return OAuthCallbackResult{}, err
		}
	} else if loadErr == nil && resource.revision == state.AuthorizationRevision && state.UsesPendingClient {
		if resource.typ == "connection" {
			_, err = q.ClearPendingConnectionOAuthApp(ctx, dbq.ClearPendingConnectionOAuthAppParams{ID: resource.id, AuthorizationRevision: resource.revision})
		} else {
			_, err = q.ClearPendingMCPServerOAuthApp(ctx, dbq.ClearPendingMCPServerOAuthAppParams{ID: resource.id, AuthorizationRevision: resource.revision})
		}
		if err != nil {
			return OAuthCallbackResult{}, err
		}
	}
	if _, err := q.DeleteOAuthState(ctx, stateToken); err != nil {
		return OAuthCallbackResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return OAuthCallbackResult{}, err
	}
	return OAuthCallbackResult{RedirectURL: authorizationErrorRedirect(state.RedirectUri, status, cause)}, nil
}

func mapSourceType(sourceType string) string {
	if sourceType == "mcp" {
		return "mcp_server"
	}
	return sourceType
}

// OAuthCallback validates provider results without replacing active credentials
// until the final locked transaction can also create the target binding.
func (s *Service) OAuthCallback(ctx context.Context, code, stateToken, providerError, providerDescription string) (OAuthCallbackResult, error) {
	if stateToken == "" || code == "" && providerError == "" {
		return OAuthCallbackResult{}, ErrOAuthMissingParams
	}
	if providerError != "" {
		cause := errors.New(providerError)
		if providerDescription != "" {
			cause = fmt.Errorf("%s: %s", providerError, providerDescription)
		}
		return s.discardAuthorization(ctx, stateToken, "denied", cause)
	}
	q := dbq.New(s.db.Pool())
	state, err := q.GetOAuthState(ctx, stateToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthCallbackResult{}, ErrOAuthInvalidState
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	resource, _, err := s.validateCallback(ctx, q, state, false)
	if err != nil {
		return s.discardAuthorization(ctx, stateToken, "invalidated", err)
	}
	verifier, err := s.encryptor.Get(ctx, "oauth_state/"+stateToken+"/code_verifier", state.CodeVerifier)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	ref := resourceSecretRef(resource)
	clientIDRef, clientSecretRef := resource.clientID, resource.clientSecret
	if state.UsesPendingClient {
		clientIDRef, clientSecretRef = resource.pendingClientID, resource.pendingClientSecret
	}
	clientID, err := s.encryptor.Get(ctx, ref+"/client_id", clientIDRef)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	clientSecret, err := s.encryptor.Get(ctx, ref+"/client_secret", clientSecretRef)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	token, err := s.oauthClient.ExchangeCode(ctx, resource.tokenURL, code, verifier, callbackURL, clientID, clientSecret)
	if err != nil {
		s.logger.Warn("OAuth token exchange failed", zap.Error(err))
		return s.discardAuthorization(ctx, stateToken, "exchange_failed", err)
	}
	granted := oauth.CanonicalScopes(state.RequestedScopes)
	if token.ScopePresent {
		granted = oauth.CanonicalScopes(token.Scope)
	}
	if !oauth.CoversScopes(state.RequestedScopes, granted) {
		return s.discardAuthorization(ctx, stateToken, "partial_grant", errors.New("provider grant does not cover required scopes"))
	}
	accessRef, err := s.encryptor.Put(ctx, ref+"/access_token", token.AccessToken)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	refreshRef := ""
	if token.RefreshToken != "" {
		refreshRef, err = s.encryptor.Put(ctx, ref+"/refresh_token", token.RefreshToken)
		if err != nil {
			return OAuthCallbackResult{}, err
		}
	}
	var expiresAt pgtype.Timestamptz
	if token.ExpiresIn > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second), Valid: true}
	}

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	defer tx.Rollback(ctx)
	q = dbq.New(tx)
	state, err = q.GetOAuthStateForUpdate(ctx, stateToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthCallbackResult{}, ErrOAuthInvalidState
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	resource, need, err := s.validateCallback(ctx, q, state, true)
	if err != nil {
		_ = tx.Rollback(ctx)
		return s.discardAuthorization(ctx, stateToken, "invalidated", err)
	}
	if token.RefreshToken == "" {
		refreshRef = resource.refreshToken
	}
	var affected int64
	if resource.typ == "connection" {
		affected, err = q.ActivateConnectionWithCredentials(ctx, dbq.ActivateConnectionWithCredentialsParams{
			ID: resource.id, AuthorizationRevision: state.AuthorizationRevision, AccessTokenRef: accessRef,
			TokenExpiresAt: expiresAt, RefreshToken: refreshRef, GrantedScopes: granted, UsesPendingClient: state.UsesPendingClient,
		})
		if err == nil && affected == 1 {
			affected, err = q.ReplaceConnectionNeedBinding(ctx, dbq.ReplaceConnectionNeedBindingParams{NeedID: state.NeedID, ResourceID: resource.id, ExpectedResourceID: state.ExpectedPriorResourceID})
		}
	} else {
		affected, err = q.ActivateMCPServerWithCredentials(ctx, dbq.ActivateMCPServerWithCredentialsParams{
			ID: resource.id, AuthorizationRevision: state.AuthorizationRevision, AccessTokenRef: accessRef,
			TokenExpiresAt: expiresAt, RefreshToken: refreshRef, GrantedScopes: granted, UsesPendingClient: state.UsesPendingClient,
		})
		if err == nil && affected == 1 {
			affected, err = q.ReplaceMCPServerNeedBinding(ctx, dbq.ReplaceMCPServerNeedBindingParams{NeedID: state.NeedID, ResourceID: resource.id, ExpectedResourceID: state.ExpectedPriorResourceID})
		}
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	if affected != 1 || need.ID != state.NeedID {
		return OAuthCallbackResult{}, service.Detail(service.ErrConflict, "OAuth target changed")
	}
	if _, err := q.DeleteOAuthState(ctx, stateToken); err != nil {
		return OAuthCallbackResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return OAuthCallbackResult{}, err
	}
	if resource.typ == "mcp_server" {
		s.refreshMCPAfterAuth(ctx, uuid.UUID(state.AgentID.Bytes), state.Slug, token.AccessToken)
	}
	successRedirect := authorizationErrorRedirect(state.RedirectUri, "authorized", nil)
	u, err := url.Parse(successRedirect)
	if err != nil {
		panic("connections: validated OAuth redirect is invalid")
	}
	query := u.Query()
	query.Set("resource_id", uuid.UUID(resource.id.Bytes).String())
	u.RawQuery = query.Encode()
	return OAuthCallbackResult{RedirectURL: u.String()}, nil
}

// OAuthStart keeps the existing endpoint compatible while routing through the
// need-aware authorization lifecycle.
func (s *Service) OAuthStart(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, redirectURI string) (string, error) {
	started, err := s.StartAuthorizationForNeed(ctx, p, agentID, "connection", slug, uuid.Nil, "", redirectURI, false)
	return started.AuthorizeURL, err
}

// MCPOAuthStart keeps the MCP endpoint compatible with the same lifecycle.
func (s *Service) MCPOAuthStart(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, redirectURI string) (string, error) {
	started, err := s.StartAuthorizationForNeed(ctx, p, agentID, "mcp_server", slug, uuid.Nil, "", redirectURI, false)
	return started.AuthorizeURL, err
}
