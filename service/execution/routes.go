package execution

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RouteSelection struct {
	Ref   string
	Asset bool
}

func (s *Service) RouteAccess(ctx context.Context, p authz.Principal, agentID uuid.UUID, method, path, rawPath string) (RouteSelection, error) {
	q := dbq.New(s.db.Pool())
	a, err := q.GetAgentByID(ctx, pgID(agentID))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return RouteSelection{}, err
		}
		return RouteSelection{}, service.ErrNotFound
	}
	return authorizeRoute(ctx, q, p, a, method, path, rawPath)
}

func authorizeRoute(ctx context.Context, q *dbq.Queries, p authz.Principal, a dbq.Agent, method, path, rawPath string) (RouteSelection, error) {
	var out RouteSelection
	req := &http.Request{Method: method, URL: &url.URL{Path: path, RawPath: rawPath}}
	if path == "/__air" || strings.HasPrefix(path, "/__air/") {
		// Match the private listener's exact public asset pattern. A prefix
		// check would also admit paths that fall through to a custom catch-all.
		_, asset, err := MatchRoute([]dbq.AgentRoute{{Method: http.MethodGet, Path: "/__air/assets/{name}"}}, req)
		if err != nil {
			return out, err
		}
		if !asset {
			return out, service.ErrNotFound
		}
		out.Asset = true
	}
	if path == "/health" || path == "/refresh" || strings.HasPrefix(path, "/job/") || strings.HasPrefix(path, "/webhook/") {
		return out, service.ErrNotFound
	}
	p, err := Principal(ctx, q, p)
	if err != nil {
		return out, err
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, uuid.UUID(a.ID.Bytes)); err != nil {
		return out, err
	}
	access, _, err := p.EffectiveAgentAccessChecked(ctx, q, uuid.UUID(a.ID.Bytes))
	if err != nil {
		return out, err
	}
	if !authz.AccessAtLeast(access, agentsdk.AccessPublic) {
		return out, service.ErrForbidden
	}
	required := agentsdk.AccessPublic
	if !out.Asset {
		routes, err := q.ListRoutesByAgent(ctx, a.ID)
		if err != nil {
			return out, err
		}
		route, found, err := MatchRoute(routes, req)
		if err != nil {
			return out, err
		}
		if !found {
			return out, service.ErrNotFound
		}
		required, out.Ref = agentsdk.Access(route.Access), route.Method+" "+route.Path
	}
	if required == agentsdk.AccessPublic && !a.AllowPublicRoutes {
		required = agentsdk.AccessUser
	}
	if !authz.AccessAtLeast(access, required) {
		if p.Kind == authz.KindAnonymousUser {
			return out, service.ErrUnauthorized
		}
		return out, service.ErrForbidden
	}
	return out, nil
}

// MatchRoute uses the same ServeMux semantics as the app listener.
func MatchRoute(routes []dbq.AgentRoute, req *http.Request) (selected dbq.AgentRoute, ok bool, err error) {
	mux := http.NewServeMux()
	byPattern := make(map[string]dbq.AgentRoute, len(routes))
	defer func() {
		if recovered := recover(); recovered != nil {
			selected, ok, err = dbq.AgentRoute{}, false, fmt.Errorf("register route pattern: %v", recovered)
		}
	}()
	for _, route := range routes {
		pattern := route.Method + " " + route.Path
		mux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
		byPattern[pattern] = route
	}
	_, pattern := mux.Handler(req)
	selected, ok = byPattern[pattern]
	return
}
