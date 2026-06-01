package convert

import (
	"fmt"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"github.com/jackc/pgx/v5/pgtype"
)

// AgentToProto maps an agents row to the wire AgentInfo. Does not
// set Running or YourAccess — those are layered on by the caller
// when known (the operator-facing list/detail handlers stamp both;
// agent-internal lookups leave them blank).
func AgentToProto(a dbq.Agent) *airlockv1.AgentInfo {
	return &airlockv1.AgentInfo{
		Id:              PgUUIDToString(a.ID),
		Name:            a.Name,
		Slug:            a.Slug,
		Description:     a.Description,
		Emoji:           a.Emoji,
		Status:          a.Status,
		UpgradeStatus:   a.UpgradeStatus,
		AutoFix:         a.AutoFix,
		ErrorMessage:    a.ErrorMessage,
		CreatedAt:       PgTimestampToProto(a.CreatedAt),
		UpdatedAt:       PgTimestampToProto(a.UpdatedAt),
		BuildModel:      a.BuildModel,
		ExecModel:       a.ExecModel,
		BuildProviderId: PgUUIDToString(a.BuildProviderID),
		ExecProviderId:  PgUUIDToString(a.ExecProviderID),
	}
}

// ConnectionToProto strips the raw secret columns (ClientID, ClientSecret,
// AccessTokenRef, RefreshToken, AuthInjection, Config) and returns only
// the operator-visible projection: derived booleans (Authorized,
// HasOAuthApp), the auth-flow start URL, and any human-readable
// warnings. Every consumer that surfaces a connection — web UI handler
// and the in-airlock system agent — goes through this projection so a
// new sensitive column can't leak to one surface without leaking to
// both.
func ConnectionToProto(c dbq.Connection, publicURL, agentID string) *airlockv1.ConnectionInfo {
	authorized := c.AccessTokenRef != ""
	hasOAuthApp := c.ClientID != "" && c.ClientSecret != ""

	var authURL string
	if c.AuthMode == "oauth" {
		authURL = fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	} else if c.AuthMode == "token" {
		authURL = fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	}

	return &airlockv1.ConnectionInfo{
		Id:                PgUUIDToString(c.ID),
		Slug:              c.Slug,
		Name:              c.Name,
		Description:       c.Description,
		AuthMode:          c.AuthMode,
		Authorized:        authorized,
		HasOauthApp:       hasOAuthApp,
		SetupInstructions: c.SetupInstructions,
		AuthUrl:           authURL,
		TokenExpiresAt:    PgTimestampToProto(c.TokenExpiresAt),
		Warnings:          ConnectionWarnings(c.AuthMode, authorized, c.RefreshToken != "", c.TokenExpiresAt),
	}
}

// ConnectionDTOToProto maps the connections service Connection DTO
// (already stripped of token bytes) to the wire ConnectionInfo. Used
// by ListConnections on both web and sysagent surfaces.
func ConnectionDTOToProto(c connsvc.Connection, publicURL, agentID string) *airlockv1.ConnectionInfo {
	var authURL string
	if c.AuthMode == "oauth" {
		authURL = fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	} else if c.AuthMode == "token" {
		authURL = fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	}
	ci := &airlockv1.ConnectionInfo{
		Id:                c.ID.String(),
		Slug:              c.Slug,
		Name:              c.Name,
		Description:       c.Description,
		AuthMode:          c.AuthMode,
		Authorized:        c.Authorized,
		HasOauthApp:       c.HasOAuthApp,
		SetupInstructions: c.SetupInstructions,
		AuthUrl:           authURL,
		Warnings:          ConnectionWarnings(c.AuthMode, c.Authorized, c.HasRefreshToken, c.TokenExpiresAt),
	}
	if c.TokenExpiresAt.Valid {
		ci.TokenExpiresAt = PgTimestampToProto(c.TokenExpiresAt)
	}
	return ci
}

// ConnectionWarnings is the shared rule set for warning strings shown
// on a connection card. Exposed so the credentials handler — which
// builds ConnectionInfo from the connections service DTO (not the raw
// dbq row) — uses the same warning list as ConnectionToProto.
func ConnectionWarnings(authMode string, authorized, hasRefreshToken bool, tokenExpiresAt pgtype.Timestamptz) []string {
	if authMode != "oauth" || !authorized {
		return nil
	}
	var warnings []string
	if !hasRefreshToken {
		warnings = append(warnings, "No refresh token — this connection will stop working once its access token expires. Re-authorize to fix.")
	}
	if tokenExpiresAt.Valid && tokenExpiresAt.Time.Before(time.Now()) {
		warnings = append(warnings, "Authorization has expired — re-authorize.")
	}
	return warnings
}

// WebhookToProto masks the verification secret (first/last 4 of >8-char
// secrets, "***" otherwise) and builds the public ingress URL.
func WebhookToProto(wh dbq.ListWebhooksByAgentWithStatusRow, publicURL, agentID string) *airlockv1.WebhookInfo {
	publicURLFull := fmt.Sprintf("%s/webhooks/%s/%s", publicURL, agentID, wh.Path)

	var secretMasked string
	if wh.Secret != "" && len(wh.Secret) > 8 {
		secretMasked = wh.Secret[:4] + "..." + wh.Secret[len(wh.Secret)-4:]
	} else if wh.Secret != "" {
		secretMasked = "***"
	}

	return &airlockv1.WebhookInfo{
		Id:             PgUUIDToString(wh.ID),
		Path:           wh.Path,
		VerifyMode:     wh.VerifyMode,
		PublicUrl:      publicURLFull,
		SecretMasked:   secretMasked,
		LastReceivedAt: PgTimestampToProto(wh.LastReceivedAt),
		CreatedAt:      PgTimestampToProto(wh.CreatedAt),
		Description:    wh.Description,
	}
}

func CronToProto(c dbq.AgentCron) *airlockv1.CronInfo {
	return &airlockv1.CronInfo{
		Id:          PgUUIDToString(c.ID),
		Name:        c.Name,
		Schedule:    c.Schedule,
		LastFiredAt: PgTimestampToProto(c.LastFiredAt),
		CreatedAt:   PgTimestampToProto(c.CreatedAt),
		Description: c.Description,
	}
}

func RouteToProto(r dbq.AgentRoute) *airlockv1.RouteInfo {
	return &airlockv1.RouteInfo{
		Id:          PgUUIDToString(r.ID),
		Path:        r.Path,
		Method:      r.Method,
		Access:      r.Access,
		Description: r.Description,
	}
}

func AgentToolToProto(t dbq.AgentTool) *airlockv1.ToolInfo {
	return &airlockv1.ToolInfo{
		Id:           PgUUIDToString(t.ID),
		Name:         t.Name,
		Description:  t.Description,
		Access:       t.Access,
		InputSchema:  string(t.InputSchema),
		OutputSchema: string(t.OutputSchema),
	}
}

// AgentBuildListItemToProto maps a list row (no log fields) to the
// wire AgentBuildInfo. rollbackTargetSourceRef is resolved by the
// caller (the list query doesn't carry it; the handler builds a map
// keyed by build ID and threads the lookup through).
func AgentBuildListItemToProto(b dbq.ListAgentBuildsByAgentRow, rollbackTargetSourceRef string) *airlockv1.AgentBuildInfo {
	var rollbackTargetID string
	if b.RollbackTargetID.Valid {
		rollbackTargetID = PgUUIDToString(b.RollbackTargetID)
	}
	return &airlockv1.AgentBuildInfo{
		Id:                      PgUUIDToString(b.ID),
		AgentId:                 PgUUIDToString(b.AgentID),
		Type:                    b.Type,
		Status:                  b.Status,
		Instructions:            b.Instructions,
		ErrorMessage:            b.ErrorMessage,
		SourceRef:               b.SourceRef,
		ImageRef:                b.ImageRef,
		StartedAt:               PgTimestampToProto(b.StartedAt),
		FinishedAt:              PgTimestampToProto(b.FinishedAt),
		LlmCalls:                b.LlmCalls,
		LlmTokensIn:             b.LlmTokensIn,
		LlmTokensOut:            b.LlmTokensOut,
		LlmCostEstimate:         b.LlmCostEstimate,
		RollbackTargetId:        rollbackTargetID,
		RollbackTargetSourceRef: rollbackTargetSourceRef,
		SdkVersion:              b.SdkVersion,
	}
}

// AgentBuildDetailToProto maps the full build row (with sol/docker
// logs) to the wire AgentBuildInfo. rollbackTargetSourceRef is the
// resolved target row's SourceRef when this build is a rollback,
// blank otherwise.
func AgentBuildDetailToProto(b dbq.AgentBuild, rollbackTargetSourceRef string) *airlockv1.AgentBuildInfo {
	var rollbackTargetID string
	if b.RollbackTargetID.Valid {
		rollbackTargetID = PgUUIDToString(b.RollbackTargetID)
	}
	return &airlockv1.AgentBuildInfo{
		Id:                      PgUUIDToString(b.ID),
		AgentId:                 PgUUIDToString(b.AgentID),
		Type:                    b.Type,
		Status:                  b.Status,
		Instructions:            b.Instructions,
		SolLog:                  b.SolLog,
		DockerLog:               b.DockerLog,
		ErrorMessage:            b.ErrorMessage,
		SourceRef:               b.SourceRef,
		ImageRef:                b.ImageRef,
		StartedAt:               PgTimestampToProto(b.StartedAt),
		FinishedAt:              PgTimestampToProto(b.FinishedAt),
		LogSeq:                  b.LogSeq,
		LlmCalls:                b.LlmCalls,
		LlmTokensIn:             b.LlmTokensIn,
		LlmTokensOut:            b.LlmTokensOut,
		LlmCostEstimate:         b.LlmCostEstimate,
		RollbackTargetId:        rollbackTargetID,
		RollbackTargetSourceRef: rollbackTargetSourceRef,
		SdkVersion:              b.SdkVersion,
	}
}
