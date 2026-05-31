// Package sysagent is the in-airlock chat agent that lets operators
// manage agents, bridges, connections, members, A2A, runs, and (later)
// other tenant resources through tool calls.
//
// No JS VM, no per-agent connections, no Sol — sysagent runs inside
// airlock and its tools are typed Go functions wrapping existing
// service.{domain} methods. Every tool call uses the caller's
// authz.Principal; the service layer's authz.Authorize gates by
// action.
//
// One sysagent per Airlock instance, per-user multi-conversation chat
// history. Schema lives in migrations/002_a2a.sql (system_conversations,
// system_messages, system_audit).
package sysagent

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/google/uuid"
)

// principalKey is the unexported context key under which the chat
// loop stashes the caller's Principal before invoking goai. Tools
// pull it back out via principalFromCtx; the key being unexported
// means nothing else in the codebase can fabricate a Principal here.
type principalKey struct{}

// withPrincipal returns a new context carrying p. Called once per
// HTTP request, at the sysagent boundary, before goai.StreamText.
func withPrincipal(ctx context.Context, p authz.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// principalFromCtx returns the Principal stashed by withPrincipal, or
// a zero Principal if absent. Authorize() will reject a zero principal
// with ErrUnauthorized on every gated action, so the absence case
// fails closed (never silently runs as something).
func principalFromCtx(ctx context.Context) authz.Principal {
	if p, ok := ctx.Value(principalKey{}).(authz.Principal); ok {
		return p
	}
	return authz.Principal{}
}

// principalForUser builds a registered-user principal from the
// authenticated user's id + tenant role. Used by the auto-resume path
// (handler.resumeConversation) where there's no live HTTP request to pull
// claims off of — the conversation carries who owns it and we look up the
// current tenant role from the users table fresh.
func principalForUser(userID uuid.UUID, tenantRole string) authz.Principal {
	return authz.UserPrincipal(userID, auth.Role(tenantRole))
}

// conversationIDKey is the unexported context key under which the chat loop
// stashes the current conversation id before invoking goai. Tools that need
// to route async callbacks back to the conversation (build upgrades,
// rollbacks) read it back via conversationIDFromCtx.
type conversationIDKey struct{}

// withConversationID returns a new context carrying the current sysagent
// conversation id. Called once per chat turn alongside withPrincipal.
func withConversationID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, conversationIDKey{}, id)
}

// conversationIDFromCtx returns the conversation id stashed by withConversationID as a
// UUID string (the shape every downstream service.UpgradeRequest /
// RollbackRequest takes). Returns "" when absent; the caller treats
// that as "no conversation association" — the async notifier just won't be
// invoked.
func conversationIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(conversationIDKey{}).(uuid.UUID); ok {
		return id.String()
	}
	return ""
}
