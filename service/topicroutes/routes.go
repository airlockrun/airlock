// Package topicroutes resolves enrolled users to live bridge destinations.
package topicroutes

import (
	"context"
	"errors"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrDestinationGone identifies a definitive platform rejection of the route,
// not an ambiguous send outcome or a transient transport failure.
var ErrDestinationGone = errors.New("notification destination is unavailable")

// Set changes the preference and, for bridge conversations, the explicit route.
// Callers establish conversation ownership or current-app authority first.
func Set(ctx context.Context, q *dbq.Queries, topic dbq.AgentTopic, conversationID pgtype.UUID, enabled bool) error {
	c, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{ID: conversationID, AgentID: topic.AgentID})
	if err != nil {
		return err
	}
	ok, err := Eligible(ctx, q, topic, c.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return apperr.ErrForbidden
	}
	if enabled {
		return q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{TopicID: topic.ID, ConversationID: c.ID})
	}
	return q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{TopicID: topic.ID, ConversationID: c.ID})
}

// Eligible checks the live account and topic access without inferring membership
// from the existence of a conversation or substituting an application owner.
func Eligible(ctx context.Context, q *dbq.Queries, topic dbq.AgentTopic, userID pgtype.UUID) (bool, error) {
	if !userID.Valid {
		return false, nil
	}
	access, err := authz.EffectiveAgentAccessForStoredUser(ctx, q, uuid.UUID(userID.Bytes), uuid.UUID(topic.AgentID.Bytes))
	if err != nil {
		if errors.Is(err, apperr.ErrForbidden) || errors.Is(err, apperr.ErrUnauthorized) {
			return false, nil
		}
		return false, err
	}
	if err := authz.AuthorizeResolvedAccess(authz.AgentTopic, access); err != nil {
		if errors.Is(err, apperr.ErrForbidden) {
			return false, nil
		}
		return false, err
	}
	return authz.AccessAtLeast(access, agentsdk.Access(topic.Access)), nil
}

// Usable distinguishes permanent route loss from a temporarily unavailable
// bridge. Database failures are errors, never evidence that a route is lost.
func Usable(ctx context.Context, q *dbq.Queries, topic dbq.AgentTopic, c dbq.ListNotificationCandidatesRow) (usable, permanent bool, err error) {
	if c.NotificationRouteLostAt.Valid {
		return false, true, nil
	}
	ok, err := Eligible(ctx, q, topic, c.UserID)
	if err != nil || !ok {
		return false, !ok && err == nil, err
	}
	if !c.BridgeID.Valid || !c.ExternalID.Valid || c.ExternalID.String == "" {
		return false, true, nil
	}
	bridge, err := q.GetBridgeByID(ctx, c.BridgeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if bridge.AgentID != topic.AgentID || bridge.IsSystem || bridge.Type != "telegram" {
		return false, true, nil
	}
	identity, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{Platform: bridge.Type, PlatformUserID: c.ExternalID.String})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if identity.UserID != c.UserID {
		return false, true, nil
	}
	return bridge.Status == "active", false, nil
}

// Resolve repairs permanent losses and returns selected destinations, including
// reserved temporarily unavailable routes that delivery must report. The topic
// row lock also serializes explicit subscription mutations and manifest sync.
// A transiently unavailable existing route reserves its place, preventing an
// alternate destination from receiving a possibly duplicate notification.
func Resolve(ctx context.Context, database *db.DB, topicID, userID pgtype.UUID) ([]dbq.ListNotificationCandidatesRow, error) {
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	topic, err := q.LockNotificationTopic(ctx, topicID)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListNotificationCandidates(ctx, dbq.ListNotificationCandidatesParams{TopicID: topicID, UserID: userID})
	if err != nil {
		return nil, err
	}
	var result []dbq.ListNotificationCandidatesRow
	for start := 0; start < len(rows); {
		end := start + 1
		for end < len(rows) && rows[end].UserID == rows[start].UserID {
			end++
		}
		reserved := false
		var candidate *dbq.ListNotificationCandidatesRow
		for i := start; i < end; i++ {
			c := rows[i]
			usable, permanent, err := Usable(ctx, q, topic, c)
			if err != nil {
				return nil, err
			}
			if c.Routed {
				if permanent {
					if err := q.DeleteTopicRoute(ctx, dbq.DeleteTopicRouteParams{TopicID: topic.ID, ConversationID: c.ID}); err != nil {
						return nil, err
					}
					continue
				}
				reserved = true
				result = append(result, c)
			} else if usable && candidate == nil {
				candidate = &c
			}
		}
		if !reserved && candidate != nil {
			if err := q.AddAutomaticTopicRoute(ctx, dbq.AddAutomaticTopicRouteParams{TopicID: topic.ID, ConversationID: candidate.ID, UserID: candidate.UserID}); err != nil {
				return nil, err
			}
			result = append(result, *candidate)
		}
		start = end
	}
	return result, tx.Commit(ctx)
}
