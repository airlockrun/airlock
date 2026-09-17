-- name: UpsertTopic :exec
INSERT INTO agent_topics (agent_id, slug, description, llm_hint, access, per_user, enrollment)
VALUES (@agent_id, @slug, @description, @llm_hint, @access, @per_user, @enrollment)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    description = EXCLUDED.description,
    llm_hint = EXCLUDED.llm_hint,
    access = EXCLUDED.access,
    per_user = EXCLUDED.per_user,
    enrollment = EXCLUDED.enrollment,
    updated_at = now();

-- name: ListTopicsByAgent :many
SELECT * FROM agent_topics WHERE agent_id = $1;

-- name: DeleteTopicsByAgentExcept :exec
DELETE FROM agent_topics
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: GetTopicBySlug :one
SELECT * FROM agent_topics WHERE agent_id = @agent_id AND slug = @slug;

-- name: SubscribeTopic :exec
SELECT set_topic_subscription(@topic_id::uuid, @conversation_id::uuid, true);

-- name: UnsubscribeTopic :exec
SELECT set_topic_subscription(@topic_id::uuid, @conversation_id::uuid, false);

-- name: LockNotificationTopic :one
SELECT * FROM agent_topics WHERE id = @id FOR UPDATE;

-- name: IsTopicRouteEnabled :one
SELECT EXISTS (
    SELECT 1 FROM topic_subscriptions s JOIN agent_topics t ON t.id = s.topic_id
    LEFT JOIN topic_preferences p ON p.topic_id = t.id AND p.user_id = s.user_id
    WHERE s.topic_id = @topic_id AND s.conversation_id = @conversation_id
      AND COALESCE(p.enabled, t.enrollment = 'default_on')
)::boolean;

-- name: ListNotificationCandidates :many
SELECT c.*, COALESCE(s.automatic, false)::boolean AS automatic,
       (s.id IS NOT NULL)::boolean AS routed
FROM agent_conversations c
JOIN agent_topics t ON t.agent_id = c.agent_id
LEFT JOIN topic_preferences p ON p.topic_id = t.id AND p.user_id = c.user_id
LEFT JOIN topic_subscriptions s ON s.topic_id = t.id AND s.conversation_id = c.id
WHERE t.id = @topic_id AND c.source = 'bridge' AND c.user_id IS NOT NULL
  AND COALESCE(p.enabled, t.enrollment = 'default_on')
  AND (sqlc.narg(user_id)::uuid IS NULL OR c.user_id = sqlc.narg(user_id))
ORDER BY c.user_id, (s.id IS NOT NULL) DESC, c.user_activity_at DESC NULLS LAST, c.id;

-- name: AddAutomaticTopicRoute :exec
INSERT INTO topic_subscriptions (topic_id, conversation_id, user_id, automatic)
VALUES (@topic_id, @conversation_id, @user_id, true);

-- name: DeleteTopicRoute :exec
DELETE FROM topic_subscriptions WHERE topic_id = @topic_id AND conversation_id = @conversation_id;

-- name: MarkNotificationRouteLost :exec
UPDATE agent_conversations SET notification_route_lost_at = now()
WHERE id = @id AND user_activity_at IS NOT DISTINCT FROM sqlc.narg(observed_activity)::timestamptz;

-- name: ListEffectiveTopicPreferences :many
SELECT t.*, COALESCE(p.enabled, t.enrollment = 'default_on')::boolean AS enabled
FROM agent_topics t LEFT JOIN topic_preferences p ON p.topic_id = t.id AND p.user_id = @user_id
WHERE t.agent_id = @agent_id;
