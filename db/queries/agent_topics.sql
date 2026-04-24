-- name: UpsertTopic :exec
INSERT INTO agent_topics (agent_id, slug, description)
VALUES (@agent_id, @slug, @description)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListTopicsByAgent :many
SELECT * FROM agent_topics WHERE agent_id = $1;

-- name: DeleteTopicsByAgentExcept :exec
DELETE FROM agent_topics
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: GetTopicBySlug :one
SELECT * FROM agent_topics WHERE agent_id = @agent_id AND slug = @slug;

-- name: SubscribeTopic :exec
INSERT INTO topic_subscriptions (topic_id, conversation_id)
VALUES (@topic_id, @conversation_id)
ON CONFLICT DO NOTHING;

-- name: UnsubscribeTopic :exec
DELETE FROM topic_subscriptions
WHERE topic_id = @topic_id AND conversation_id = @conversation_id;

-- name: ListTopicSubscriptions :many
SELECT ts.id, ts.topic_id, ts.conversation_id, ts.created_at, at.slug as topic_slug, at.description as topic_description
FROM topic_subscriptions ts
JOIN agent_topics at ON at.id = ts.topic_id
WHERE at.agent_id = @agent_id AND ts.conversation_id = @conversation_id;

-- name: ListSubscribedConversations :many
SELECT ts.conversation_id
FROM topic_subscriptions ts
JOIN agent_topics at ON at.id = ts.topic_id
WHERE at.agent_id = @agent_id AND at.slug = @slug;
