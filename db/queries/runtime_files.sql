-- name: CreateAnonymousToolConversation :one
INSERT INTO agent_conversations(agent_id,user_id,source,title,metadata,settings)
VALUES (@agent_id,NULL,'mcp-tool',@title,'{}','{}') RETURNING *;

-- name: MarkRuntimeAttachment :execrows
INSERT INTO runtime_attached_files(run_id,path) VALUES (@run_id,@path) ON CONFLICT DO NOTHING;
