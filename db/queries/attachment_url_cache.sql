-- name: GetCachedAttachmentURL :one
-- Returns the cached presigned URL only if it has at least @min_remaining left
-- before expiry. Caller treats "no rows" as cache miss → mint fresh.
SELECT url, expires_at
FROM attachment_url_cache
WHERE canonical_key = @canonical_key
  AND expires_at > now() + @min_remaining::interval;

-- name: UpsertCachedAttachmentURL :exec
INSERT INTO attachment_url_cache (canonical_key, url, expires_at)
VALUES (@canonical_key, @url, @expires_at)
ON CONFLICT (canonical_key) DO UPDATE SET
    url        = EXCLUDED.url,
    expires_at = EXCLUDED.expires_at;

-- name: PruneExpiredAttachmentURLs :execrows
-- Background pruner: delete URL cache rows that expired more than 24h ago.
-- Stale rows aren't harmful (just unused) but bounded growth is nice.
DELETE FROM attachment_url_cache WHERE expires_at < now() - interval '24 hours';
