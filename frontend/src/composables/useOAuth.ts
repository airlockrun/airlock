import api from '@/api/client'

/**
 * Start an OAuth flow: redirect the browser to the provider's
 * authorization URL.
 *
 * The redirect_uri we hand to the server (and ultimately to the OAuth
 * provider's callback chain) must use the agent's UUID, not its slug.
 * The router cosmetically repaints `window.location.href` to show the
 * slug for vanity reasons; using that verbatim breaks the post-auth
 * return if the agent is renamed during the flow (the user lands on
 * the agents list with a `staleAgent` notice instead of their detail
 * page). The OAuth token itself is bound to the UUID via the state
 * row's `agent_id` — only the redirect target is rename-vulnerable.
 */
export async function startOAuth(agentId: string, slug: string) {
  const { data } = await api.post('/api/v1/credentials/oauth/start', {
    agentId,
    slug,
    redirectUri: canonicalAgentURL(agentId),
  })
  if (data.authorizeUrl) {
    window.location.href = data.authorizeUrl
  } else {
    throw new Error('No authorization URL returned')
  }
}

// canonicalAgentURL rewrites the current URL with the agent's UUID in
// the {id} slot, preserving the tab/sub-route the user was on (e.g.
// `/agents/{slug}/connections` → `/agents/{UUID}/connections`). When
// the path doesn't follow the /agents/{id}/... shape we fall back to
// the bare detail URL — the connection authorization is per-agent so
// the detail page is always a reasonable landing spot.
export function canonicalAgentURL(agentId: string): string {
  const url = new URL(window.location.href)
  const parts = url.pathname.split('/')
  if (parts[1] === 'agents' && parts.length > 2 && parts[2] !== agentId) {
    parts[2] = agentId
    url.pathname = parts.join('/')
    return url.toString()
  }
  return `${url.origin}/agents/${agentId}`
}
