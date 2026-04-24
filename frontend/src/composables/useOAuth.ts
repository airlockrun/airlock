import api from '@/api/client'

/** Start an OAuth flow: redirect the browser to the provider's authorization URL. */
export async function startOAuth(agentId: string, slug: string) {
  const { data } = await api.post('/api/v1/credentials/oauth/start', {
    agentId,
    slug,
    redirectUri: window.location.href,
  })
  if (data.authorizeUrl) {
    window.location.href = data.authorizeUrl
  } else {
    throw new Error('No authorization URL returned')
  }
}
