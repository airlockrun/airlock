<script setup lang="ts">
// ConsentView — landing page for /oauth/authorize after the user is
// signed in. The server redirects the browser here with the original
// authorize parameters reflected; the SPA POSTs the user's decision
// to /api/v1/oauth/consent which returns the redirect URL to bounce
// back to the OAuth client (Claude Desktop / VSCode / Codex loopback).
//
// We don't fetch a separate /authorize-context endpoint — everything
// we need (client name, agent slug + name, scope) is either in the
// query string or fetched lazily from existing /api/v1 endpoints.
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'

const route = useRoute()
const router = useRouter()
const { t } = useAirlockI18n()

const submitting = ref(false)
const error = ref('')
const agentInfo = ref<{ name: string; slug: string } | null>(null)
const clientInfo = ref<{ name: string } | null>(null)
const decisionInFlight = ref<'approve' | 'deny' | null>(null)

// Pull the canonical authorize params from the URL.
const q = computed(() => route.query)
const clientId = computed(() => String(q.value.client_id ?? ''))
const redirectURI = computed(() => String(q.value.redirect_uri ?? ''))
const state = computed(() => String(q.value.state ?? ''))
const codeChallenge = computed(() => String(q.value.code_challenge ?? ''))
const codeChallengeMethod = computed(() => String(q.value.code_challenge_method ?? ''))
const scope = computed(() => String(q.value.scope ?? 'mcp'))
const resource = computed(() => String(q.value.resource ?? ''))
const consentToken = computed(() => String(q.value.consent_token ?? ''))

// Derive the agent slug/UUID from the resource URL so we can fetch
// the human-readable name. The resource URL is
// {PUBLIC_URL}/api/agent/{identifier}/mcp.
const agentIdentifier = computed(() => {
  const m = resource.value.match(/\/api\/agent\/([^/]+)\/mcp$/)
  return m ? m[1] : ''
})
const consentApp = computed(() => {
  const name = agentInfo.value?.name || agentIdentifier.value
  const slug = agentInfo.value?.slug
  return slug && slug !== name ? t('auth.consent.appWithSlug', { name, slug }) : name
})

async function fetchContext() {
  if (!agentIdentifier.value || !clientId.value) {
    error.value = t('auth.consent.missingParameters')
    return
  }
  try {
    // Reuse the existing agent-detail endpoint to get a human name.
    const { data } = await api.get(`/api/v1/agents/${agentIdentifier.value}`)
    agentInfo.value = { name: data?.agent?.name ?? agentIdentifier.value, slug: data?.agent?.slug ?? agentIdentifier.value }
  } catch {
    agentInfo.value = { name: agentIdentifier.value, slug: agentIdentifier.value }
  }
  // We don't have a "get one client" endpoint — fall back to using
  // the client_id as-is. (The server-side /authorize handler already
  // verified the client exists; the user-visible name is just nicer
  // formatting.)
  clientInfo.value = { name: clientId.value }
}

async function decide(decision: 'approve' | 'deny') {
  if (submitting.value) return
  submitting.value = true
  decisionInFlight.value = decision
  try {
    const { data } = await api.post('/api/v1/oauth/consent', {
      decision,
      client_id: clientId.value,
      redirect_uri: redirectURI.value,
      state: state.value,
      code_challenge: codeChallenge.value,
      code_challenge_method: codeChallengeMethod.value,
      scope: scope.value,
      resource: resource.value,
      consent_token: consentToken.value,
    })
    if (data?.redirect_to) {
      // Top-level navigation so the OAuth client (which is listening
      // on its loopback redirect_uri) captures the auth code.
      window.location.href = data.redirect_to
      return
    }
    error.value = t('auth.consent.missingRedirect')
  } catch (err: any) {
    error.value = err?.response?.data?.error || err?.message || t('auth.consent.failed')
  } finally {
    submitting.value = false
    decisionInFlight.value = null
  }
}

onMounted(fetchContext)
</script>

<template>
  <div class="consent-page">
    <Card class="consent-card">
      <template #title>{{ t('auth.consent.title') }}</template>
      <template #content>
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

        <div v-if="!error">
          <p>{{ t('auth.consent.request', { client: clientInfo?.name || clientId, app: consentApp }) }}</p>

          <p style="margin-top: 1rem">{{ t('auth.consent.abilities') }}</p>
          <ul>
            <li>{{ t('auth.consent.sendAndCall', { scope }) }}</li>
            <li>{{ t('auth.consent.readConversations') }}</li>
          </ul>

          <Message severity="info" :closable="false" style="margin-top: 1rem">
            {{ t('auth.consent.duration') }}
            <RouterLink to="/settings">{{ t('auth.consent.connectedAppsLink') }}</RouterLink>.
          </Message>
        </div>
      </template>
      <template #footer>
        <div class="footer-actions">
          <Button
            :label="t('auth.action.deny')"
            severity="secondary"
            :disabled="submitting"
            :loading="decisionInFlight === 'deny'"
            @click="decide('deny')"
          />
          <Button
            :label="t('auth.action.approve')"
            :disabled="submitting || !!error"
            :loading="decisionInFlight === 'approve'"
            @click="decide('approve')"
          />
        </div>
      </template>
    </Card>
  </div>
</template>

<style scoped>
.consent-page {
  display: flex;
  justify-content: center;
  padding: 3rem 1rem;
}
.consent-card {
  max-width: 36rem;
  width: 100%;
}
.footer-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
ul {
  padding-left: 1.25rem;
  margin: 0.5rem 0 0;
}
li {
  margin: 0.25rem 0;
}
code {
  background: var(--p-surface-100);
  padding: 0 0.25rem;
  border-radius: 3px;
  font-size: 0.9em;
}
/* surface-100 stays light in dark mode; swap it so inline code is readable. */
:root.dark code {
  background: var(--p-surface-800);
}
</style>
