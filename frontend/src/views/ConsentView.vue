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

const route = useRoute()
const router = useRouter()

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

// Derive the agent slug/UUID from the resource URL so we can fetch
// the human-readable name. The resource URL is
// {PUBLIC_URL}/api/agent/{identifier}/mcp.
const agentIdentifier = computed(() => {
  const m = resource.value.match(/\/api\/agent\/([^/]+)\/mcp$/)
  return m ? m[1] : ''
})

async function fetchContext() {
  if (!agentIdentifier.value || !clientId.value) {
    error.value = 'Missing OAuth parameters. Cannot continue.'
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
    })
    if (data?.redirect_to) {
      // Top-level navigation so the OAuth client (which is listening
      // on its loopback redirect_uri) captures the auth code.
      window.location.href = data.redirect_to
      return
    }
    error.value = 'Server did not return a redirect URL.'
  } catch (err: any) {
    error.value = err?.response?.data?.error || err?.message || 'Consent failed'
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
      <template #title>Authorize external app</template>
      <template #content>
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

        <div v-if="!error">
          <p>
            <strong>{{ clientInfo?.name || clientId }}</strong>
            is requesting access to your agent
            <strong>{{ agentInfo?.name || agentIdentifier }}</strong>
            <span v-if="agentInfo?.slug && agentInfo.slug !== agentInfo.name">
              (<code>{{ agentInfo.slug }}</code>)
            </span>.
          </p>

          <p style="margin-top: 1rem">It will be able to:</p>
          <ul>
            <li>Send prompts and call the tools this agent exposes (scope <code>{{ scope }}</code>).</li>
            <li>Read your conversations with this agent.</li>
          </ul>

          <Message severity="info" :closable="false" style="margin-top: 1rem">
            Access is granted for 90 days. You can revoke it any time in
            <RouterLink to="/settings">Settings &rarr; Connected apps</RouterLink>.
          </Message>
        </div>
      </template>
      <template #footer>
        <div class="footer-actions">
          <Button
            label="Deny"
            severity="secondary"
            :disabled="submitting"
            :loading="decisionInFlight === 'deny'"
            @click="decide('deny')"
          />
          <Button
            label="Approve"
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
