<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import api from '@/api/client'
import CredentialDialog from './CredentialDialog.vue'

interface MCPServer {
  id: string
  slug: string
  name: string
  url: string
  authMode: string
  authorized: boolean
  hasOauthApp: boolean
  toolCount: number
  authUrl?: string
  tokenExpiresAt?: string
  lastSyncedAt?: string
}

const props = defineProps<{ agentId: string }>()

const toast = useToast()
const confirm = useConfirm()
const servers = ref<MCPServer[]>([])
const loading = ref(true)
const credDialogVisible = ref(false)
const oauthAppDialogVisible = ref(false)
const selectedServer = ref<MCPServer | null>(null)
const oauthClientId = ref('')
const oauthClientSecret = ref('')
const oauthSaving = ref(false)
const callbackUrl = ref('')

// Per-server PrimeVue Menu refs (overflow ⋮ button). Map keyed by slug
// so each row owns its own menu instance — sharing one would mis-route
// clicks since the menu's positioning is anchored to its `toggle()`
// caller's event target, not to a logical "current row".
const overflowMenus = ref<Record<string, any>>({})
function setOverflowMenu(slug: string, el: any) {
  if (el) overflowMenus.value[slug] = el
}

// Pulled from each server row at click time so the menu items can
// branch on the row's authMode/authorized state without rebinding the
// `model` prop per click.
const menuTargetServer = ref<MCPServer | null>(null)

const overflowItems = computed(() => {
  const srv = menuTargetServer.value
  if (!srv) return []
  const items: any[] = []

  if (srv.authorized) {
    items.push({
      label: 'Disconnect',
      icon: 'pi pi-sign-out',
      command: () => disconnect(srv),
    })
  }

  // OAuth-app reset: relabels per mode. For oauth_discovery this forces
  // a fresh DCR on next Authorize; for oauth it lets the operator paste
  // a new client_id/secret. Either way it wipes the existing OAuth app
  // config + any credentials tied to it (the old creds would 401 since
  // they belong to the old client_id at the provider).
  if (srv.authMode === 'oauth_discovery' && srv.hasOauthApp) {
    items.push({
      label: 'Re-register OAuth client',
      icon: 'pi pi-refresh',
      command: () => resetOAuthApp(srv),
    })
  }
  if (srv.authMode === 'oauth') {
    items.push({
      label: srv.hasOauthApp ? 'Edit OAuth app' : 'Set OAuth app',
      icon: 'pi pi-pencil',
      command: () => editOAuthApp(srv),
    })
  }

  return items
})

function primaryAction(srv: MCPServer) {
  selectedServer.value = srv
  if (srv.authMode === 'oauth_discovery') {
    // Backend handles RFC 7591 DCR if no client_id is stored. If DCR
    // fails we get a 400 with a clear remediation message — surfaced
    // as a toast by startMCPOAuth.
    startMCPOAuth()
  } else if (srv.authMode === 'oauth') {
    if (srv.hasOauthApp) {
      // OAuth app already configured — just run the flow.
      startMCPOAuth()
    } else {
      // First-time configuration — paste client_id/secret.
      oauthClientId.value = ''
      oauthClientSecret.value = ''
      oauthAppDialogVisible.value = true
    }
  } else {
    credDialogVisible.value = true
  }
}

function openOverflow(event: Event, srv: MCPServer) {
  menuTargetServer.value = srv
  overflowMenus.value[srv.slug]?.toggle(event)
}

async function disconnect(srv: MCPServer) {
  confirm.require({
    message: `Sign out of ${srv.name || srv.slug}? Tokens are discarded; OAuth app config stays.`,
    header: 'Disconnect',
    icon: 'pi pi-sign-out',
    rejectProps: { label: 'Cancel', severity: 'secondary', outlined: true },
    acceptProps: { label: 'Disconnect' },
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/mcp-servers/${srv.slug}/credentials`)
        srv.authorized = false
        toast.add({ severity: 'success', summary: `Disconnected from ${srv.name || srv.slug}`, life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Disconnect failed', life: 5000 })
      }
    },
  })
}

async function resetOAuthApp(srv: MCPServer) {
  confirm.require({
    message: `Re-register OAuth client for ${srv.name || srv.slug}? Existing client and tokens will be discarded.`,
    header: 'Re-register OAuth client',
    icon: 'pi pi-refresh',
    rejectProps: { label: 'Cancel', severity: 'secondary', outlined: true },
    acceptProps: { label: 'Re-register' },
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/mcp-servers/${srv.slug}/credentials/oauth-app`)
        srv.hasOauthApp = false
        srv.authorized = false
        toast.add({ severity: 'success', summary: 'OAuth client cleared. Click Authorize to register a new one.', life: 4000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Reset failed', life: 5000 })
      }
    },
  })
}

async function editOAuthApp(srv: MCPServer) {
  // For `oauth` (manual) — wipe the old app first so the dialog isn't
  // ambiguous about whether saving "edits" or "replaces". The backend
  // path is the same as a fresh Set OAuth app from there.
  try {
    if (srv.hasOauthApp) {
      await api.delete(`/api/v1/agents/${props.agentId}/mcp-servers/${srv.slug}/credentials/oauth-app`)
      srv.hasOauthApp = false
      srv.authorized = false
    }
    selectedServer.value = srv
    oauthClientId.value = ''
    oauthClientSecret.value = ''
    oauthAppDialogVisible.value = true
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to reset OAuth app', life: 5000 })
  }
}

async function saveOAuthApp() {
  if (!selectedServer.value || !oauthClientId.value || !oauthClientSecret.value) return
  oauthSaving.value = true
  try {
    await api.put(`/api/v1/agents/${props.agentId}/mcp-servers/${selectedServer.value.slug}/credentials/oauth-app`, {
      clientId: oauthClientId.value,
      clientSecret: oauthClientSecret.value,
    })
    toast.add({ severity: 'success', summary: 'OAuth app saved. Starting authorization...', life: 3000 })
    oauthAppDialogVisible.value = false
    selectedServer.value.hasOauthApp = true
    startMCPOAuth()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to save OAuth app', life: 5000 })
  } finally {
    oauthSaving.value = false
  }
}

async function startMCPOAuth() {
  if (!selectedServer.value) return
  try {
    const { data } = await api.post('/api/v1/credentials/mcp/oauth/start', {
      agentId: props.agentId,
      slug: selectedServer.value.slug,
    })
    if (data.authorizeUrl) {
      window.location.href = data.authorizeUrl
    }
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'OAuth start failed', life: 5000 })
  }
}

function authModeLabel(mode: string): string {
  switch (mode) {
    case 'oauth_discovery': return 'OAuth (auto)'
    case 'oauth': return 'OAuth'
    case 'token': return 'Token'
    case 'none': return 'None'
    default: return mode
  }
}

function primaryLabel(srv: MCPServer): string {
  if (srv.authMode === 'token') return srv.authorized ? 'Update token' : 'Set token'
  if (srv.authorized) return 'Reauthorize'
  return 'Authorize'
}

// Whether this server has any overflow-menu items right now. Used to
// hide the ⋮ button when it would open an empty dropdown — e.g.
// oauth_discovery + !hasOauthApp + !authorized has nothing to offer
// beyond the primary Authorize button.
function hasOverflow(srv: MCPServer): boolean {
  if (srv.authorized) return true                                // Disconnect
  if (srv.authMode === 'oauth_discovery' && srv.hasOauthApp) return true  // Re-register
  if (srv.authMode === 'oauth') return true                      // Set/Edit OAuth app
  return false
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/mcp-servers`)
    servers.value = data.mcpServers || []
    callbackUrl.value = data.oauthCallbackUrl ?? ''
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="servers" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No MCP servers registered.
        </div>
      </template>
      <Column field="name" header="Name">
        <template #body="{ data: srv }">
          <div>
            <strong>{{ srv.name || srv.slug }}</strong>
            <div style="font-size: 0.8rem; color: var(--p-text-muted-color); word-break: break-all">{{ srv.url }}</div>
          </div>
        </template>
      </Column>
      <Column header="Auth Mode">
        <template #body="{ data: srv }">
          {{ authModeLabel(srv.authMode) }}
        </template>
      </Column>
      <Column header="Tools">
        <template #body="{ data: srv }">
          {{ srv.toolCount || 0 }}
        </template>
      </Column>
      <Column header="Status">
        <template #body="{ data: srv }">
          <Tag v-if="srv.authMode === 'none'" value="No Auth" severity="secondary" />
          <Tag v-else-if="srv.authorized" value="Authorized" severity="success" />
          <Tag v-else value="Needs Setup" severity="warn" />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data: srv }">
          <div v-if="srv.authMode !== 'none'" style="display: flex; gap: 0.25rem; align-items: center">
            <Button
              :label="primaryLabel(srv)"
              size="small"
              outlined
              @click="primaryAction(srv)"
            />
            <Button
              v-if="hasOverflow(srv)"
              icon="pi pi-ellipsis-v"
              size="small"
              text
              severity="secondary"
              aria-label="More actions"
              @click="(e) => openOverflow(e, srv)"
            />
            <Menu
              v-if="hasOverflow(srv)"
              :ref="(el) => setOverflowMenu(srv.slug, el)"
              :model="overflowItems"
              :popup="true"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Name"><template #body><Skeleton /></template></Column>
      <Column header="Auth Mode"><template #body><Skeleton width="5rem" /></template></Column>
      <Column header="Tools"><template #body><Skeleton width="3rem" /></template></Column>
      <Column header="Status"><template #body><Skeleton width="5rem" /></template></Column>
      <Column header="Actions"><template #body><Skeleton width="6rem" /></template></Column>
    </DataTable>

    <!-- Token/API key dialog (reuse CredentialDialog) -->
    <CredentialDialog
      v-if="selectedServer"
      v-model:visible="credDialogVisible"
      :agent-id="props.agentId"
      :slug="selectedServer.slug"
      :name="selectedServer.name"
      base-path="mcp-servers"
    />

    <!-- OAuth app paste dialog (oauth mode only) -->
    <Dialog v-model:visible="oauthAppDialogVisible" :header="`Configure ${selectedServer?.name ?? 'MCP OAuth'}`" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <p style="font-size: 0.85rem; color: var(--p-text-muted-color); margin: 0">
          Enter OAuth2 client credentials for this MCP server.
        </p>
        <div style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">Redirect URI: </span>
          <code style="user-select: all; word-break: break-all">{{ callbackUrl }}</code>
        </div>
        <FloatLabel>
          <InputText id="mcp-oauth-client-id" v-model="oauthClientId" style="width: 100%" />
          <label for="mcp-oauth-client-id">Client ID</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="mcp-oauth-client-secret" v-model="oauthClientSecret" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="mcp-oauth-client-secret">Client Secret</label>
        </FloatLabel>
        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button label="Save & Authorize" :loading="oauthSaving" @click="saveOAuthApp" :disabled="!oauthClientId || !oauthClientSecret" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
