<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
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
const servers = ref<MCPServer[]>([])
const loading = ref(true)
const credDialogVisible = ref(false)
const oauthAppDialogVisible = ref(false)
const selectedServer = ref<MCPServer | null>(null)
const oauthClientId = ref('')
const oauthClientSecret = ref('')
const oauthSaving = ref(false)
const callbackUrl = ref('')

function configure(srv: MCPServer) {
  selectedServer.value = srv
  if (srv.authMode === 'oauth' || srv.authMode === 'oauth_discovery') {
    oauthClientId.value = ''
    oauthClientSecret.value = ''
    oauthAppDialogVisible.value = true
  } else {
    credDialogVisible.value = true
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

function reauthorize() {
  oauthAppDialogVisible.value = false
  startMCPOAuth()
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
          <Button
            v-if="srv.authMode !== 'none'"
            :label="srv.authorized ? 'Reconfigure' : 'Configure'"
            size="small"
            outlined
            @click="configure(srv)"
          />
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

    <!-- OAuth app dialog -->
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
          <Button v-if="selectedServer?.hasOauthApp" label="Reauthorize" severity="secondary" @click="reauthorize" />
          <Button label="Save & Authorize" :loading="oauthSaving" @click="saveOAuthApp" :disabled="!oauthClientId || !oauthClientSecret" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
