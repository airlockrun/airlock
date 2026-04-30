<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { startOAuth } from '@/composables/useOAuth'
import CredentialDialog from './CredentialDialog.vue'

interface Connection {
  name: string
  slug: string
  authMode: string
  authorized: boolean
  hasOauthApp: boolean
  setupInstructions: string
}

const props = defineProps<{ agentId: string }>()

const toast = useToast()
const connections = ref<Connection[]>([])
const loading = ref(true)
const credDialogVisible = ref(false)
const oauthAppDialogVisible = ref(false)
const selectedConn = ref<Connection | null>(null)
const oauthClientId = ref('')
const oauthClientSecret = ref('')
const oauthSaving = ref(false)
const callbackUrl = ref('')

function configure(conn: Connection) {
  if (conn.authMode === 'oauth') {
    selectedConn.value = conn
    oauthClientId.value = ''
    oauthClientSecret.value = ''
    oauthAppDialogVisible.value = true
  } else {
    selectedConn.value = conn
    credDialogVisible.value = true
  }
}

async function saveOAuthApp() {
  if (!selectedConn.value || !oauthClientId.value || !oauthClientSecret.value) return
  oauthSaving.value = true
  try {
    await api.put(`/api/v1/agents/${props.agentId}/credentials/${selectedConn.value.slug}/oauth-app`, {
      clientId: oauthClientId.value,
      clientSecret: oauthClientSecret.value,
    })
    toast.add({ severity: 'success', summary: 'OAuth app saved. Starting authorization...', life: 3000 })
    oauthAppDialogVisible.value = false
    // Update local state and start OAuth flow.
    selectedConn.value.hasOauthApp = true
    startOAuth(props.agentId, selectedConn.value.slug).catch((err: any) => {
      toast.add({ severity: 'error', summary: err.message || 'OAuth failed', life: 5000 })
    })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to save OAuth app', life: 5000 })
  } finally {
    oauthSaving.value = false
  }
}

function reauthorize() {
  if (!selectedConn.value) return
  oauthAppDialogVisible.value = false
  startOAuth(props.agentId, selectedConn.value.slug).catch((err: any) => {
    toast.add({ severity: 'error', summary: err.message || 'OAuth failed', life: 5000 })
  })
}

function mapConnection(raw: Record<string, any>): Connection {
  return {
    name: raw.name ?? '',
    slug: raw.slug ?? '',
    authMode: raw.authMode ?? raw.auth_mode ?? '',
    authorized: raw.authorized ?? false,
    hasOauthApp: raw.hasOauthApp ?? raw.has_oauth_app ?? false,
    setupInstructions: raw.setupInstructions ?? raw.setup_instructions ?? '',
  }
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/connections`)
    connections.value = (data.connections || []).map(mapConnection)
    callbackUrl.value = data.oauthCallbackUrl ?? data.oauth_callback_url ?? ''
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="connections" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No connections registered.
        </div>
      </template>
      <Column field="name" header="Name" />
      <Column field="authMode" header="Auth Mode" />
      <Column header="Status">
        <template #body="{ data: conn }">
          <Tag
            :value="conn.authorized ? 'Authorized' : 'Needs Setup'"
            :severity="conn.authorized ? 'success' : 'warn'"
          />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data: conn }">
          <Button :label="conn.authorized ? 'Reconfigure' : 'Configure'" size="small" outlined @click="configure(conn)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Name">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Auth Mode">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Status">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
      <Column header="Actions">
        <template #body><Skeleton width="6rem" /></template>
      </Column>
    </DataTable>

    <CredentialDialog
      v-if="selectedConn"
      v-model:visible="credDialogVisible"
      :agent-id="props.agentId"
      :slug="selectedConn.slug"
      :name="selectedConn.name"
    />

    <Dialog v-model:visible="oauthAppDialogVisible" :header="`Configure ${selectedConn?.name ?? 'OAuth'}`" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <p style="font-size: 0.85rem; color: var(--p-text-muted-color); margin: 0">
          {{ selectedConn?.setupInstructions || 'Enter your OAuth2 client credentials.' }}
        </p>
        <div style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">Redirect URI: </span>
          <code style="user-select: all; word-break: break-all">{{ callbackUrl }}</code>
        </div>
        <FloatLabel>
          <InputText id="oauth-client-id" v-model="oauthClientId" style="width: 100%" />
          <label for="oauth-client-id">Client ID</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="oauth-client-secret" v-model="oauthClientSecret" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="oauth-client-secret">Client Secret</label>
        </FloatLabel>
        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button v-if="selectedConn?.hasOauthApp" label="Reauthorize" severity="secondary" @click="reauthorize" />
          <Button label="Save & Authorize" :loading="oauthSaving" @click="saveOAuthApp" :disabled="!oauthClientId || !oauthClientSecret" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
