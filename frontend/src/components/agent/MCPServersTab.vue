<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import type { MCPServerInfo } from '@/gen/airlock/v1/types_pb'
import type { NeedInfo } from '@/gen/airlock/v1/api_pb'
import { ListMCPServersResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useAgentResources } from '@/composables/useAgentResources'
import { hasCapability, resourceLabel } from '@/utils/resources'
import { serializeOAuthAppRequest } from '@/utils/resourceRequests'
import CredentialDialog from './CredentialDialog.vue'
import ResourceBindingDialog from './ResourceBindingDialog.vue'

const props = withDefaults(defineProps<{ agentId: string; yourAccess?: string }>(), { yourAccess: '' })
const emit = defineEmits<{ populated: [count: number]; mutated: [] }>()
const toast = useToast()
const confirm = useConfirm()
const resources = useAgentResources(props.agentId)
const definitions = ref<MCPServerInfo[]>([])
const loading = ref(true)
const loadError = ref('')
const callbackUrl = ref('')
const bindingOpen = ref(false)
const credentialOpen = ref(false)
const oauthAppOpen = ref(false)
const selectedNeed = ref<NeedInfo | null>(null)
const clientId = ref('')
const clientSecret = ref('')
const saving = ref(false)

const needs = computed(() => resources.needs.value.filter((need) => need.type === 'mcp_server'))
watch(needs, (rows) => emit('populated', rows.length), { immediate: true })
const definitionsBySlug = computed(() => new Map(definitions.value.map((row) => [row.slug, row])))
const selectedDefinition = computed(() => selectedNeed.value ? definitionsBySlug.value.get(selectedNeed.value.slug) : undefined)
const selectedResource = computed(() => selectedNeed.value ? resources.resourceFor(selectedNeed.value) : undefined)
const canAdmin = computed(() => props.yourAccess === 'admin')

function definition(need: NeedInfo): MCPServerInfo | undefined { return definitionsBySlug.value.get(need.slug) }
function boundName(need: NeedInfo): string {
  const resource = resources.resourceFor(need)
  return resource ? resourceLabel(resource) : definition(need)?.name || 'Bound resource'
}
function canManage(need: NeedInfo): boolean {
  const resource = resources.resourceFor(need)
  return !!resource && hasCapability(resource.capabilities, 'manage')
}
function canAuthorize(need: NeedInfo): boolean {
  const resource = resources.resourceFor(need)
  return !!resource && hasCapability(resource.capabilities, 'bind') && hasCapability(resource.capabilities, 'manage')
}
function sharedWarning(need: NeedInfo): string {
  const resource = resources.resourceFor(need)
  return resource && resource.agentCount > 1
    ? `Token or OAuth changes affect all ${resource.agentCount} apps using this shared MCP resource.`
    : ''
}
function authLabel(mode: string): string {
  if (mode === 'oauth_discovery') return 'OAuth (automatic)'
  if (mode === 'oauth') return 'OAuth'
  if (mode === 'token') return 'Token'
  if (mode === 'none') return 'No authentication'
  return mode
}

async function refresh() {
  const [response] = await Promise.all([
    api.get(`/api/v1/agents/${props.agentId}/mcp-servers`),
    resources.refresh(),
  ])
  const parsed = fromJson(ListMCPServersResponseSchema, response.data)
  definitions.value = parsed.mcpServers
  callbackUrl.value = parsed.oauthCallbackUrl
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    await refresh()
  } catch (error: any) {
    loadError.value = error.response?.data?.error || error.message || 'Failed to load MCP servers'
    emit('populated', 1)
  } finally {
    loading.value = false
  }
}

function openSetup(need: NeedInfo) { selectedNeed.value = need; bindingOpen.value = true }
function configureToken(need: NeedInfo) { selectedNeed.value = need; credentialOpen.value = true }
function configureOAuthApp(need: NeedInfo) {
  if (!canAuthorize(need)) return
  selectedNeed.value = need
  clientId.value = ''
  clientSecret.value = ''
  oauthAppOpen.value = true
}

async function configureBound(need: NeedInfo) {
  try {
    await refresh()
    configureToken(need)
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || 'Failed to load resource setup', life: 6000 })
  }
}

async function reauthorize(need: NeedInfo) {
  const resource = resources.resourceFor(need)
  if (!resource) return
  try {
    await resources.startAuthorization(need, { resourceId: resource.id, displayName: '', createNew: false })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || 'Authorization failed', life: 6000 })
  }
}

async function saveOAuthApp() {
  const need = selectedNeed.value
  const resource = selectedResource.value
  if (!need || !resource || !canAuthorize(need) || !clientId.value || !clientSecret.value) return
  saving.value = true
  try {
    await api.put(
      `/api/v1/agents/${props.agentId}/mcp-servers/${encodeURIComponent(need.slug)}/credentials/oauth-app`,
      serializeOAuthAppRequest(clientId.value, clientSecret.value, '', false),
    )
    oauthAppOpen.value = false
    await resources.startAuthorization(need, { resourceId: resource.id, displayName: '', createNew: false })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || 'OAuth setup failed', life: 6000 })
  } finally {
    saving.value = false
  }
}

function disconnect(need: NeedInfo) {
  confirm.require({
    header: 'Disconnect from this app?',
    message: `${boundName(need)} stays available to other apps. Its stored credentials are not cleared.`,
    acceptLabel: 'Disconnect from this app',
    rejectLabel: 'Cancel',
    accept: async () => {
      try {
        await resources.unbind(need)
        await refresh()
        emit('mutated')
        toast.add({ severity: 'success', summary: 'MCP resource disconnected from this app', life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: error.response?.data?.error || 'Disconnect failed', life: 5000 })
      }
    },
  })
}

async function changed() { await refresh(); emit('mutated') }

onMounted(load)
</script>

<template>
  <Message v-if="loadError" severity="error" :closable="false">
    <div class="load-error"><span>{{ loadError }}</span><Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <DataTable v-else-if="!loading" :value="needs" stripedRows responsive-layout="scroll">
    <template #empty><div class="empty">No MCP servers registered.</div></template>
    <Column header="MCP server">
      <template #body="{ data: need }">
        <div class="primary-name">{{ need.bound ? boundName(need) : (definition(need)?.name || need.slug) }}</div>
        <div class="secondary">App handle: <code>{{ need.slug }}</code></div>
        <div v-if="definition(need)?.url" class="secondary url">{{ definition(need)?.url }}</div>
      </template>
    </Column>
    <Column header="Authentication"><template #body="{ data: need }">{{ authLabel(definition(need)?.authMode || '') }}</template></Column>
    <Column header="Tools"><template #body="{ data: need }">{{ definition(need)?.toolCount || 0 }}</template></Column>
    <Column header="Binding"><template #body="{ data: need }"><Tag :value="need.bound ? 'Bound' : 'Unbound'" :severity="need.bound ? 'success' : 'warn'" /></template></Column>
    <Column header="Status">
      <template #body="{ data: need }">
        <Tag
          v-if="need.bound"
          :value="definition(need)?.authMode === 'none' ? 'Ready' : (definition(need)?.authorized ? 'Ready' : 'Needs setup')"
          :severity="definition(need)?.authMode === 'none' || definition(need)?.authorized ? 'success' : 'warn'"
        />
        <span v-else class="secondary">Not connected</span>
      </template>
    </Column>
    <Column header="Actions">
      <template #body="{ data: need }">
        <div v-if="canAdmin" class="actions">
          <Button v-if="!need.bound" label="Set up" size="small" @click="openSetup(need)" />
          <template v-else>
            <Button
              v-if="['oauth', 'oauth_discovery'].includes(definition(need)?.authMode || '') && canAuthorize(need)"
              label="Reauthorize"
              size="small"
              outlined
              @click="reauthorize(need)"
            />
            <Button v-if="definition(need)?.authMode === 'token' && canManage(need)" label="Configure token" size="small" outlined @click="configureToken(need)" />
            <Button v-if="definition(need)?.authMode === 'oauth' && canAuthorize(need)" label="OAuth app" size="small" text @click="configureOAuthApp(need)" />
            <Button label="Switch resource" size="small" text @click="openSetup(need)" />
            <Button label="Disconnect from this app" size="small" text severity="danger" @click="disconnect(need)" />
          </template>
        </div>
        <span v-else class="secondary">View only</span>
      </template>
    </Column>
  </DataTable>
  <div v-else class="skeletons"><Skeleton v-for="i in 3" :key="i" height="3rem" /></div>

  <ResourceBindingDialog
    v-model:visible="bindingOpen"
    :agent-id="agentId"
    :need="selectedNeed"
    :auth-mode="selectedDefinition?.authMode"
    :callback-url="callbackUrl"
    @changed="changed"
    @configure="configureBound"
  />
  <CredentialDialog
    v-if="selectedNeed"
    v-model:visible="credentialOpen"
    :agent-id="agentId"
    :slug="selectedNeed.slug"
    :name="selectedResource ? resourceLabel(selectedResource) : selectedNeed.slug"
    base-path="mcp-servers"
    :warning="sharedWarning(selectedNeed)"
    @saved="changed"
  />
  <Dialog v-model:visible="oauthAppOpen" header="Replace MCP OAuth app" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
    <div class="oauth-form">
      <Message v-if="selectedNeed && sharedWarning(selectedNeed)" severity="warn" :closable="false">{{ sharedWarning(selectedNeed) }}</Message>
      <p class="secondary">After saving, you will authorize the shared resource again. Existing credentials remain active until authorization succeeds.</p>
      <div class="secondary">Redirect URI: <code class="url">{{ callbackUrl }}</code></div>
      <InputText v-model="clientId" placeholder="Client ID" />
      <Password v-model="clientSecret" placeholder="Client secret" :feedback="false" toggle-mask fluid />
      <div class="dialog-actions">
        <Button label="Cancel" text severity="secondary" @click="oauthAppOpen = false" />
        <Button label="Save and authorize" :loading="saving" :disabled="!clientId || !clientSecret" @click="saveOAuthApp" />
      </div>
    </div>
  </Dialog>
</template>

<style scoped>
.empty { text-align: center; padding: 2rem; color: var(--p-text-muted-color); }
.primary-name { font-weight: 600; }
.secondary { color: var(--p-text-muted-color); font-size: 0.8rem; }
.url { word-break: break-all; }
.actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
.skeletons, .oauth-form { display: flex; flex-direction: column; gap: 0.75rem; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
</style>
