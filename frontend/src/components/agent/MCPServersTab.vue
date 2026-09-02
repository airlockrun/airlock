<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'
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
const { t, formatNumber } = useAirlockI18n()
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
  return resource ? resourceLabel(resource) : definition(need)?.name || t('resources.connections.boundResource')
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
    ? t('resources.mcp.sharedWarning', {
        count: resource.agentCount,
        formattedCount: formatNumber(resource.agentCount),
      })
    : ''
}
function authLabel(mode: string): string {
  if (mode === 'oauth_discovery') return t('resources.auth.oauthAutomatic')
  if (mode === 'oauth') return t('resources.auth.oauth')
  if (mode === 'token') return t('resources.auth.token')
  if (mode === 'none') return t('resources.auth.none')
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
    loadError.value = error.response?.data?.error || error.message || t('resources.errors.loadMcpServers')
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
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || t('resources.errors.loadResourceSetup'), life: 6000 })
  }
}

async function reauthorize(need: NeedInfo) {
  const resource = resources.resourceFor(need)
  if (!resource) return
  try {
    await resources.startAuthorization(need, { resourceId: resource.id, displayName: '', createNew: false })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || t('resources.errors.authorizationFailed'), life: 6000 })
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
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || t('resources.errors.oauthSetupFailed'), life: 6000 })
  } finally {
    saving.value = false
  }
}

function disconnect(need: NeedInfo) {
  confirm.require({
    header: t('resources.connections.disconnectHeader'),
    message: t('resources.connections.disconnectNamed', { name: boundName(need) }),
    acceptLabel: t('resources.actions.disconnectApp'),
    rejectLabel: t('resources.actions.cancel'),
    accept: async () => {
      try {
        await resources.unbind(need)
        await refresh()
        emit('mutated')
        toast.add({ severity: 'success', summary: t('resources.mcp.disconnected'), life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: error.response?.data?.error || t('resources.errors.disconnectFailed'), life: 5000 })
      }
    },
  })
}

async function changed() { await refresh(); emit('mutated') }

onMounted(load)
</script>

<template>
  <Message v-if="loadError" severity="error" :closable="false">
    <div class="load-error"><span>{{ loadError }}</span><Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <DataTable v-else-if="!loading" :value="needs" stripedRows responsive-layout="scroll">
    <template #empty><div class="empty">{{ t('resources.mcp.empty') }}</div></template>
    <Column :header="t('resources.types.mcpServer')">
      <template #body="{ data: need }">
        <div class="primary-name">{{ need.bound ? boundName(need) : (definition(need)?.name || need.slug) }}</div>
        <div class="secondary">{{ t('resources.connections.appHandle', { slug: need.slug }) }}</div>
        <div v-if="definition(need)?.url" class="secondary url">{{ definition(need)?.url }}</div>
      </template>
    </Column>
    <Column :header="t('resources.connections.authentication')"><template #body="{ data: need }">{{ authLabel(definition(need)?.authMode || '') }}</template></Column>
    <Column :header="t('resources.mcp.tools')"><template #body="{ data: need }">{{ formatNumber(definition(need)?.toolCount || 0) }}</template></Column>
    <Column :header="t('resources.mcp.binding')"><template #body="{ data: need }"><Tag :value="need.bound ? t('resources.status.bound') : t('resources.status.unbound')" :severity="need.bound ? 'success' : 'warn'" /></template></Column>
    <Column :header="t('resources.inventory.status')">
      <template #body="{ data: need }">
        <Tag
          v-if="need.bound"
          :value="definition(need)?.authMode === 'none' ? t('resources.status.ready') : (definition(need)?.authorized ? t('resources.status.ready') : t('resources.status.needsSetup'))"
          :severity="definition(need)?.authMode === 'none' || definition(need)?.authorized ? 'success' : 'warn'"
        />
        <span v-else class="secondary">{{ t('resources.status.notConnected') }}</span>
      </template>
    </Column>
    <Column :header="t('resources.bridges.actions')">
      <template #body="{ data: need }">
        <div v-if="canAdmin" class="actions">
          <Button v-if="!need.bound" :label="t('resources.actions.setUp')" size="small" @click="openSetup(need)" />
          <template v-else>
            <Button
              v-if="['oauth', 'oauth_discovery'].includes(definition(need)?.authMode || '') && canAuthorize(need)"
              :label="t('resources.actions.reauthorize')"
              size="small"
              outlined
              @click="reauthorize(need)"
            />
            <Button v-if="definition(need)?.authMode === 'token' && canManage(need)" :label="t('resources.actions.configureToken')" size="small" outlined @click="configureToken(need)" />
            <Button v-if="definition(need)?.authMode === 'oauth' && canAuthorize(need)" :label="t('resources.actions.oauthApp')" size="small" text @click="configureOAuthApp(need)" />
            <Button :label="t('resources.actions.switchResource')" size="small" text @click="openSetup(need)" />
            <Button :label="t('resources.actions.disconnectApp')" size="small" text severity="danger" @click="disconnect(need)" />
          </template>
        </div>
        <span v-else class="secondary">{{ t('resources.connections.viewOnly') }}</span>
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
  <Dialog v-model:visible="oauthAppOpen" :header="t('resources.auth.replaceMcpOAuthApp')" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
    <div class="oauth-form">
      <Message v-if="selectedNeed && sharedWarning(selectedNeed)" severity="warn" :closable="false">{{ sharedWarning(selectedNeed) }}</Message>
      <p class="secondary">{{ t('resources.auth.reauthorizeSharedAfterSave') }}</p>
      <div class="secondary">{{ t('resources.auth.redirectUri', { uri: callbackUrl }) }}</div>
      <InputText v-model="clientId" :placeholder="t('resources.auth.clientId')" />
      <Password v-model="clientSecret" :placeholder="t('resources.auth.clientSecret')" :feedback="false" toggle-mask fluid />
      <div class="dialog-actions">
        <Button :label="t('resources.actions.cancel')" text severity="secondary" @click="oauthAppOpen = false" />
        <Button :label="t('resources.actions.saveAndAuthorize')" :loading="saving" :disabled="!clientId || !clientSecret" @click="saveOAuthApp" />
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
