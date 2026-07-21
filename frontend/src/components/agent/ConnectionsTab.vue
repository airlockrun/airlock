<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import type { ConnectionInfo } from '@/gen/airlock/v1/types_pb'
import type { NeedInfo } from '@/gen/airlock/v1/api_pb'
import { ListConnectionsResponseSchema } from '@/gen/airlock/v1/api_pb'
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
const definitions = ref<ConnectionInfo[]>([])
const loading = ref(true)
const loadError = ref('')
const callbackUrl = ref('')
const bindingOpen = ref(false)
const credentialOpen = ref(false)
const oauthAppOpen = ref(false)
const selectedNeed = ref<NeedInfo | null>(null)
const oauthClientId = ref('')
const oauthClientSecret = ref('')
const saving = ref(false)

const needs = computed(() => resources.needs.value.filter((need) => need.type === 'connection'))
watch(needs, (rows) => emit('populated', rows.length), { immediate: true })
const definitionsBySlug = computed(() => new Map(definitions.value.map((row) => [row.slug, row])))
const selectedDefinition = computed(() => selectedNeed.value ? definitionsBySlug.value.get(selectedNeed.value.slug) : undefined)
const selectedResource = computed(() => selectedNeed.value ? resources.resourceFor(selectedNeed.value) : undefined)
const canAdmin = computed(() => props.yourAccess === 'admin')

function definition(need: NeedInfo): ConnectionInfo | undefined { return definitionsBySlug.value.get(need.slug) }
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
  if (!resource || resource.agentCount < 2) return ''
  return `Credential changes affect all ${resource.agentCount} apps using this shared resource.`
}
function authLabel(mode: string): string {
  if (mode === 'oauth') return 'OAuth'
  if (mode === 'api_key') return 'API key'
  if (mode === 'none') return 'No authentication'
  return mode
}

async function refresh() {
  const [response] = await Promise.all([
    api.get(`/api/v1/agents/${props.agentId}/connections`),
    resources.refresh(),
  ])
  const parsed = fromJson(ListConnectionsResponseSchema, response.data)
  definitions.value = parsed.connections
  callbackUrl.value = parsed.oauthCallbackUrl
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    await refresh()
  } catch (error: any) {
    loadError.value = error.response?.data?.error || error.message || 'Failed to load connections'
    emit('populated', 1)
  } finally {
    loading.value = false
  }
}

function openSetup(need: NeedInfo) {
  selectedNeed.value = need
  bindingOpen.value = true
}

function configure(need: NeedInfo) {
  selectedNeed.value = need
  const row = definition(need)
  if (row?.authMode === 'oauth') {
    if (!canAuthorize(need)) return
    oauthClientId.value = ''
    oauthClientSecret.value = ''
    oauthAppOpen.value = true
  } else {
    credentialOpen.value = true
  }
}

async function configureBound(need: NeedInfo) {
  try {
    await refresh()
    configure(need)
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
  if (!need || !resource || !canAuthorize(need) || !oauthClientId.value || !oauthClientSecret.value) return
  saving.value = true
  try {
    await api.put(
      `/api/v1/agents/${props.agentId}/credentials/${encodeURIComponent(need.slug)}/oauth-app`,
      serializeOAuthAppRequest(oauthClientId.value, oauthClientSecret.value, '', false),
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
        toast.add({ severity: 'success', summary: 'Resource disconnected from this app', life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: error.response?.data?.error || 'Disconnect failed', life: 5000 })
      }
    },
  })
}

async function changed() {
  await refresh()
  emit('mutated')
}

onMounted(load)
</script>

<template>
  <Message v-if="loadError" severity="error" :closable="false">
    <div class="load-error"><span>{{ loadError }}</span><Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <DataTable v-else-if="!loading" :value="needs" stripedRows responsive-layout="scroll">
    <template #empty><div class="empty">No connections registered.</div></template>
    <Column header="Connection">
      <template #body="{ data: need }">
        <div class="primary-name">{{ need.bound ? boundName(need) : (definition(need)?.name || need.slug) }}</div>
        <div class="secondary">App handle: <code>{{ need.slug }}</code><span v-if="need.description"> · {{ need.description }}</span></div>
      </template>
    </Column>
    <Column header="Authentication"><template #body="{ data: need }">{{ authLabel(definition(need)?.authMode || '') }}</template></Column>
    <Column header="Binding">
      <template #body="{ data: need }">
        <Tag :value="need.bound ? 'Bound' : 'Unbound'" :severity="need.bound ? 'success' : 'warn'" />
      </template>
    </Column>
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
              v-if="definition(need)?.authMode === 'oauth' && canAuthorize(need)"
              label="Reauthorize"
              size="small"
              outlined
              @click="reauthorize(need)"
            />
            <Button
              v-if="definition(need)?.authMode === 'oauth' && canAuthorize(need)"
              label="OAuth app"
              size="small"
              text
              @click="configure(need)"
            />
            <Button
              v-else-if="definition(need)?.authMode !== 'none' && canManage(need)"
              label="Configure"
              size="small"
              outlined
              @click="configure(need)"
            />
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
    :setup-instructions="selectedDefinition?.setupInstructions"
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
    :warning="sharedWarning(selectedNeed)"
    @saved="changed"
  />
  <Dialog v-model:visible="oauthAppOpen" header="Replace OAuth app credentials" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
    <div class="oauth-form">
      <Message v-if="selectedNeed && sharedWarning(selectedNeed)" severity="warn" :closable="false">{{ sharedWarning(selectedNeed) }}</Message>
      <p class="secondary">After saving, you will authorize the resource again. Existing credentials remain active until authorization succeeds.</p>
      <InputText v-model="oauthClientId" placeholder="Client ID" />
      <Password v-model="oauthClientSecret" placeholder="Client secret" :feedback="false" toggle-mask fluid />
      <div class="dialog-actions">
        <Button label="Cancel" text severity="secondary" @click="oauthAppOpen = false" />
        <Button label="Save and authorize" :loading="saving" :disabled="!oauthClientId || !oauthClientSecret" @click="saveOAuthApp" />
      </div>
    </div>
  </Dialog>
</template>

<style scoped>
.empty { text-align: center; padding: 2rem; color: var(--p-text-muted-color); }
.primary-name { font-weight: 600; }
.secondary { color: var(--p-text-muted-color); font-size: 0.8rem; }
.actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
.skeletons, .oauth-form { display: flex; flex-direction: column; gap: 0.75rem; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
</style>
