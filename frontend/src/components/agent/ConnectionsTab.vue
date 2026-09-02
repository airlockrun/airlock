<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'
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
const { t, formatNumber } = useAirlockI18n()
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
const actionMenu = ref()
const actionNeed = ref<NeedInfo | null>(null)

const needs = computed(() => resources.needs.value.filter((need) => need.type === 'connection'))
watch(needs, (rows) => emit('populated', rows.length), { immediate: true })
const definitionsBySlug = computed(() => new Map(definitions.value.map((row) => [row.slug, row])))
const selectedDefinition = computed(() => selectedNeed.value ? definitionsBySlug.value.get(selectedNeed.value.slug) : undefined)
const selectedResource = computed(() => selectedNeed.value ? resources.resourceFor(selectedNeed.value) : undefined)
const canAdmin = computed(() => props.yourAccess === 'admin')

function definition(need: NeedInfo): ConnectionInfo | undefined { return definitionsBySlug.value.get(need.slug) }
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
  if (!resource || resource.agentCount < 2) return ''
  return t('resources.connections.sharedWarning', {
    count: resource.agentCount,
    formattedCount: formatNumber(resource.agentCount),
  })
}
function authLabel(mode: string): string {
  if (mode === 'oauth') return t('resources.auth.oauth')
  if (mode === 'api_key') return t('resources.auth.apiKey')
  if (mode === 'none') return t('resources.auth.none')
  return mode
}

const actionMenuItems = computed(() => {
  const need = actionNeed.value
  if (!need) return []
  const items: any[] = []
  if (definition(need)?.authMode === 'oauth' && canAuthorize(need)) {
    items.push({ label: t('resources.actions.oauthApp'), icon: 'pi pi-key', command: () => configure(need) })
  }
  items.push({ label: t('resources.actions.switchResource'), icon: 'pi pi-sync', command: () => openSetup(need) })
  items.push({ separator: true })
  items.push({ label: t('resources.actions.disconnectApp'), icon: 'pi pi-unlink', danger: true, command: () => disconnect(need) })
  return items
})

function openActionMenu(event: Event, need: NeedInfo) {
  actionNeed.value = need
  actionMenu.value.toggle(event)
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
    loadError.value = error.response?.data?.error || error.message || t('resources.errors.loadConnections')
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
        toast.add({ severity: 'success', summary: t('resources.connections.disconnected'), life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: error.response?.data?.error || t('resources.errors.disconnectFailed'), life: 5000 })
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
    <div class="load-error"><span>{{ loadError }}</span><Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <DataTable v-else-if="!loading" :value="needs" class="connections-table" stripedRows responsive-layout="scroll" :table-style="{ minWidth: '46rem' }">
    <template #empty><div class="empty">{{ t('resources.connections.empty') }}</div></template>
    <Column :header="t('resources.connections.connection')" style="min-width: 20rem">
      <template #body="{ data: need }">
        <div class="primary-name">{{ need.bound ? boundName(need) : (definition(need)?.name || need.slug) }}</div>
        <div class="secondary">{{ t('resources.connections.appHandle', { slug: need.slug }) }}<span v-if="need.description"> · {{ need.description }}</span></div>
      </template>
    </Column>
    <Column :header="t('resources.connections.authentication')" style="width: 10rem"><template #body="{ data: need }">{{ authLabel(definition(need)?.authMode || '') }}</template></Column>
    <Column :header="t('resources.connections.state')" style="width: 11rem">
      <template #body="{ data: need }">
        <div class="state-cell">
          <Tag
            :value="!need.bound ? t('resources.status.unbound') : (definition(need)?.authMode === 'none' || definition(need)?.authorized ? t('resources.status.ready') : t('resources.status.needsSetup'))"
            :severity="!need.bound || (definition(need)?.authMode !== 'none' && !definition(need)?.authorized) ? 'warn' : 'success'"
          />
          <span class="secondary">{{ need.bound ? t('resources.status.boundToApp') : t('resources.status.noResourceSelected') }}</span>
        </div>
      </template>
    </Column>
    <Column :header="t('resources.bridges.actions')" style="width: 13rem" header-style="text-align: right" body-style="text-align: right">
      <template #body="{ data: need }">
        <div v-if="canAdmin" class="actions">
          <Button v-if="!need.bound" :label="t('resources.actions.setUp')" size="small" @click="openSetup(need)" />
          <template v-else>
            <Button
              v-if="definition(need)?.authMode === 'oauth' && canAuthorize(need)"
              :label="t('resources.actions.reauthorize')"
              size="small"
              outlined
              @click="reauthorize(need)"
            />
            <Button
              v-else-if="definition(need)?.authMode !== 'none' && canManage(need)"
              :label="t('resources.actions.configure')"
              size="small"
              outlined
              @click="configure(need)"
            />
            <Button icon="pi pi-ellipsis-v" size="small" text rounded :aria-label="t('resources.connections.moreActions')" @click="openActionMenu($event, need)" />
          </template>
        </div>
        <span v-else class="secondary">{{ t('resources.connections.viewOnly') }}</span>
      </template>
    </Column>
  </DataTable>
  <div v-else class="skeletons"><Skeleton v-for="i in 3" :key="i" height="3rem" /></div>
  <Menu ref="actionMenu" :model="actionMenuItems" :popup="true">
    <template #item="{ item, props: menuProps }">
      <a v-bind="menuProps.action" :class="{ 'danger-menu-item': item.danger }">
        <span :class="item.icon" />
        <span>{{ item.label }}</span>
      </a>
    </template>
  </Menu>

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
  <Dialog v-model:visible="oauthAppOpen" :header="t('resources.auth.replaceOAuthApp')" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
    <div class="oauth-form">
      <Message v-if="selectedNeed && sharedWarning(selectedNeed)" severity="warn" :closable="false">{{ sharedWarning(selectedNeed) }}</Message>
      <p class="secondary">{{ t('resources.auth.reauthorizeAfterSave') }}</p>
      <InputText v-model="oauthClientId" :placeholder="t('resources.auth.clientId')" />
      <Password v-model="oauthClientSecret" :placeholder="t('resources.auth.clientSecret')" :feedback="false" toggle-mask fluid />
      <div class="dialog-actions">
        <Button :label="t('resources.actions.cancel')" text severity="secondary" @click="oauthAppOpen = false" />
        <Button :label="t('resources.actions.saveAndAuthorize')" :loading="saving" :disabled="!oauthClientId || !oauthClientSecret" @click="saveOAuthApp" />
      </div>
    </div>
  </Dialog>
</template>

<style scoped>
.empty { text-align: center; padding: 2rem; color: var(--p-text-muted-color); }
.primary-name { font-weight: 600; line-height: 1.3; }
.secondary { color: var(--p-text-muted-color); font-size: 0.8rem; line-height: 1.35; }
.state-cell { display: flex; flex-direction: column; align-items: flex-start; gap: 0.35rem; }
.actions { display: flex; flex-wrap: nowrap; align-items: center; justify-content: flex-end; gap: 0.35rem; }
.danger-menu-item { color: var(--p-red-400) !important; }
.connections-table :deep(th:last-child .p-datatable-column-header-content) { justify-content: flex-end; }
.connections-table :deep(td) { vertical-align: middle; }
.skeletons, .oauth-form { display: flex; flex-direction: column; gap: 0.75rem; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
</style>
