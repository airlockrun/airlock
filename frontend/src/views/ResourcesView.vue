<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useRouter } from 'vue-router'
import type { GetConnectorResponse, OwnedResourceInfo, ResourceConsumerInfo, ResourceGrantInfo } from '@/gen/airlock/v1/api_pb'
import type { GitCredential, HostInfo } from '@/gen/airlock/v1/types_pb'
import { listHosts } from '@/api/hosts'
import { useNow } from '@/composables/useNow'
import { useAuthStore } from '@/stores/auth'
import { useResourcesStore } from '@/stores/resources'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import { useUsersStore } from '@/stores/users'
import { hasCapability, resourceDetailAccess, resourceLabel, resourceStatus } from '@/utils/resources'
import { useAirlockI18n } from '@/i18n'

const resources = useResourcesStore()
const git = useGitCredentialsStore()
const users = useUsersStore()
const auth = useAuthStore()
const confirm = useConfirm()
const toast = useToast()
const router = useRouter()
const now = useNow()
const i18n = useAirlockI18n()
const { t, formatDate, formatNumber, locale } = i18n

const typeMeta = computed<Record<string, { label: string; icon: string }>>(() => ({
  connection: { label: t('resources.types.connection'), icon: 'pi pi-link' },
  mcp_server: { label: t('resources.types.mcpServer'), icon: 'pi pi-bolt' },
  git_credential: { label: t('resources.types.gitCredential'), icon: 'pi pi-code' },
  connector: { label: t('resources.types.connector'), icon: 'pi pi-desktop' },
  host: { label: t('resources.types.host'), icon: 'pi pi-server' },
  connector_target_group: { label: t('resources.types.connectorTargetGroup'), icon: 'pi pi-sitemap' },
}))
const resourceTypes = new Set(['connection', 'mcp_server', 'git_credential', 'connector', 'host', 'connector_target_group'])
const consumerTypes = new Set(['connection', 'mcp_server', 'connector'])
const renameTypes = new Set(['connection', 'mcp_server', 'connector'])
const typeRank: Record<string, number> = {
  connection: 0,
  mcp_server: 1,
  git_credential: 2,
  host: 3,
  connector_target_group: 4,
  connector: 5,
}
const visibleHostIds = computed(() => new Set(resources.resources
  .filter((resource) => resource.type === 'host')
  .map((resource) => resource.id)))
const sortedResources = computed(() => {
  const available = resources.resources.filter((resource) => resourceTypes.has(resource.type))
  const connectors = available.filter((resource) => resource.type === 'connector')
  const topLevel = available
    .filter((resource) => resource.type !== 'connector')
    .sort((a, b) => (typeRank[a.type] ?? 99) - (typeRank[b.type] ?? 99) || resourceLabel(a).localeCompare(resourceLabel(b), locale.value))
  const rows: OwnedResourceInfo[] = []
  for (const resource of topLevel) {
    rows.push(resource)
    if (resource.type === 'host') {
      rows.push(...connectors
        .filter((connector) => connector.hostId === resource.id)
        .sort((a, b) => resourceLabel(a).localeCompare(resourceLabel(b), locale.value)))
    }
  }
  rows.push(...connectors
    .filter((connector) => !connector.hostId || !visibleHostIds.value.has(connector.hostId))
    .sort((a, b) => resourceLabel(a).localeCompare(resourceLabel(b), locale.value)))
  return rows
})

const detailOpen = ref(false)
const selected = ref<OwnedResourceInfo | null>(null)
const consumers = ref<ResourceConsumerInfo[]>([])
const consumersLoading = ref(false)
const consumersError = ref('')
const connectorDetail = ref<GetConnectorResponse | null>(null)
const detailLoading = ref(false)
const detailError = ref('')
const grants = ref<ResourceGrantInfo[]>([])
const grantsLoading = ref(false)
const grantsError = ref('')
const editingId = ref('')
const editName = ref('')
const renaming = ref(false)
const grantDialogOpen = ref(false)
const grantGranteeId = ref('')
const grantCapabilities = ref<string[]>([])
const grantSaving = ref(false)
const granteesLoading = ref(false)
const granteesError = ref('')
const transferDialogOpen = ref(false)
const transferUserId = ref('')
const transferSaving = ref(false)
const hostsById = ref(new Map<string, HostInfo>())
let connectorDetailSequence = 0

const canManageSelected = computed(() => !!selected.value && hasCapability(selected.value.capabilities, 'manage'))
const canTransferSelected = computed(() => !!selected.value && (
  selected.value.ownerUserId === auth.user?.id || auth.isAdmin
))
const detailAccess = computed(() => resourceDetailAccess(selected.value?.capabilities ?? []))
const connector = computed(() => connectorDetail.value?.connector)
const supportedGrantCapabilities = computed(() => selected.value?.type === 'host'
  ? ['view', 'manage']
  : ['view', 'bind', 'manage'])
const selectableUsers = computed(() => users.selectable.filter((principal) => principal.kind === 'user'))
const availableGrantees = computed(() => {
  const granted = new Set(grants.value.map((grant) => grant.userId))
  return selectableUsers.value
    .filter((principal) => principal.id !== selected.value?.ownerUserId)
    .filter((principal) => principal.id === grantGranteeId.value || !granted.has(principal.id))
    .map((principal) => ({
      value: principal.id,
      label: principal.displayName
        ? principal.email ? `${principal.displayName} (${principal.email})` : principal.displayName
        : principal.email || principal.id,
    }))
})
const availableTransferUsers = computed(() => selectableUsers.value
  .filter((principal) => principal.id !== selected.value?.ownerUserId)
  .map((principal) => ({
    value: principal.id,
    label: principal.displayName
      ? principal.email ? `${principal.displayName} (${principal.email})` : principal.displayName
      : principal.email || principal.id,
  })))

function errorMessage(error: any, fallback: string): string {
  return error?.response?.data?.error || error?.message || fallback
}
function capabilityLabel(capability: string): string {
  if (capability === 'view') return t('resources.details.capabilityView')
  if (capability === 'bind') return t('resources.details.capabilityBind')
  if (capability === 'manage') return t('resources.details.capabilityManage')
  return capability
}
function principalKindLabel(kind: string): string {
  if (kind === 'user') return t('resources.details.principalKindUser')
  if (kind === 'group') return t('resources.details.principalKindGroup')
  return kind || t('resources.common.unknown')
}
function lifecycleLabel(lifecycle: string): string {
  if (lifecycle === 'active') return t('resources.details.lifecycleActive')
  if (lifecycle === 'revoked') return t('resources.details.lifecycleRevoked')
  return lifecycle || t('resources.common.unknown')
}
function artifactFreshnessLabel(freshness: string): string {
  if (freshness === 'current') return t('resources.details.artifactFreshnessCurrent')
  if (freshness === 'outdated') return t('resources.details.artifactFreshnessOutdated')
  if (freshness === 'missing') return t('resources.details.artifactFreshnessMissing')
  if (freshness === 'unknown') return t('resources.details.artifactFreshnessUnknown')
  return freshness || t('resources.common.unknown')
}
function directoryAccessLabel(directory: { read: boolean; write: boolean; list: boolean }): string {
  const access: string[] = []
  if (directory.read) access.push(t('resources.details.directoryRead'))
  if (directory.write) access.push(t('resources.details.directoryWrite'))
  if (directory.list) access.push(t('resources.details.directoryList'))
  return access.join(', ')
}
function consumerSummary(): string {
  if (!detailAccess.value.consumers || consumersError.value) return t('resources.details.noKnownConsumers')
  if (!consumers.value.length) return t('resources.details.noAppsUseIt')
  return t('resources.details.usedByNames', { names: consumers.value.map((consumer) => consumer.agentName || consumer.agentSlug).join(', ') })
}

function hasConsumers(resource: OwnedResourceInfo): boolean {
  return consumerTypes.has(resource.type)
}

function canRename(resource: OwnedResourceInfo): boolean {
  return renameTypes.has(resource.type) && hasCapability(resource.capabilities, 'manage')
}

function isNestedConnector(resource: OwnedResourceInfo): boolean {
  return resource.type === 'connector' && !!resource.hostId && visibleHostIds.value.has(resource.hostId)
}

function openResource(resource: OwnedResourceInfo): void {
  if (resource.type === 'host') {
    void router.push(`/settings/hosts/${resource.id}`)
    return
  }
  void loadDetail(resource)
}

function usageLabel(resource: OwnedResourceInfo): string {
  const values = { count: resource.agentCount, formattedCount: formatNumber(resource.agentCount) }
  if (resource.type === 'host') return t('resources.inventory.connectorCount', values)
  if (resource.type === 'connector_target_group') return t('resources.inventory.memberCount', values)
  return t('resources.inventory.appCount', values)
}

function displayedResourceStatus(resource: OwnedResourceInfo) {
  return resourceStatus(resource, i18n, resource.type === 'host' ? hostsById.value.get(resource.id) : undefined, now.value)
}

async function loadHostInventory(): Promise<void> {
  const hosts = await listHosts()
  hostsById.value = new Map(hosts.map((host) => [host.id, host]))
}

async function loadConsumers(resource: OwnedResourceInfo) {
  if (!resourceDetailAccess(resource.capabilities).consumers) return
  consumersLoading.value = true
  consumersError.value = ''
  consumers.value = []
  try {
    const loaded = await resources.fetchConsumers(resource.type, resource.id)
    if (selected.value?.id === resource.id) consumers.value = loaded
  } catch (error: any) {
    if (selected.value?.id === resource.id) consumersError.value = errorMessage(error, t('resources.errors.loadConsumers'))
  } finally {
    if (selected.value?.id === resource.id) consumersLoading.value = false
  }
}

async function loadConnectorDetail(resource: OwnedResourceInfo) {
  const sequence = connectorDetailSequence
  detailLoading.value = true
  detailError.value = ''
  connectorDetail.value = null
  consumers.value = []
  try {
    const detail = await resources.fetchConnector(resource.id)
    if (sequence !== connectorDetailSequence || selected.value?.id !== resource.id) return
    connectorDetail.value = detail
    consumers.value = detail.consumers
  } catch (error: any) {
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) detailError.value = errorMessage(error, t('resources.errors.loadConnectorDetails'))
  } finally {
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) detailLoading.value = false
  }
}

async function loadGrants(resource: OwnedResourceInfo) {
  const sequence = connectorDetailSequence
  grantsLoading.value = true
  grantsError.value = ''
  grants.value = []
  try {
    const loaded = await resources.fetchGrants(resource.type, resource.id)
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) grants.value = loaded
  } catch (error: any) {
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) grantsError.value = errorMessage(error, t('resources.errors.loadGrants'))
  } finally {
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) grantsLoading.value = false
  }
}

async function loadGrantees() {
  granteesLoading.value = true
  granteesError.value = ''
  try {
    await users.fetchSelectable()
  } catch (error: any) {
    granteesError.value = errorMessage(error, t('resources.errors.loadUsers'))
  } finally {
    granteesLoading.value = false
  }
}

async function loadDetail(resource: OwnedResourceInfo) {
  connectorDetailSequence++
  grantSaving.value = false
  grantDialogOpen.value = false
  selected.value = resource
  detailOpen.value = true
  consumers.value = []
  consumersError.value = ''
  connectorDetail.value = null
  detailError.value = ''
  grants.value = []
  grantsError.value = ''
  transferDialogOpen.value = false
  transferUserId.value = ''
  if (canManageSelected.value || canTransferSelected.value) void loadGrantees()
  if (detailAccess.value.grants) void loadGrants(resource)
  if (resource.type === 'connector') {
    if (detailAccess.value.details || detailAccess.value.grants) await loadConnectorDetail(resource)
    return
  }
  if (hasConsumers(resource)) await loadConsumers(resource)
}

function retryDetail() {
  if (!selected.value) return
  connectorDetailSequence++
  if (selected.value.type === 'connector') void loadConnectorDetail(selected.value)
  if (detailAccess.value.grants) void loadGrants(selected.value)
}

function openGrant(grant?: ResourceGrantInfo) {
  grantGranteeId.value = grant?.userId ?? ''
  grantCapabilities.value = grant ? [...grant.capabilities] : ['view']
  grantDialogOpen.value = true
}

async function saveGrant() {
  if (!selected.value || !grantGranteeId.value || !grantCapabilities.value.length) return
  const resource = selected.value
  const sequence = ++connectorDetailSequence
  grantSaving.value = true
  try {
    const loaded = await resources.saveGrant(resource.type, resource.id, grantGranteeId.value, grantCapabilities.value)
    if (sequence !== connectorDetailSequence || selected.value?.id !== resource.id) return
    grants.value = loaded
    grantDialogOpen.value = false
    toast.add({ severity: 'success', summary: t('resources.details.resourceAccessUpdated'), life: 2500 })
  } catch (error: any) {
    if (sequence === connectorDetailSequence && selected.value?.id === resource.id) {
      toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.updateResourceAccess')), life: 5000 })
    }
  } finally {
    if (sequence === connectorDetailSequence) grantSaving.value = false
  }
}

function deleteGrant(grant: ResourceGrantInfo) {
  if (!selected.value) return
  const resource = selected.value
  const granteeName = grant.displayName || grant.email
  confirm.require({
    header: t('resources.details.removeGrantHeader', { name: granteeName }),
    message: t('resources.details.removeGrantImpact'),
    acceptLabel: t('resources.actions.removeAccess'),
    rejectLabel: t('resources.actions.cancel'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      const sequence = ++connectorDetailSequence
      try {
        const loaded = await resources.removeGrant(resource.type, resource.id, grant.userId)
        if (sequence !== connectorDetailSequence || selected.value?.id !== resource.id) return
        grants.value = loaded
        toast.add({ severity: 'success', summary: t('resources.details.resourceAccessRemoved'), life: 2500 })
      } catch (error: any) {
        if (sequence === connectorDetailSequence && selected.value?.id === resource.id) {
          toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.removeResourceAccess')), life: 5000 })
        }
      }
    },
  })
}

async function transferOwnership() {
  if (!selected.value || !transferUserId.value) return
  const resource = selected.value
  transferSaving.value = true
  try {
    await resources.transfer(resource.type, resource.id, transferUserId.value)
    transferDialogOpen.value = false
    const updated = resources.resources.find((row) => row.id === resource.id)
    if (updated) await loadDetail(updated)
    else {
      detailOpen.value = false
      selected.value = null
    }
    toast.add({ severity: 'success', summary: t('resources.details.ownershipTransferred'), life: 3000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.ownershipTransferFailed')), life: 5000 })
  } finally {
    transferSaving.value = false
  }
}

function beginRename(resource: OwnedResourceInfo) {
  editingId.value = resource.id
  editName.value = resourceLabel(resource)
}

async function saveRename(resource: OwnedResourceInfo) {
  const name = editName.value.trim()
  if (!name) return
  renaming.value = true
  try {
    await resources.rename(resource.type, resource.id, name)
    editingId.value = ''
    if (selected.value?.id === resource.id) selected.value = resources.resources.find((row) => row.id === resource.id) ?? null
    toast.add({ severity: 'success', summary: t('resources.details.resourceRenamed'), life: 2500 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.renameFailed')), life: 5000 })
  } finally {
    renaming.value = false
  }
}

function signOut(resource: OwnedResourceInfo) {
  confirm.require({
    header: t('resources.details.signOutHeader', { name: resourceLabel(resource) }),
    message: t('resources.details.signOutImpact', { consumers: consumerSummary() }),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('resources.actions.signOutResource'),
    rejectLabel: t('resources.actions.cancel'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.revoke(resource.type, resource.id)
        selected.value = resources.resources.find((row) => row.id === resource.id) ?? null
        toast.add({ severity: 'success', summary: t('resources.details.localCredentialsCleared'), life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.signOutFailed')), life: 5000 })
      }
    },
  })
}

function deleteResource(resource: OwnedResourceInfo) {
  confirm.require({
    header: t('resources.details.deleteHeader', { name: resourceLabel(resource) }),
    message: t('resources.details.deleteImpact', { consumers: consumerSummary() }),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('resources.actions.deleteResource'),
    rejectLabel: t('resources.actions.cancel'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.remove(resource.type, resource.id)
        detailOpen.value = false
        selected.value = null
        toast.add({ severity: 'success', summary: t('resources.details.deleted'), life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.deleteFailed')), life: 5000 })
      }
    },
  })
}

const gitDialogOpen = ref(false)
const gitName = ref('')
const gitToken = ref('')
const gitSaving = ref(false)
async function saveGit() {
  if (!gitName.value.trim() || !gitToken.value.trim()) return
  gitSaving.value = true
  try {
    await git.createCredential(gitName.value.trim(), gitToken.value.trim())
    await resources.fetchResources()
    gitDialogOpen.value = false
    gitName.value = ''
    gitToken.value = ''
    toast.add({ severity: 'success', summary: t('resources.git.saved'), detail: t('resources.git.plaintextNotReturned'), life: 5000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.saveCredential')), life: 5000 })
  } finally {
    gitSaving.value = false
  }
}
function deleteGit(credential: GitCredential) {
  confirm.require({
    header: t('resources.git.confirmDelete', { name: credential.name }),
    message: t('resources.git.deleteImpact'),
    acceptLabel: t('resources.actions.delete'),
    rejectLabel: t('resources.actions.cancel'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      try { await git.deleteCredential(credential.id); await resources.fetchResources() }
      catch (error: any) { toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.deleteFailed')), life: 5000 }) }
    },
  })
}
function formatTimestamp(timestamp: any): string {
  return timestamp
    ? formatDate(timestampDate(timestamp), {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
      })
    : t('resources.common.notAvailable')
}

function updateLabel(status: string): string {
  const labels: Record<string, string> = {
    current: t('resources.status.current'),
    update_available: t('resources.status.updateAvailable'),
    update_recommended: t('resources.status.updateRecommended'),
    manual_update_required: t('resources.status.manualUpdateRequired'),
    unsupported_protocol: t('resources.status.unsupportedProtocol'),
  }
  return (labels[status] ?? status) || t('resources.status.unknown')
}

function updateSeverity(status: string): 'success' | 'info' | 'warn' | 'danger' | 'secondary' {
  if (status === 'current') return 'success'
  if (status === 'update_available') return 'info'
  if (status === 'unsupported_protocol') return 'danger'
  if (status) return 'warn'
  return 'secondary'
}

function retryResources() {
  void resources.fetchResources().catch(() => {})
  void loadHostInventory().catch(() => {})
}

function retryGitCredentials() {
  void git.fetchCredentials().catch(() => {})
}

onMounted(() => {
  void resources.fetchResources().catch(() => {})
  void loadHostInventory().catch(() => {})
  void git.fetchCredentials().catch(() => {})
})
</script>

<template>
  <div class="resources-page">
    <div class="page-heading">
      <h1>{{ t('resources.inventory.title') }}</h1>
      <Button :label="t('resources.actions.enrollHost')" icon="pi pi-plus" outlined @click="router.push('/hosts/connect')" />
    </div>
    <p class="intro">{{ t('resources.inventory.intro') }}</p>

    <Card class="inventory-card">
      <template #title>{{ t('resources.inventory.reusable') }}</template>
      <template #content>
        <Message v-if="resources.error" severity="error" :closable="false">
          <div class="load-error">
            <span>{{ resources.error }}</span>
            <Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="retryResources" />
          </div>
        </Message>
        <DataTable
          v-else-if="!resources.loading || sortedResources.length"
          :value="sortedResources"
          stripedRows
          size="small"
          responsive-layout="scroll"
          row-hover
          @row-click="openResource($event.data)"
        >
          <template #empty><div class="empty">{{ t('resources.inventory.empty') }}</div></template>
          <Column :header="t('resources.inventory.resource')">
            <template #body="{ data }">
              <div v-if="editingId === data.id" class="rename-row" @click.stop>
                <InputText v-model="editName" size="small" autofocus @keydown.enter="saveRename(data)" @keydown.escape="editingId = ''" />
                <Button icon="pi pi-check" size="small" text :loading="renaming" :aria-label="t('resources.actions.saveName')" @click="saveRename(data)" />
                <Button icon="pi pi-times" size="small" text severity="secondary" :aria-label="t('resources.actions.cancelRename')" @click="editingId = ''" />
              </div>
              <div v-else class="resource-cell" :class="{ nested: isNestedConnector(data) }">
                <i v-if="isNestedConnector(data)" class="pi pi-angle-right branch-icon" />
                <div class="resource-name">
                  <span class="primary-name">{{ resourceLabel(data) }}</span>
                  <span class="diagnostic">{{ data.slug }}</span>
                </div>
              </div>
            </template>
          </Column>
          <Column :header="t('resources.inventory.type')"><template #body="{ data }"><span class="type"><i :class="typeMeta[data.type]?.icon || 'pi pi-box'" />{{ typeMeta[data.type]?.label || data.type }}</span></template></Column>
          <Column :header="t('resources.inventory.owner')"><template #body="{ data }">{{ data.ownerName || data.ownerUserId }}</template></Column>
          <Column :header="t('resources.inventory.status')"><template #body="{ data }"><Tag :value="displayedResourceStatus(data).label" :severity="displayedResourceStatus(data).severity" /></template></Column>
          <Column :header="t('resources.inventory.usage')"><template #body="{ data }">{{ usageLabel(data) }}</template></Column>
          <Column :header="t('resources.inventory.yourAccess')"><template #body="{ data }"><div class="capabilities"><Tag v-for="capability in data.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></div></template></Column>
          <Column header="" class="action-column">
            <template #body="{ data }">
              <div class="row-actions" @click.stop>
                <Button v-if="canRename(data)" icon="pi pi-pencil" size="small" text severity="secondary" :aria-label="t('resources.actions.rename')" v-tooltip.top="t('resources.actions.rename')" @click="beginRename(data)" />
                <Button icon="pi pi-angle-right" size="small" text severity="secondary" :aria-label="t('resources.actions.openDetails')" @click="openResource(data)" />
              </div>
            </template>
          </Column>
        </DataTable>
        <div v-else class="skeletons"><Skeleton v-for="i in 3" :key="i" height="3rem" /></div>
      </template>
    </Card>

    <Card>
      <template #title><div class="card-title"><span>{{ t('resources.git.title') }}</span><Button :label="t('resources.actions.addPat')" icon="pi pi-plus" size="small" @click="gitDialogOpen = true" /></div></template>
      <template #subtitle>{{ t('resources.git.subtitle') }}</template>
      <template #content>
        <Message v-if="git.error" severity="error" :closable="false">
          <div class="load-error">
            <span>{{ git.error }}</span>
            <Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="retryGitCredentials" />
          </div>
        </Message>
        <div v-else-if="git.loading" class="skeletons"><Skeleton v-for="i in 2" :key="i" height="3rem" /></div>
        <DataTable v-else :value="git.credentials" stripedRows size="small" responsive-layout="scroll">
          <template #empty><div class="empty">{{ t('resources.git.empty') }}</div></template>
          <Column field="name" :header="t('resources.git.name')" />
          <Column field="type" :header="t('resources.inventory.type')" />
          <Column :header="t('resources.git.created')"><template #body="{ data }">{{ formatTimestamp(data.createdAt) }}</template></Column>
          <Column :header="t('resources.git.lastUsed')"><template #body="{ data }">{{ formatTimestamp(data.lastUsedAt) }}</template></Column>
          <Column header=""><template #body="{ data }"><Button icon="pi pi-trash" severity="danger" text size="small" :aria-label="t('resources.actions.deleteGitCredential')" @click="deleteGit(data)" /></template></Column>
        </DataTable>
      </template>
    </Card>

    <Dialog v-model:visible="detailOpen" :header="selected ? resourceLabel(selected) : t('resources.inventory.resource')" modal :style="{ width: 'min(52rem, calc(100vw - 2rem))' }">
      <div v-if="selected" class="detail-body">
        <div class="detail-heading">
          <div>
            <div class="type"><i :class="typeMeta[selected.type]?.icon || 'pi pi-box'" />{{ typeMeta[selected.type]?.label || selected.type }}</div>
            <div v-if="selected.slug" class="diagnostic">{{ t('resources.details.immutableSlug', { slug: selected.slug }) }}</div>
          </div>
          <Tag :value="displayedResourceStatus(selected).label" :severity="displayedResourceStatus(selected).severity" />
        </div>
        <div class="capabilities"><span class="muted">{{ t('resources.inventory.yourAccessColon') }}</span><Tag v-for="capability in selected.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></div>
        <div class="owner-summary"><span class="muted">{{ t('resources.details.owner') }}</span><strong>{{ selected.ownerName || selected.ownerUserId }}</strong></div>

        <section v-if="selected.type === 'connector'">
          <h3>{{ t('resources.details.installationDetails') }}</h3>
          <Message v-if="!detailAccess.details" severity="secondary" :closable="false">{{ t('resources.details.detailsUnavailable') }}</Message>
          <Skeleton v-else-if="detailLoading" height="14rem" />
          <Message v-else-if="detailError" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ detailError }}</span>
              <Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="retryDetail" />
            </div>
          </Message>
          <template v-else-if="connector">
            <p v-if="connector.description" class="connector-description">{{ connector.description }}</p>
            <Message v-if="connector.readinessMessage" :severity="connector.readiness === 'ready' ? 'success' : 'warn'" :closable="false">{{ connector.readinessMessage }}</Message>
            <dl class="connector-facts">
              <div><dt>{{ t('resources.details.owner') }}</dt><dd>{{ connector.ownerName }} <span class="muted">({{ principalKindLabel(connector.ownerKind) }})</span></dd></div>
              <div><dt>{{ t('resources.details.lifecycle') }}</dt><dd>{{ lifecycleLabel(connector.lifecycle) }}</dd></div>
              <div><dt>{{ t('resources.details.connection') }}</dt><dd>{{ connector.online ? t('resources.status.online') : t('resources.status.offline') }}</dd></div>
              <div><dt>{{ t('resources.details.lastHeartbeat') }}</dt><dd>{{ formatTimestamp(connector.lastSeenAt) }}</dd></div>
              <div><dt>{{ t('resources.details.protocol') }}</dt><dd>{{ connector.protocolMajor }}.{{ connector.protocolMinor }}</dd></div>
              <div><dt>{{ t('resources.details.contract') }}</dt><dd><code>{{ connector.contractId || t('resources.common.notAvailable') }}</code></dd></div>
              <div><dt>{{ t('resources.details.installedArtifact') }}</dt><dd>{{ connector.artifactVersion || t('resources.common.notAvailable') }}</dd></div>
              <div><dt>{{ t('resources.details.artifactProvenance') }}</dt><dd>{{ artifactFreshnessLabel(connector.artifactFreshness) }}</dd></div>
              <div><dt>{{ t('resources.details.update') }}</dt><dd><Tag :value="updateLabel(connector.updateStatus)" :severity="updateSeverity(connector.updateStatus)" /></dd></div>
              <div><dt>{{ t('resources.details.latestArtifact') }}</dt><dd>{{ connector.latestArtifactVersion || t('resources.common.notAvailable') }}</dd></div>
              <div><dt>{{ t('resources.details.latestArtifactBuilt') }}</dt><dd>{{ formatTimestamp(connector.latestArtifactCreatedAt) }}</dd></div>
              <div><dt>{{ t('resources.details.lastReady') }}</dt><dd>{{ formatTimestamp(connector.lastReadyAt) }}</dd></div>
              <div class="wide"><dt>{{ t('resources.details.artifactSha') }}</dt><dd><code class="digest">{{ connector.artifactDigest || t('resources.common.notAvailable') }}</code></dd></div>
              <div class="wide"><dt>{{ t('resources.details.interfaceHash') }}</dt><dd><code class="digest">{{ connector.interfaceHash || t('resources.common.notAvailable') }}</code></dd></div>
              <div class="wide"><dt>{{ t('resources.details.latestArtifactSha') }}</dt><dd><code class="digest">{{ connector.latestArtifactDigest || t('resources.common.notAvailable') }}</code></dd></div>
              <div class="wide"><dt>{{ t('resources.details.latestInterfaceHash') }}</dt><dd><code class="digest">{{ connector.latestInterfaceHash || t('resources.common.notAvailable') }}</code></dd></div>
            </dl>
            <div v-if="connector.features.length" class="label-list"><span class="muted">{{ t('resources.details.protocolFeatures') }}</span><Tag v-for="feature in connector.features" :key="feature" :value="feature" severity="info" /></div>
            <div v-if="Object.keys(connector.labels).length" class="label-list">
              <span class="muted">{{ t('resources.details.labels') }}</span>
              <Tag v-for="(value, key) in connector.labels" :key="key" :value="`${key}=${value}`" severity="secondary" />
            </div>
            <div class="interface-grid">
              <div>
                <h4>{{ t('resources.details.publishedCommands') }}</h4>
                <div v-if="connector.commands.length" class="interface-list">
                  <div v-for="command in connector.commands" :key="`${command.name}:${command.revision}`" class="interface-row">
                    <div><code>{{ command.name }}@{{ command.revision }}</code><Tag :value="command.mode" severity="secondary" /></div>
                    <small>{{ command.description || t('resources.details.noDescription') }}</small>
                    <small class="digest">{{ t('resources.details.commandHashes', { input: command.inputSchemaHash, output: command.outputSchemaHash }) }}</small>
                  </div>
                </div>
                <p v-else class="muted">{{ t('resources.details.noCommands') }}</p>
              </div>
              <div>
                <h4>{{ t('resources.details.publishedDirectories') }}</h4>
                <div v-if="connector.directories.length" class="interface-list">
                  <div v-for="directory in connector.directories" :key="`${directory.name}:${directory.revision}`" class="interface-row">
                    <div><code>{{ directory.name }}@{{ directory.revision }}</code><Tag :value="directoryAccessLabel(directory)" severity="warn" /></div>
                    <small>{{ directory.description || t('resources.details.noDescription') }}</small>
                  </div>
                </div>
                <p v-else class="muted">{{ t('resources.details.noDirectories') }}</p>
              </div>
            </div>
          </template>
        </section>

        <section v-if="hasConsumers(selected)">
          <h3>{{ t('resources.details.consumingApps') }}</h3>
          <Message v-if="!detailAccess.consumers" severity="secondary" :closable="false">{{ t('resources.details.consumersUnavailable') }}</Message>
          <Skeleton v-else-if="consumersLoading || (selected.type === 'connector' && detailLoading)" height="7rem" />
          <Message v-else-if="consumersError || (selected.type === 'connector' && detailError)" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ consumersError || detailError }}</span>
              <Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="selected.type === 'connector' ? retryDetail() : loadConsumers(selected)" />
            </div>
          </Message>
          <div v-else-if="!consumers.length" class="empty compact">{{ t('resources.details.noConsumers') }}</div>
          <div v-else class="consumer-list">
            <template v-for="consumer in consumers" :key="`${consumer.agentId}:${consumer.needType}:${consumer.needSlug}`">
              <RouterLink v-if="consumer.canAccessAgent" :to="{ name: 'agent-detail', params: { id: consumer.agentId }, hash: `#${consumer.needType === 'connection' ? 'connections' : consumer.needType === 'connector' ? 'connectors' : 'mcp-servers'}` }" class="consumer-row consumer-link">
                <span><strong>{{ consumer.agentName || consumer.agentSlug }}</strong><small>{{ consumer.agentSlug }}</small></span>
                <span class="need-type">{{ typeMeta[consumer.needType]?.label || consumer.needType }} · <code>{{ consumer.needSlug }}</code></span>
              </RouterLink>
              <div v-else class="consumer-row">
                <span><strong>{{ consumer.agentName || consumer.agentSlug }}</strong><small>{{ consumer.agentSlug }}</small></span>
                <span class="need-type">{{ typeMeta[consumer.needType]?.label || consumer.needType }} · <code>{{ consumer.needSlug }}</code></span>
              </div>
            </template>
          </div>
        </section>

        <section v-if="detailAccess.grants">
          <div class="section-title">
            <h3>{{ t('resources.details.sharedAccess') }}</h3>
            <Button v-if="canManageSelected" :label="t('resources.actions.addGrant')" icon="pi pi-plus" size="small" :loading="granteesLoading" :disabled="!!granteesError" @click="openGrant()" />
          </div>
          <Skeleton v-if="grantsLoading" height="6rem" />
          <Message v-else-if="grantsError" severity="error" :closable="false"><div class="load-error"><span>{{ grantsError }}</span><Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="loadGrants(selected)" /></div></Message>
          <Message v-else-if="granteesError && canManageSelected" severity="error" :closable="false"><div class="load-error"><span>{{ granteesError }}</span><Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="loadGrantees" /></div></Message>
          <div v-else-if="grants.length" class="grant-list">
            <div v-for="grant in grants" :key="grant.id" class="grant-row">
              <span><strong>{{ grant.displayName || grant.email }}</strong><small>{{ grant.email }}</small></span>
              <div class="grant-actions">
                <div class="capabilities"><Tag v-for="capability in grant.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></div>
                <Button v-if="canManageSelected" icon="pi pi-pencil" text size="small" :aria-label="t('resources.actions.editResourceGrant')" @click="openGrant(grant)" />
                <Button v-if="canManageSelected" icon="pi pi-trash" text size="small" severity="danger" :aria-label="t('resources.actions.deleteResourceGrant')" @click="deleteGrant(grant)" />
              </div>
            </div>
          </div>
          <div v-else class="empty compact">{{ t('resources.details.noGrants') }}</div>
        </section>

        <section v-if="canManageSelected || canTransferSelected || selected.type === 'host' || (selected.type === 'connector' && connector?.hostId)" class="danger-zone">
          <h3>{{ t('resources.details.resourceActions') }}</h3>
          <p class="muted">{{ t('resources.details.actionsHelp') }}</p>
          <div class="danger-actions">
            <Button v-if="selected.type === 'host'" :label="t('resources.actions.openHost')" icon="pi pi-server" outlined @click="router.push(`/settings/hosts/${selected.id}`)" />
            <Button v-else-if="selected.type === 'connector' && connector?.hostId" :label="t('resources.actions.openHost')" icon="pi pi-desktop" outlined @click="router.push(`/settings/hosts/${connector.hostId}`)" />
            <Button v-if="canManageSelected && (selected.type === 'connection' || selected.type === 'mcp_server') && selected.authMode !== 'none'" :label="t('resources.actions.signOutResource')" icon="pi pi-sign-out" severity="secondary" outlined @click="signOut(selected)" />
            <Button v-if="canManageSelected && (selected.type === 'connection' || selected.type === 'mcp_server')" :label="t('resources.actions.deleteResource')" icon="pi pi-trash" severity="danger" outlined @click="deleteResource(selected)" />
            <Button v-if="canTransferSelected" :label="t('resources.actions.transferOwnership')" icon="pi pi-arrow-right-arrow-left" severity="danger" outlined :loading="granteesLoading" :disabled="!!granteesError" @click="transferDialogOpen = true" />
          </div>
        </section>
      </div>
    </Dialog>

    <Dialog v-model:visible="grantDialogOpen" :header="t('resources.details.resourceAccess')" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
      <div class="grant-form">
        <div class="field">
          <label for="resource-grantee">{{ t('resources.details.user') }}</label>
          <Select id="resource-grantee" v-model="grantGranteeId" :options="availableGrantees" option-label="label" option-value="value" :loading="granteesLoading" :disabled="grants.some((grant) => grant.userId === grantGranteeId)" :placeholder="t('resources.details.selectUser')" fluid />
        </div>
        <fieldset>
          <legend>{{ t('resources.details.capabilities') }}</legend>
          <label v-for="capability in supportedGrantCapabilities" :key="capability" class="capability-option">
            <Checkbox v-model="grantCapabilities" :value="capability" />
            <span>{{ capabilityLabel(capability) }}</span>
          </label>
        </fieldset>
        <Message severity="info" :closable="false">{{ t('resources.details.capabilityHelp') }}</Message>
        <div class="dialog-actions"><Button :label="t('resources.actions.cancel')" text severity="secondary" @click="grantDialogOpen = false" /><Button :label="t('resources.actions.saveAccess')" :loading="grantSaving" :disabled="!grantGranteeId || !grantCapabilities.length" @click="saveGrant" /></div>
      </div>
    </Dialog>

    <Dialog v-model:visible="transferDialogOpen" :header="t('resources.details.transferOwnership')" modal :style="{ width: 'min(30rem, calc(100vw - 2rem))' }">
      <div class="grant-form">
        <Message severity="warn" :closable="false">{{ t('resources.details.transferOwnershipHelp') }}</Message>
        <div class="field">
          <label for="transfer-owner">{{ t('resources.details.newOwner') }}</label>
          <Select id="transfer-owner" v-model="transferUserId" :options="availableTransferUsers" option-label="label" option-value="value" :loading="granteesLoading" :placeholder="t('resources.details.selectUser')" fluid />
        </div>
        <div class="dialog-actions"><Button :label="t('resources.actions.cancel')" text severity="secondary" @click="transferDialogOpen = false" /><Button :label="t('resources.actions.transferOwnership')" severity="danger" :loading="transferSaving" :disabled="!transferUserId" @click="transferOwnership" /></div>
      </div>
    </Dialog>

    <Dialog v-model:visible="gitDialogOpen" :header="t('resources.git.addTitle')" modal :style="{ width: 'min(28rem, calc(100vw - 2rem))' }">
      <div class="git-form">
        <Message severity="info" :closable="false">{{ t('resources.git.encryptionHelp') }}</Message>
        <InputText v-model="gitName" :placeholder="t('resources.git.namePlaceholder')" />
        <Password v-model="gitToken" :placeholder="t('resources.auth.token')" :feedback="false" toggle-mask fluid />
        <div class="dialog-actions"><Button :label="t('resources.actions.cancel')" text severity="secondary" @click="gitDialogOpen = false" /><Button :label="t('resources.actions.save')" :loading="gitSaving" :disabled="!gitName.trim() || !gitToken.trim()" @click="saveGit" /></div>
      </div>
    </Dialog>
  </div>
</template>

<style scoped>
.resources-page { max-width: 68rem; }
h1 { margin: 0; font-size: 1.5rem; }
.intro { margin: 0.3rem 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem; }
.inventory-card { margin-bottom: 1.5rem; }
.empty { text-align: center; padding: 2rem; color: var(--p-text-muted-color); }
.empty.compact { padding: 1rem; border: 1px dashed var(--p-content-border-color); border-radius: 0.5rem; }
.page-heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.resource-cell, .resource-name { display: flex; }
.resource-cell { align-items: center; gap: 0.55rem; }
.resource-cell.nested { padding-left: 1.25rem; }
.resource-name { flex-direction: column; }
.branch-icon { color: var(--p-text-muted-color); font-size: 0.75rem; }
.primary-name { font-weight: 600; }
.diagnostic, .muted { color: var(--p-text-muted-color); font-size: 0.8rem; }
.type, .capabilities, .row-actions, .card-title, .detail-heading, .danger-actions, .section-title, .label-list, .grant-actions { display: flex; align-items: center; gap: 0.4rem; }
.type i { color: var(--p-text-muted-color); }
.capabilities { flex-wrap: wrap; }
.row-actions { justify-content: flex-end; }
.card-title, .detail-heading, .section-title { justify-content: space-between; }
.rename-row { display: flex; align-items: center; gap: 0.2rem; }
.skeletons, .detail-body, .git-form, .grant-form, .interface-list, .grant-list { display: flex; flex-direction: column; gap: 1rem; }
.detail-body section { padding-top: 1rem; border-top: 1px solid var(--p-content-border-color); }
.owner-summary { display: flex; align-items: baseline; gap: 0.5rem; }
.detail-body h3 { margin: 0 0 0.6rem; font-size: 1rem; }
.section-title h3 { margin-bottom: 0; }
.detail-body p { margin: 0 0 0.8rem; }
.connector-description { color: var(--p-text-muted-color); }
.connector-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem 1rem; }
.connector-facts div { min-width: 0; }
.connector-facts .wide { grid-column: 1 / -1; }
.connector-facts dt { color: var(--p-text-muted-color); font-size: 0.75rem; }
.connector-facts dd { margin: 0.2rem 0 0; overflow-wrap: anywhere; }
.digest { overflow-wrap: anywhere; word-break: break-word; }
.label-list { flex-wrap: wrap; margin: 1rem 0; }
.interface-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin-top: 1rem; }
.interface-grid h4 { margin: 0 0 0.5rem; }
.interface-row { padding: 0.65rem; border: 1px solid var(--p-content-border-color); border-radius: 0.5rem; }
.interface-row > div { display: flex; align-items: center; gap: 0.4rem; }
.interface-row small { display: block; margin-top: 0.3rem; color: var(--p-text-muted-color); }
.consumer-list { display: flex; flex-direction: column; gap: 0.4rem; }
.consumer-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.65rem; border: 1px solid var(--p-content-border-color); border-radius: 0.5rem; color: inherit; text-decoration: none; }
.consumer-link:hover { border-color: var(--p-primary-color); }
.consumer-row > span:first-child { display: flex; flex-direction: column; }
.consumer-row small { color: var(--p-text-muted-color); }
.need-type { color: var(--p-text-muted-color); font-size: 0.8rem; text-align: right; }
.grant-list { gap: 0.4rem; }
.grant-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.65rem; border: 1px solid var(--p-content-border-color); border-radius: 0.5rem; }
.grant-row > span { display: flex; flex-direction: column; }
.grant-row small { color: var(--p-text-muted-color); }
.grant-actions { justify-content: flex-end; }
.grant-form .field { display: flex; flex-direction: column; gap: 0.35rem; }
.grant-form .field label, .grant-form legend { font-size: 0.85rem; font-weight: 600; }
.grant-form fieldset { display: flex; gap: 1rem; border: 0; padding: 0; margin: 0; }
.capability-option { display: flex; align-items: center; gap: 0.35rem; }
.danger-zone { border-top-color: var(--p-red-300) !important; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
@media (max-width: 44rem) {
  .page-heading { align-items: flex-start; flex-direction: column; }
  .connector-facts, .interface-grid { grid-template-columns: 1fr; }
  .connector-facts .wide { grid-column: auto; }
  .consumer-row { align-items: flex-start; flex-wrap: wrap; }
  .need-type { text-align: left; width: 100%; }
  .danger-actions { align-items: stretch; flex-direction: column; }
  .danger-actions :deep(.p-button) { width: 100%; }
  .grant-row, .grant-actions { align-items: flex-start; flex-direction: column; }
  .grant-actions { width: 100%; }
  .grant-form fieldset { flex-direction: column; }
}
</style>
