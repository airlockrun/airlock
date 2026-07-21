<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import type { OwnedResourceInfo, ResourceConsumerInfo, ResourceGrantInfo } from '@/gen/airlock/v1/api_pb'
import type { GitCredential } from '@/gen/airlock/v1/types_pb'
import { useResourcesStore } from '@/stores/resources'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import { useUsersStore } from '@/stores/users'
import { hasCapability, resourceDetailAccess, resourceLabel, resourceStatus } from '@/utils/resources'

const resources = useResourcesStore()
const git = useGitCredentialsStore()
const users = useUsersStore()
const confirm = useConfirm()
const toast = useToast()

const typeMeta: Record<string, { label: string; icon: string }> = {
  connection: { label: 'Connection', icon: 'pi pi-link' },
  mcp_server: { label: 'MCP server', icon: 'pi pi-bolt' },
  exec_endpoint: { label: 'Exec endpoint', icon: 'pi pi-desktop' },
}
const sortedResources = computed(() => [...resources.resources].sort((a, b) =>
  a.type.localeCompare(b.type) || resourceLabel(a).localeCompare(resourceLabel(b)),
))

const detailOpen = ref(false)
const selected = ref<OwnedResourceInfo | null>(null)
const consumers = ref<ResourceConsumerInfo[]>([])
const grants = ref<ResourceGrantInfo[]>([])
const consumersLoading = ref(false)
const consumersError = ref('')
const grantsLoading = ref(false)
const grantsError = ref('')
const editingId = ref('')
const editName = ref('')
const renaming = ref(false)
const grantGrantee = ref('')
const grantCapabilities = ref<string[]>(['view'])
const grantSaving = ref(false)
const capabilityOptions = [
  { label: 'View', value: 'view' },
  { label: 'Bind', value: 'bind' },
  { label: 'Manage', value: 'manage' },
]

const canManageSelected = computed(() => !!selected.value && hasCapability(selected.value.capabilities, 'manage'))
const detailAccess = computed(() => resourceDetailAccess(selected.value?.capabilities ?? []))
const granteeById = computed(() => new Map(users.selectable.map((user) => [user.id, user])))
const granteeOptions = computed(() => users.selectable.map((user) => ({
  id: user.id,
  label: user.kind === 'group'
    ? user.displayName
    : user.displayName ? `${user.displayName} (${user.email})` : user.email,
})))

function errorMessage(error: any, fallback: string): string {
  return error?.response?.data?.error || fallback
}
function capabilityLabel(capability: string): string {
  return capability.charAt(0).toUpperCase() + capability.slice(1)
}
function granteeLabel(id: string): string {
  const grantee = granteeById.value.get(id)
  if (!grantee) return id
  return grantee.kind === 'group' ? grantee.displayName : grantee.displayName || grantee.email
}
function consumerSummary(): string {
  if (!detailAccess.value.consumers || consumersError.value) return 'This affects every app using it.'
  if (!consumers.value.length) return 'No apps currently use it.'
  return `Used by ${consumers.value.map((consumer) => consumer.agentName || consumer.agentSlug).join(', ')}.`
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
    if (selected.value?.id === resource.id) consumersError.value = errorMessage(error, 'Failed to load consuming apps')
  } finally {
    if (selected.value?.id === resource.id) consumersLoading.value = false
  }
}

async function loadGrants(resource: OwnedResourceInfo) {
  if (!resourceDetailAccess(resource.capabilities).grants) return
  grantsLoading.value = true
  grantsError.value = ''
  grants.value = []
  try {
    const [loaded] = await Promise.all([
      resources.fetchGrants(resource.type, resource.id),
      users.fetchSelectable(),
    ])
    if (selected.value?.id === resource.id) grants.value = loaded
  } catch (error: any) {
    if (selected.value?.id === resource.id) grantsError.value = errorMessage(error, 'Failed to load sharing')
  } finally {
    if (selected.value?.id === resource.id) grantsLoading.value = false
  }
}

async function loadDetail(resource: OwnedResourceInfo) {
  selected.value = resource
  detailOpen.value = true
  consumers.value = []
  grants.value = []
  consumersError.value = ''
  grantsError.value = ''
  grantGrantee.value = ''
  grantCapabilities.value = ['view']
  await Promise.all([loadConsumers(resource), loadGrants(resource)])
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
    toast.add({ severity: 'success', summary: 'Resource renamed', life: 2500 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, 'Rename failed'), life: 5000 })
  } finally {
    renaming.value = false
  }
}

watch(grantGrantee, (id) => {
  const existing = grants.value.find((grant) => grant.granteeId === id)
  grantCapabilities.value = existing ? [...existing.capabilities] : ['view']
})

async function saveGrant() {
  const resource = selected.value
  if (!resource || !resourceDetailAccess(resource.capabilities).grants || !grantGrantee.value || !grantCapabilities.value.length) return
  grantSaving.value = true
  try {
    await resources.grant(resource.type, resource.id, grantGrantee.value, grantCapabilities.value)
    grants.value = await resources.fetchGrants(resource.type, resource.id)
    toast.add({ severity: 'success', summary: 'Sharing updated', life: 2500 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, 'Failed to update sharing'), life: 5000 })
  } finally {
    grantSaving.value = false
  }
}

function revokeGrant(grant: ResourceGrantInfo) {
  const resource = selected.value
  if (!resource || !resourceDetailAccess(resource.capabilities).grants) return
  confirm.require({
    header: 'Revoke shared access?',
    message: `Remove ${granteeLabel(grant.granteeId)}'s ${grant.capabilities.join(', ')} access? Existing app bindings are not removed.`,
    acceptLabel: 'Revoke access',
    rejectLabel: 'Cancel',
    accept: async () => {
      try {
        await resources.revokeGrant(resource.type, resource.id, grant.id)
        grants.value = await resources.fetchGrants(resource.type, resource.id)
        toast.add({ severity: 'success', summary: 'Shared access revoked', life: 2500 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: errorMessage(error, 'Failed to revoke access'), life: 5000 })
      }
    },
  })
}

function signOut(resource: OwnedResourceInfo) {
  confirm.require({
    header: `Sign out ${resourceLabel(resource)}?`,
    message: `Airlock will clear its locally stored credentials for every consumer. ${consumerSummary()} This does not claim to revoke access at the provider.`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Sign out resource',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.revoke(resource.type, resource.id)
        selected.value = resources.resources.find((row) => row.id === resource.id) ?? null
        toast.add({ severity: 'success', summary: 'Local credentials cleared', life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: errorMessage(error, 'Sign out failed'), life: 5000 })
      }
    },
  })
}

function deleteResource(resource: OwnedResourceInfo) {
  confirm.require({
    header: `Delete ${resourceLabel(resource)}?`,
    message: `This permanently deletes the resource, removes its grants, and disconnects every app. ${consumerSummary()}`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Delete resource',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.remove(resource.type, resource.id)
        detailOpen.value = false
        selected.value = null
        toast.add({ severity: 'success', summary: 'Resource deleted', life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: errorMessage(error, 'Delete failed'), life: 5000 })
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
    gitDialogOpen.value = false
    gitName.value = ''
    gitToken.value = ''
    toast.add({ severity: 'success', summary: 'Git credential saved', detail: 'The plaintext token is not returned.', life: 5000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, 'Failed to save credential'), life: 5000 })
  } finally {
    gitSaving.value = false
  }
}
function deleteGit(credential: GitCredential) {
  confirm.require({
    header: `Delete ${credential.name}?`,
    message: 'Apps using this credential lose access to their git remote until another credential is attached.',
    acceptLabel: 'Delete',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try { await git.deleteCredential(credential.id) }
      catch (error: any) { toast.add({ severity: 'error', summary: errorMessage(error, 'Delete failed'), life: 5000 }) }
    },
  })
}
function formatTimestamp(timestamp: any): string {
  return timestamp?.seconds !== undefined ? new Date(Number(timestamp.seconds) * 1000).toLocaleString() : '-'
}

function retryResources() {
  void resources.fetchResources().catch(() => {})
}

function retryGitCredentials() {
  void git.fetchCredentials().catch(() => {})
}

onMounted(() => {
  void resources.fetchResources().catch(() => {})
  void git.fetchCredentials().catch(() => {})
})
</script>

<template>
  <div class="resources-page">
    <h1>Resources</h1>
    <p class="intro">Reusable connections, MCP servers, and exec endpoints available through ownership or sharing. Credentials stay hidden; apps bind resources from their own setup.</p>

    <Card class="inventory-card">
      <template #title>Connections, MCP servers and exec endpoints</template>
      <template #content>
        <Message v-if="resources.error" severity="error" :closable="false">
          <div class="load-error">
            <span>{{ resources.error }}</span>
            <Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="retryResources" />
          </div>
        </Message>
        <DataTable
          v-else-if="!resources.loading || sortedResources.length"
          :value="sortedResources"
          stripedRows
          size="small"
          responsive-layout="scroll"
          row-hover
          @row-click="loadDetail($event.data)"
        >
          <template #empty><div class="empty">No reusable resources are available yet. Create one while setting up an app requirement.</div></template>
          <Column header="Resource">
            <template #body="{ data }">
              <div v-if="editingId === data.id" class="rename-row" @click.stop>
                <InputText v-model="editName" size="small" autofocus @keydown.enter="saveRename(data)" @keydown.escape="editingId = ''" />
                <Button icon="pi pi-check" size="small" text :loading="renaming" aria-label="Save name" @click="saveRename(data)" />
                <Button icon="pi pi-times" size="small" text severity="secondary" aria-label="Cancel rename" @click="editingId = ''" />
              </div>
              <div v-else class="resource-name">
                <span class="primary-name">{{ resourceLabel(data) }}</span>
                <span class="diagnostic">{{ data.slug }}</span>
              </div>
            </template>
          </Column>
          <Column header="Type"><template #body="{ data }"><span class="type"><i :class="typeMeta[data.type]?.icon || 'pi pi-box'" />{{ typeMeta[data.type]?.label || data.type }}</span></template></Column>
          <Column header="Status"><template #body="{ data }"><Tag :value="resourceStatus(data).label" :severity="resourceStatus(data).severity" /></template></Column>
          <Column header="Used by"><template #body="{ data }">{{ data.agentCount }} app{{ data.agentCount === 1 ? '' : 's' }}</template></Column>
          <Column header="Your access"><template #body="{ data }"><div class="capabilities"><Tag v-for="capability in data.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></div></template></Column>
          <Column header="" class="action-column">
            <template #body="{ data }">
              <div class="row-actions" @click.stop>
                <Button v-if="hasCapability(data.capabilities, 'manage')" icon="pi pi-pencil" size="small" text severity="secondary" aria-label="Rename resource" v-tooltip.top="'Rename'" @click="beginRename(data)" />
                <Button icon="pi pi-angle-right" size="small" text severity="secondary" aria-label="Open details" @click="loadDetail(data)" />
              </div>
            </template>
          </Column>
        </DataTable>
        <div v-else class="skeletons"><Skeleton v-for="i in 3" :key="i" height="3rem" /></div>
      </template>
    </Card>

    <Card>
      <template #title><div class="card-title"><span>Git credentials</span><Button label="Add PAT" icon="pi pi-plus" size="small" @click="gitDialogOpen = true" /></div></template>
      <template #subtitle>Personal access tokens for app source remotes.</template>
      <template #content>
        <Message v-if="git.error" severity="error" :closable="false">
          <div class="load-error">
            <span>{{ git.error }}</span>
            <Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="retryGitCredentials" />
          </div>
        </Message>
        <div v-else-if="git.loading" class="skeletons"><Skeleton v-for="i in 2" :key="i" height="3rem" /></div>
        <DataTable v-else :value="git.credentials" stripedRows size="small" responsive-layout="scroll">
          <template #empty><div class="empty">No git credentials yet.</div></template>
          <Column field="name" header="Name" />
          <Column field="type" header="Type" />
          <Column header="Created"><template #body="{ data }">{{ formatTimestamp(data.createdAt) }}</template></Column>
          <Column header="Last used"><template #body="{ data }">{{ formatTimestamp(data.lastUsedAt) }}</template></Column>
          <Column header=""><template #body="{ data }"><Button icon="pi pi-trash" severity="danger" text size="small" aria-label="Delete git credential" @click="deleteGit(data)" /></template></Column>
        </DataTable>
      </template>
    </Card>

    <Dialog v-model:visible="detailOpen" :header="selected ? resourceLabel(selected) : 'Resource'" modal :style="{ width: 'min(52rem, calc(100vw - 2rem))' }">
      <div v-if="selected" class="detail-body">
        <div class="detail-heading">
          <div>
            <div class="type"><i :class="typeMeta[selected.type]?.icon" />{{ typeMeta[selected.type]?.label }}</div>
            <div class="diagnostic">Immutable slug: <code>{{ selected.slug }}</code></div>
          </div>
          <Tag :value="resourceStatus(selected).label" :severity="resourceStatus(selected).severity" />
        </div>
        <div class="capabilities"><span class="muted">Your access:</span><Tag v-for="capability in selected.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></div>

        <section>
          <h3>Consuming apps</h3>
          <Message v-if="!detailAccess.consumers" severity="secondary" :closable="false">Consumer details are unavailable without view access.</Message>
          <Skeleton v-else-if="consumersLoading" height="7rem" />
          <Message v-else-if="consumersError" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ consumersError }}</span>
              <Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="loadConsumers(selected)" />
            </div>
          </Message>
          <div v-else-if="!consumers.length" class="empty compact">No apps currently use this resource.</div>
          <div v-else class="consumer-list">
            <template v-for="consumer in consumers" :key="`${consumer.agentId}:${consumer.needType}:${consumer.needSlug}`">
              <RouterLink v-if="consumer.canAccessAgent" :to="{ name: 'agent-detail', params: { id: consumer.agentId }, hash: `#${consumer.needType === 'connection' ? 'connections' : consumer.needType === 'mcp_server' ? 'mcp-servers' : 'exec-endpoints'}` }" class="consumer-row consumer-link">
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

        <section>
          <h3>Sharing</h3>
          <Message v-if="!detailAccess.grants" severity="secondary" :closable="false">Sharing details are unavailable without manage access.</Message>
          <Skeleton v-else-if="grantsLoading" height="10rem" />
          <Message v-else-if="grantsError" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ grantsError }}</span>
              <Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="loadGrants(selected)" />
            </div>
          </Message>
          <template v-else-if="canManageSelected">
            <p class="muted">View reveals metadata. Bind lets someone connect it to apps they administer. Manage lets them rename, reconfigure, sign out, delete, and share it.</p>
            <div class="grant-editor">
              <Select v-model="grantGrantee" :options="granteeOptions" option-label="label" option-value="id" placeholder="Select user or group" filter />
              <SelectButton v-model="grantCapabilities" :options="capabilityOptions" option-label="label" option-value="value" multiple />
              <Button label="Save access" :loading="grantSaving" :disabled="!grantGrantee || !grantCapabilities.length" @click="saveGrant" />
            </div>
            <div v-if="grants.length" class="grant-list">
              <div v-for="grant in grants" :key="grant.id" class="grant-row">
                <span><i :class="granteeById.get(grant.granteeId)?.kind === 'group' ? 'pi pi-users' : 'pi pi-user'" /> {{ granteeLabel(grant.granteeId) }}</span>
                <span class="capabilities"><Tag v-for="capability in grant.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></span>
                <Button icon="pi pi-trash" size="small" text severity="danger" aria-label="Revoke grant" @click="revokeGrant(grant)" />
              </div>
            </div>
          </template>
        </section>

        <section v-if="canManageSelected" class="danger-zone">
          <h3>Resource actions</h3>
          <p class="muted">Disconnecting one app only removes that app's binding. Signing out or deleting here affects the shared resource and every consuming app.</p>
          <div class="danger-actions">
            <Button v-if="selected.type !== 'exec_endpoint' && selected.authMode !== 'none'" label="Sign out resource" icon="pi pi-sign-out" severity="secondary" outlined @click="signOut(selected)" />
            <Button label="Delete resource" icon="pi pi-trash" severity="danger" outlined @click="deleteResource(selected)" />
          </div>
        </section>
      </div>
    </Dialog>

    <Dialog v-model:visible="gitDialogOpen" header="Add Personal Access Token" modal :style="{ width: 'min(28rem, calc(100vw - 2rem))' }">
      <div class="git-form">
        <Message severity="info" :closable="false">Airlock encrypts the token at rest and never returns the plaintext.</Message>
        <InputText v-model="gitName" placeholder="Name, e.g. GitHub Personal" />
        <Password v-model="gitToken" placeholder="Token" :feedback="false" toggle-mask fluid />
        <div class="dialog-actions"><Button label="Cancel" text severity="secondary" @click="gitDialogOpen = false" /><Button label="Save" :loading="gitSaving" :disabled="!gitName.trim() || !gitToken.trim()" @click="saveGit" /></div>
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
.resource-name { display: flex; flex-direction: column; }
.primary-name { font-weight: 600; }
.diagnostic, .muted { color: var(--p-text-muted-color); font-size: 0.8rem; }
.type, .capabilities, .row-actions, .card-title, .detail-heading, .danger-actions { display: flex; align-items: center; gap: 0.4rem; }
.type i { color: var(--p-text-muted-color); }
.capabilities { flex-wrap: wrap; }
.row-actions { justify-content: flex-end; }
.card-title, .detail-heading { justify-content: space-between; }
.rename-row { display: flex; align-items: center; gap: 0.2rem; }
.skeletons, .detail-body, .git-form { display: flex; flex-direction: column; gap: 1rem; }
.detail-body section { padding-top: 1rem; border-top: 1px solid var(--p-content-border-color); }
.detail-body h3 { margin: 0 0 0.6rem; font-size: 1rem; }
.detail-body p { margin: 0 0 0.8rem; }
.consumer-list, .grant-list { display: flex; flex-direction: column; gap: 0.4rem; }
.consumer-row, .grant-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.65rem; border: 1px solid var(--p-content-border-color); border-radius: 0.5rem; color: inherit; text-decoration: none; }
.consumer-link:hover { border-color: var(--p-primary-color); }
.consumer-row > span:first-child { display: flex; flex-direction: column; }
.consumer-row small { color: var(--p-text-muted-color); }
.need-type { color: var(--p-text-muted-color); font-size: 0.8rem; text-align: right; }
.grant-editor { display: grid; grid-template-columns: minmax(12rem, 1fr) auto auto; align-items: center; gap: 0.6rem; margin-bottom: 0.8rem; }
.grant-row > :first-child { flex: 1; }
.danger-zone { border-top-color: var(--p-red-300) !important; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
@media (max-width: 44rem) {
  .grant-editor { grid-template-columns: 1fr; }
  .consumer-row, .grant-row { align-items: flex-start; flex-wrap: wrap; }
  .need-type { text-align: left; width: 100%; }
  .danger-actions { align-items: stretch; flex-direction: column; }
  .danger-actions :deep(.p-button) { width: 100%; }
}
</style>
