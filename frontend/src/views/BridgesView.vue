<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useBridgesStore } from '@/stores/bridges'
import { useAgentsStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'

const store = useBridgesStore()
const agentsStore = useAgentsStore()
const auth = useAuthStore()
const toast = useToast()
const confirm = useConfirm()

// True iff the current user owns the bridge — only the owner can change
// what agent it's bound to. Admin can still delete (escape hatch).
function canReassign(bridge: { owner?: { id?: string } | null }): boolean {
  return !!bridge.owner?.id && bridge.owner.id === auth.user?.id
}

// Anyone allowed to view a bridge can also delete their own; admins can
// delete any bridge, including system bridges.
function canDelete(bridge: { owner?: { id?: string } | null }): boolean {
  if (auth.isAdmin) return true
  return canReassign(bridge)
}

const dialogVisible = ref(false)
const form = ref({ name: '', type: 'telegram', token: '', agentId: '' })

// Reassign dialog — separate from create to avoid co-mingling state.
const reassignVisible = ref(false)
const reassigning = ref<{ id: string; name: string; agentId: string } | null>(null)
const reassignAgentID = ref('')

const bridgeTypes = [
  { label: 'Telegram', value: 'telegram' },
]

onMounted(() => {
  store.fetchBridges()
  agentsStore.fetchAgents()
})

function openCreate() {
  form.value = { name: '', type: 'telegram', token: '', agentId: '' }
  dialogVisible.value = true
}

async function onSubmit() {
  try {
    await store.createBridge({
      name: form.value.name,
      type: form.value.type,
      token: form.value.token,
      agentId: form.value.agentId,
    })
    toast.add({ severity: 'success', summary: 'Bridge created', life: 3000 })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Create failed', life: 5000 })
  }
}

function formatType(t: string): string {
  if (!t) return 'unknown'
  return t.charAt(0).toUpperCase() + t.slice(1)
}

function typeIcon(t: string): string {
  switch (t) {
    case 'telegram': return 'pi pi-send'
    default: return 'pi pi-link'
  }
}

function openReassign(bridge: { id: string; name: string; agentId: string }) {
  reassigning.value = { id: bridge.id, name: bridge.name, agentId: bridge.agentId || '' }
  reassignAgentID.value = bridge.agentId || ''
  reassignVisible.value = true
}

async function onReassign() {
  if (!reassigning.value) return
  if (reassignAgentID.value === (reassigning.value.agentId || '')) {
    reassignVisible.value = false
    return
  }
  try {
    await store.updateBridge(reassigning.value.id, { agentId: reassignAgentID.value })
    toast.add({ severity: 'success', summary: 'Bridge reassigned', life: 3000 })
    reassignVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Reassign failed', life: 5000 })
  }
}

function confirmDelete(bridge: { id: string; name: string }) {
  confirm.require({
    message: `Delete bridge "${bridge.name}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteBridge(bridge.id)
        toast.add({ severity: 'success', summary: 'Bridge deleted', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Bridges</h1>
      <Button v-if="auth.isManagerOrAdmin" label="Add Bridge" icon="pi pi-plus" @click="openCreate" />
    </div>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column header="Name"><template #body><Skeleton width="60%" /></template></Column>
      <Column header="Type"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Bot Username"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Agent"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Owner"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Status"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Actions"><template #body><Skeleton width="3rem" /></template></Column>
    </DataTable>

    <!-- Data table -->
    <DataTable v-else :value="store.bridges" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No bridges configured yet.
        </div>
      </template>
      <Column field="name" header="Name" />
      <Column header="Type">
        <template #body="{ data }">
          <Tag :value="formatType(data.type)" :icon="typeIcon(data.type)" severity="info" />
        </template>
      </Column>
      <Column field="botUsername" header="Bot Username" />
      <Column header="Agent">
        <template #body="{ data }">
          {{ agentsStore.agents.find(a => a.id === data.agentId)?.name || data.agentId || '—' }}
        </template>
      </Column>
      <Column header="Owner">
        <template #body="{ data }">
          <span v-if="data.owner" v-tooltip.top="data.owner.email">
            {{ data.owner.displayName || data.owner.email }}
          </span>
          <span v-else style="color: var(--p-text-muted-color)">System</span>
        </template>
      </Column>
      <Column header="Status">
        <template #body="{ data }">
          <Tag :value="data.status || 'unknown'" :severity="data.status === 'active' ? 'success' : 'secondary'" />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <div style="display: flex; gap: 0.25rem">
            <Button v-if="canReassign(data)" icon="pi pi-user-edit" severity="secondary" text rounded v-tooltip.top="'Reassign agent'" @click="openReassign(data)" />
            <Button v-if="canDelete(data)" icon="pi pi-trash" severity="danger" text rounded @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create dialog -->
    <Dialog v-model:visible="dialogVisible" header="Add Bridge" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeName">Name</label>
          <InputText id="bridgeName" v-model="form.name" placeholder="My Telegram Bot" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeType">Type</label>
          <Select id="bridgeType" v-model="form.type" :options="bridgeTypes" optionLabel="label" optionValue="value" style="width: 100%" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeToken">Token</label>
          <Password id="bridgeToken" v-model="form.token" :feedback="false" toggleMask />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeAgentId">Agent</label>
          <Select id="bridgeAgentId" v-model="form.agentId" :options="agentsStore.agents" optionLabel="name" optionValue="id" placeholder="Select an agent" style="width: 100%" />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button label="Create" @click="onSubmit" />
      </template>
    </Dialog>

    <!-- Reassign dialog -->
    <Dialog v-model:visible="reassignVisible" :header="`Reassign ${reassigning?.name ?? 'bridge'}`" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <p style="margin: 0; color: var(--p-text-muted-color); font-size: 0.85rem">
          Forward incoming messages to a different agent. The running poller reloads immediately.
        </p>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="reassignAgent">Agent</label>
          <Select
            id="reassignAgent"
            v-model="reassignAgentID"
            :options="agentsStore.agents"
            optionLabel="name"
            optionValue="id"
            placeholder="Select an agent"
            filter
            autoFilterFocus
            showClear
            style="width: 100%"
          />
          <small style="color: var(--p-text-muted-color)">Clearing makes this a system bridge (admin only).</small>
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="reassignVisible = false" />
        <Button label="Save" @click="onReassign" />
      </template>
    </Dialog>
  </div>
</template>
