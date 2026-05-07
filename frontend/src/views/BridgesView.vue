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
// Mirrors the edit dialog so operators see and lock the public-access
// posture at creation rather than only after a refresh.
const createAllowPublicDMs = ref(false)
const createSessionMode = ref<'session' | 'one_shot'>('session')
const createTTLAmount = ref(3)
const createTTLUnit = ref<'minutes' | 'hours' | 'days'>('hours')
const createTTLNever = ref(false)
const createPublicPromptTimeout = ref(60)

// Edit dialog — covers both reassignment and per-bridge settings.
const editVisible = ref(false)
const editing = ref<{ id: string; name: string; agentId: string } | null>(null)
const editAgentID = ref('')
const editAllowPublicDMs = ref(true)
const editSessionMode = ref<'session' | 'one_shot'>('session')
const editTTLAmount = ref(3)
const editTTLUnit = ref<'minutes' | 'hours' | 'days'>('hours')
const editTTLNever = ref(false)
const editPublicPromptTimeout = ref(60)

const sessionModes = [
  { label: 'Persistent session', value: 'session', description: 'Conversation history is preserved per channel until the expiry below.' },
  { label: 'One-shot (no history)', value: 'one_shot', description: 'Each message is independent. The replied-to / forwarded message is included as context.' },
]

const ttlUnits = [
  { label: 'Minutes', value: 'minutes' },
  { label: 'Hours', value: 'hours' },
  { label: 'Days', value: 'days' },
]

// pickTTLDisplay turns seconds into the most natural (amount, unit) pair so
// "86400" loads as "1 Day" instead of "24 Hours". Falls back to seconds-as-
// minutes for awkward numbers.
function pickTTLDisplay(seconds: number): { amount: number; unit: 'minutes' | 'hours' | 'days' } {
  if (seconds <= 0) return { amount: 3, unit: 'hours' }
  if (seconds % 86400 === 0) return { amount: seconds / 86400, unit: 'days' }
  if (seconds % 3600 === 0) return { amount: seconds / 3600, unit: 'hours' }
  return { amount: Math.round(seconds / 60), unit: 'minutes' }
}

function ttlToSeconds(amount: number, unit: 'minutes' | 'hours' | 'days'): number {
  if (amount <= 0) return 0
  switch (unit) {
    case 'minutes': return amount * 60
    case 'hours': return amount * 3600
    case 'days': return amount * 86400
  }
}

const bridgeTypes = [
  { label: 'Telegram', value: 'telegram' },
  { label: 'Discord', value: 'discord' },
]

onMounted(() => {
  store.fetchBridges()
  agentsStore.fetchAgents()
})

function openCreate() {
  form.value = { name: '', type: 'telegram', token: '', agentId: '' }
  // Reset to the same defaults the backend would write (DMs off, session
  // mode, 3h TTL, 60s prompt timeout) so the form reflects what we'll
  // send if the operator just hits Create.
  createAllowPublicDMs.value = false
  createSessionMode.value = 'session'
  createTTLAmount.value = 3
  createTTLUnit.value = 'hours'
  createTTLNever.value = false
  createPublicPromptTimeout.value = 60
  dialogVisible.value = true
}

async function onSubmit() {
  try {
    // CreateBridgeRequest doesn't carry settings yet (proto), so we
    // create-then-update. The brief window between the two requests
    // doesn't open the bridge to the public because the new default in
    // DefaultBridgeSettings is allowPublicDms=false — and we re-issue
    // the explicit choices immediately.
    const created = await store.createBridge({
      name: form.value.name,
      type: form.value.type,
      token: form.value.token,
      agentId: form.value.agentId,
    })
    if (created?.id) {
      await store.updateBridge(created.id, {
        agentId: form.value.agentId,
        settings: {
          allowPublicDms: createAllowPublicDMs.value,
          publicSessionTtlSeconds: createTTLNever.value ? 0 : ttlToSeconds(createTTLAmount.value, createTTLUnit.value),
          publicSessionMode: createSessionMode.value,
          publicPromptTimeoutSeconds: createPublicPromptTimeout.value,
        },
      })
    }
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
    case 'discord': return 'pi pi-discord'
    default: return 'pi pi-link'
  }
}

function openEdit(bridge: {
  id: string
  name: string
  agentId: string
  settings?: {
    allowPublicDms?: boolean
    publicSessionTtlSeconds?: number
    publicSessionMode?: string
    publicPromptTimeoutSeconds?: number
  } | null
}) {
  editing.value = { id: bridge.id, name: bridge.name, agentId: bridge.agentId || '' }
  editAgentID.value = bridge.agentId || ''
  editAllowPublicDMs.value = bridge.settings?.allowPublicDms ?? true
  editSessionMode.value = bridge.settings?.publicSessionMode === 'one_shot' ? 'one_shot' : 'session'
  const ttlSecs = bridge.settings?.publicSessionTtlSeconds ?? 10800
  editTTLNever.value = ttlSecs === 0
  const display = pickTTLDisplay(ttlSecs === 0 ? 10800 : ttlSecs)
  editTTLAmount.value = display.amount
  editTTLUnit.value = display.unit
  editPublicPromptTimeout.value = bridge.settings?.publicPromptTimeoutSeconds || 60
  editVisible.value = true
}

async function onEdit() {
  if (!editing.value) return
  try {
    await store.updateBridge(editing.value.id, {
      agentId: editAgentID.value,
      settings: {
        allowPublicDms: editAllowPublicDMs.value,
        publicSessionTtlSeconds: editTTLNever.value ? 0 : ttlToSeconds(editTTLAmount.value, editTTLUnit.value),
        publicSessionMode: editSessionMode.value,
        publicPromptTimeoutSeconds: editPublicPromptTimeout.value,
      },
    })
    toast.add({ severity: 'success', summary: 'Bridge updated', life: 3000 })
    editVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Update failed', life: 5000 })
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
            <Button v-if="canReassign(data)" icon="pi pi-pencil" severity="secondary" text rounded v-tooltip.top="'Edit bridge'" @click="openEdit(data)" />
            <Button v-if="canDelete(data)" icon="pi pi-trash" severity="danger" text rounded @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create dialog -->
    <Dialog v-model:visible="dialogVisible" header="Add Bridge" modal style="width: 30rem">
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

        <!-- Public DMs -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
            <div>
              <div style="font-weight: 600">Allow public DMs</div>
              <small style="color: var(--p-text-muted-color)">
                Off by default — opens the bot to unauthenticated users at public access. <code>/auth</code> still works either way.
              </small>
            </div>
            <ToggleSwitch v-model="createAllowPublicDMs" />
          </div>
        </div>

        <!-- Public session mode -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="font-weight: 600">Public session mode</div>
          <Select
            v-model="createSessionMode"
            :options="sessionModes"
            optionLabel="label"
            optionValue="value"
            style="width: 100%"
          />
          <small style="color: var(--p-text-muted-color)">
            {{ sessionModes.find((m) => m.value === createSessionMode)?.description }}
          </small>
        </div>

        <!-- Public prompt timeout -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div>
            <div style="font-weight: 600">Public prompt timeout</div>
            <small style="color: var(--p-text-muted-color)">
              Wall-clock cap (in seconds) on a single public-DM prompt run. Authed users are unaffected.
            </small>
          </div>
          <InputNumber
            v-model="createPublicPromptTimeout"
            :min="1"
            :max="3600"
            showButtons
            suffix=" sec"
            style="width: 10rem"
            inputStyle="width: 100%"
          />
        </div>

        <!-- Public session expiry — only meaningful in session mode -->
        <div v-if="createSessionMode === 'session'" style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
            <div>
              <div style="font-weight: 600">Public session expiry</div>
              <small style="color: var(--p-text-muted-color)">
                Idle public conversations are finalized and cleared. Authed conversations are unaffected.
              </small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; white-space: nowrap">
              <span style="font-size: 0.85rem; color: var(--p-text-muted-color)">Never</span>
              <ToggleSwitch v-model="createTTLNever" />
            </div>
          </div>
          <div v-if="!createTTLNever" style="display: flex; gap: 0.5rem; align-items: center">
            <InputNumber
              v-model="createTTLAmount"
              :min="1"
              :max="999"
              showButtons
              style="flex: 0 0 8rem"
              inputStyle="width: 100%"
            />
            <Select
              v-model="createTTLUnit"
              :options="ttlUnits"
              optionLabel="label"
              optionValue="value"
              style="flex: 1"
            />
          </div>
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button label="Create" @click="onSubmit" />
      </template>
    </Dialog>

    <!-- Edit dialog (agent reassignment + per-bridge settings) -->
    <Dialog v-model:visible="editVisible" :header="`Edit ${editing?.name ?? 'bridge'}`" modal style="width: 30rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">

        <!-- Agent binding -->
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="editAgent">Agent</label>
          <Select
            id="editAgent"
            v-model="editAgentID"
            :options="agentsStore.agents"
            optionLabel="name"
            optionValue="id"
            placeholder="Select an agent"
            filter
            autoFilterFocus
            showClear
            style="width: 100%"
          />
          <small style="color: var(--p-text-muted-color)">
            Clearing unbinds this bridge — credentials stay so you can reassign it later.
          </small>
        </div>

        <!-- Public DMs -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
            <div>
              <div style="font-weight: 600">Allow public DMs</div>
              <small style="color: var(--p-text-muted-color)">
                Unauthenticated users can chat with the bot at public access. <code>/auth</code> still works either way.
              </small>
            </div>
            <ToggleSwitch v-model="editAllowPublicDMs" />
          </div>
        </div>

        <!-- Public session mode -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="font-weight: 600">Public session mode</div>
          <Select
            v-model="editSessionMode"
            :options="sessionModes"
            optionLabel="label"
            optionValue="value"
            style="width: 100%"
          />
          <small style="color: var(--p-text-muted-color)">
            {{ sessionModes.find((m) => m.value === editSessionMode)?.description }}
          </small>
        </div>

        <!-- Public prompt timeout -->
        <div style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div>
            <div style="font-weight: 600">Public prompt timeout</div>
            <small style="color: var(--p-text-muted-color)">
              Wall-clock cap (in seconds) on a single public-DM prompt run. Authed users are unaffected.
            </small>
          </div>
          <InputNumber
            v-model="editPublicPromptTimeout"
            :min="1"
            :max="3600"
            showButtons
            suffix=" sec"
            style="width: 10rem"
            inputStyle="width: 100%"
          />
        </div>

        <!-- Public session expiry — only meaningful in session mode -->
        <div v-if="editSessionMode === 'session'" style="display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--p-surface-200); padding-top: 1rem">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
            <div>
              <div style="font-weight: 600">Public session expiry</div>
              <small style="color: var(--p-text-muted-color)">
                Idle public conversations are finalized and cleared. Authed conversations are unaffected.
              </small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; white-space: nowrap">
              <span style="font-size: 0.85rem; color: var(--p-text-muted-color)">Never</span>
              <ToggleSwitch v-model="editTTLNever" />
            </div>
          </div>
          <div v-if="!editTTLNever" style="display: flex; gap: 0.5rem; align-items: center">
            <InputNumber
              v-model="editTTLAmount"
              :min="1"
              :max="999"
              showButtons
              style="flex: 0 0 8rem"
              inputStyle="width: 100%"
            />
            <Select
              v-model="editTTLUnit"
              :options="ttlUnits"
              optionLabel="label"
              optionValue="value"
              style="flex: 1"
            />
          </div>
        </div>

      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="editVisible = false" />
        <Button label="Save" @click="onEdit" />
      </template>
    </Dialog>
  </div>
</template>
