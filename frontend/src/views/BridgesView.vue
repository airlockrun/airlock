<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import api from '@/api/client'
import { useBridgesStore } from '@/stores/bridges'
import { useAgentsStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { GetSystemSettingsResponseSchema } from '@/gen/airlock/v1/api_pb'

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
// "System bridge" toggle: admin-only. When on, the backend persists
// the bridge with is_system=true and agentId is forced empty. Mirrors
// the backend's authz.TenantBridgeSystem gate.
const createIsSystem = ref(false)
// Token-source mode: paste an existing bot token, or initiate the
// Telegram Managed Bots create-flow (requires the manager bot to be
// configured in System Settings). The create-new path opens the
// manager-bot deep link in a new tab; the resulting bridge appears
// after the next bridges refresh.
const createTokenSource = ref<'paste' | 'create_new'>('paste')
// Deep link returned by the Managed Bots session-create endpoint.
// Surfaced in the dialog after submit so users on iOS browsers that
// block window.open still have a tappable / copyable fallback.
const pendingDeepLink = ref<string | null>(null)
const deepLinkCopied = ref(false)
// True iff an admin has configured the Telegram manager bot. Without
// it, the Managed Bots create-flow has no bot to dispatch to, so the
// "Create new bot via Telegram" radio stays hidden.
const managerBotConfigured = ref(false)
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
const editing = ref<{ id: string; name: string; agentId: string; isSystem: boolean } | null>(null)
const editAgentID = ref('')
const editIsSystem = ref(false)
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

onMounted(async () => {
  store.fetchBridges()
  agentsStore.fetchAgents()
  try {
    const { data } = await api.get('/api/v1/settings')
    const resp = fromJson(GetSystemSettingsResponseSchema, data)
    managerBotConfigured.value = !!resp.settings?.telegramManagerBotConfigured
  } catch {
    managerBotConfigured.value = false
  }
})

function openCreate() {
  form.value = { name: '', type: 'telegram', token: '', agentId: '' }
  pendingDeepLink.value = null
  deepLinkCopied.value = false
  // Reset to the same defaults the backend would write (DMs off, session
  // mode, 3h TTL, 60s prompt timeout) so the form reflects what we'll
  // send if the operator just hits Create.
  createAllowPublicDMs.value = false
  createSessionMode.value = 'session'
  createTTLAmount.value = 3
  createTTLUnit.value = 'hours'
  createTTLNever.value = false
  createPublicPromptTimeout.value = 60
  createIsSystem.value = false
  createTokenSource.value = 'paste'
  dialogVisible.value = true
}

async function onSubmit() {
  try {
    // Managed Bots flow: server issues a session + Telegram deep link
    // the user opens to create a new bot. The new bridge lands on the
    // next refresh after the manager-bot poller sees the event. We
    // surface the link inside the dialog (instead of just window.open)
    // so iOS browsers that block popups still have a tappable
    // fallback — and we attempt window.open opportunistically.
    if (createTokenSource.value === 'create_new') {
      const deepLink = await store.createManagedBotSession({
        agentId: createIsSystem.value ? undefined : form.value.agentId,
        isSystem: createIsSystem.value,
        suggestedName: form.value.name,
      })
      pendingDeepLink.value = deepLink
      window.open(deepLink, '_blank', 'noopener')
      return
    }
    // CreateBridgeRequest doesn't carry settings yet (proto), so we
    // create-then-update. The brief window between the two requests
    // doesn't open the bridge to the public because the new default in
    // DefaultBridgeSettings is allowPublicDms=false — and we re-issue
    // the explicit choices immediately.
    const agentIdField = createIsSystem.value ? '' : form.value.agentId
    const created = await store.createBridge({
      name: form.value.name,
      type: form.value.type,
      token: form.value.token,
      agentId: agentIdField,
    })
    if (created?.id) {
      await store.updateBridge(created.id, {
        agentId: agentIdField,
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

async function copyDeepLink() {
  if (!pendingDeepLink.value) return
  try {
    await navigator.clipboard.writeText(pendingDeepLink.value)
    deepLinkCopied.value = true
    setTimeout(() => { deepLinkCopied.value = false }, 2000)
  } catch {
    toast.add({ severity: 'error', summary: 'Copy failed — long-press the link to copy manually', life: 4000 })
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
  isSystem?: boolean
  settings?: {
    allowPublicDms?: boolean
    publicSessionTtlSeconds?: number
    publicSessionMode?: string
    publicPromptTimeoutSeconds?: number
  } | null
}) {
  editing.value = {
    id: bridge.id,
    name: bridge.name,
    agentId: bridge.agentId || '',
    isSystem: !!bridge.isSystem,
  }
  editIsSystem.value = !!bridge.isSystem
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
  if (!editIsSystem.value && !editAgentID.value) {
    toast.add({ severity: 'error', summary: 'Pick an agent or enable System bridge', life: 4000 })
    return
  }
  try {
    // System-bound bridges have no per-conversation public-DM controls
    // (the operator surface always requires a linked identity), so we
    // omit settings on that branch — the backend keeps the row's
    // existing JSON.
    const payload: Parameters<typeof store.updateBridge>[1] = {
      agentId: editIsSystem.value ? '' : editAgentID.value,
      isSystem: editIsSystem.value,
    }
    if (!editIsSystem.value) {
      payload.settings = {
        allowPublicDms: editAllowPublicDMs.value,
        publicSessionTtlSeconds: editTTLNever.value ? 0 : ttlToSeconds(editTTLAmount.value, editTTLUnit.value),
        publicSessionMode: editSessionMode.value,
        publicPromptTimeoutSeconds: editPublicPromptTimeout.value,
      }
    }
    await store.updateBridge(editing.value.id, payload)
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
          <span v-if="data.isSystem" style="font-style: italic">System agent</span>
          <template v-else>
            {{ agentsStore.agents.find(a => a.id === data.agentId)?.name || data.agentId || '—' }}
          </template>
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
      <!-- Deep-link panel: shown after the Managed Bots session is
           created. Big tappable link is the iOS browser fallback for
           window.open being blocked. -->
      <div v-if="pendingDeepLink" style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-info-circle" style="color: var(--p-blue-500)" />
          <span style="font-weight: 600">Open Telegram to finish creating your bot</span>
        </div>
        <small style="color: var(--p-text-muted-color)">
          We tried to open Telegram in a new tab. If that didn't work, tap the link below. The new bridge will appear in the list once the bot is created.
        </small>
        <a
          :href="pendingDeepLink"
          target="_blank"
          rel="noopener"
          style="display: flex; align-items: center; justify-content: center; gap: 0.5rem; padding: 0.75rem 1rem; background: var(--p-primary-color); color: var(--p-primary-contrast-color); border-radius: 6px; text-decoration: none; font-weight: 600"
        >
          <i class="pi pi-send" />
          <span>Open in Telegram</span>
        </a>
        <div style="display: flex; gap: 0.5rem; align-items: center">
          <InputText :value="pendingDeepLink" readonly style="flex: 1; font-size: 0.8rem" />
          <Button
            :icon="deepLinkCopied ? 'pi pi-check' : 'pi pi-copy'"
            :label="deepLinkCopied ? 'Copied' : 'Copy'"
            severity="secondary"
            @click="copyDeepLink"
          />
        </div>
      </div>
      <div v-else style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeName">Name</label>
          <InputText id="bridgeName" v-model="form.name" placeholder="My Telegram Bot" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeType">Type</label>
          <Select id="bridgeType" v-model="form.type" :options="bridgeTypes" optionLabel="label" optionValue="value" style="width: 100%" />
        </div>
        <!-- Token source: paste an existing bot's token, or kick off
             the Telegram Managed Bots flow that creates a new bot.
             Hidden when the manager bot isn't configured — the
             create-new path has nothing to dispatch to. -->
        <div v-if="form.type === 'telegram' && managerBotConfigured" style="display: flex; flex-direction: column; gap: 0.5rem">
          <label>Bot</label>
          <div style="display: flex; gap: 1rem">
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer">
              <input type="radio" v-model="createTokenSource" value="paste" />
              <span>Paste existing token</span>
            </label>
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer">
              <input type="radio" v-model="createTokenSource" value="create_new" />
              <span>Create new bot via Telegram</span>
            </label>
          </div>
          <small style="color: var(--p-text-muted-color)">
            Create-new opens Telegram with the airlock manager bot to walk through bot creation.
          </small>
        </div>
        <div v-if="createTokenSource === 'paste'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeToken">Token</label>
          <Password id="bridgeToken" v-model="form.token" :feedback="false" toggleMask />
        </div>
        <!-- System bridge: admin-only. A system bridge isn't bound to
             an agent; inbound DMs route to the in-airlock sysagent
             (operator chat surface). -->
        <div v-if="auth.isAdmin" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">System bridge</div>
            <small style="color: var(--p-text-muted-color)">
              Routes inbound DMs to the airlock system agent instead of an agent. Admin-only.
            </small>
          </div>
          <ToggleSwitch v-model="createIsSystem" />
        </div>
        <div v-if="!createIsSystem" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeAgentId">Agent</label>
          <Select id="bridgeAgentId" v-model="form.agentId" :options="agentsStore.agents" optionLabel="name" optionValue="id" placeholder="Select an agent" style="width: 100%" />
        </div>

        <!-- Public-DM controls are hidden for system bridges: those
             always require a linked identity, so the public-access
             toggles have nothing to govern. -->
        <template v-if="!createIsSystem">
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
        </template>
      </div>
      <template #footer>
        <template v-if="pendingDeepLink">
          <Button label="Done" @click="dialogVisible = false" />
        </template>
        <template v-else>
          <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
          <Button label="Create" @click="onSubmit" />
        </template>
      </template>
    </Dialog>

    <!-- Edit dialog (agent reassignment + per-bridge settings) -->
    <Dialog v-model:visible="editVisible" :header="`Edit ${editing?.name ?? 'bridge'}`" modal style="width: 30rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">

        <!-- System bridge toggle (admin-only). Flipping it switches the
             bridge's surface: on → routes inbound DMs to the in-airlock
             sysagent (no per-agent binding, no public-DM controls); off
             → binds to a specific agent picked below. Backend requires
             admin to cross the boundary in either direction. -->
        <div v-if="auth.isAdmin" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">System bridge</div>
            <small style="color: var(--p-text-muted-color)">
              Routes inbound DMs to the airlock system agent instead of an agent. Admin-only.
            </small>
          </div>
          <ToggleSwitch v-model="editIsSystem" />
        </div>

        <template v-if="!editIsSystem">
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
            style="width: 100%"
          />
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
        </template>

      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="editVisible = false" />
        <Button label="Save" @click="onEdit" />
      </template>
    </Dialog>
  </div>
</template>
