<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
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
const form = ref({ name: '', type: 'telegram', token: '', agentId: '', isManager: false })
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
// True iff a Telegram manager bridge (is_manager) exists. Without it the
// Managed Bots create-flow has no bot to dispatch to, so the "Create new bot
// via Telegram" radio stays hidden. Derived from the bridge list — the
// manager is now a bridge capability, not a separate settings token.
const managerBotConfigured = computed(() =>
  store.bridges.some((b) => b.isManager && b.type === 'telegram'),
)

// Agent picker options: the caller's own agents first, then alphabetical by
// name. Names aren't unique, so the option rows also show the slug + owner to
// disambiguate; the filter box matches name / slug / owner.
const agentOptions = computed(() =>
  [...agentsStore.agents].sort((a, b) => {
    if (a.isOwner !== b.isOwner) return a.isOwner ? -1 : 1
    return a.name.localeCompare(b.name)
  }),
)
// Edit dialog — covers both reassignment and per-bridge settings.
const editVisible = ref(false)
const editing = ref<{ id: string; name: string; agentId: string; isSystem: boolean } | null>(null)
const editAgentID = ref('')
const editIsSystem = ref(false)
const editType = ref('telegram')
const editIsManager = ref(false)

onMounted(() => {
  store.fetchBridges()
  agentsStore.fetchAgents()
})

function openCreate() {
  form.value = { name: '', type: 'telegram', token: '', agentId: '', isManager: false }
  pendingDeepLink.value = null
  deepLinkCopied.value = false
  createIsSystem.value = false
  createTokenSource.value = managerBotConfigured.value ? 'create_new' : 'paste'
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
    // System and manager bridges are never agent-bound.
    const agentIdField = createIsSystem.value || form.value.isManager ? '' : form.value.agentId
    await store.createBridge({
      type: form.value.type,
      token: form.value.token,
      agentId: agentIdField,
      isSystem: createIsSystem.value,
      isManager: form.value.type === 'telegram' ? form.value.isManager : false,
    })
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
    toast.add({ severity: 'error', summary: 'Copy failed - long-press the link to copy manually', life: 4000 })
  }
}

function openEdit(bridge: {
  id: string
  name: string
  agentId: string
  isSystem?: boolean
  type?: string
  isManager?: boolean
}) {
  editing.value = {
    id: bridge.id,
    name: bridge.name,
    agentId: bridge.agentId || '',
    isSystem: !!bridge.isSystem,
  }
  editIsSystem.value = !!bridge.isSystem
  editAgentID.value = bridge.agentId || ''
  editType.value = bridge.type || 'telegram'
  editIsManager.value = !!bridge.isManager
  editVisible.value = true
}

async function onEdit() {
  if (!editing.value) return
  const isManagerEdit = editType.value === 'telegram' && auth.can('tenant.manager_bot.config') && editIsManager.value
  // A manager or system bridge isn't agent-bound; otherwise an agent is required.
  if (!editIsSystem.value && !isManagerEdit && !editAgentID.value) {
    toast.add({ severity: 'error', summary: 'Pick an app, or enable System / Manager bridge', life: 4000 })
    return
  }
  try {
    const payload: Parameters<typeof store.updateBridge>[1] = {
      agentId: editIsSystem.value || isManagerEdit ? '' : editAgentID.value,
      isSystem: editIsSystem.value,
    }
    // Manager capability is Telegram-only + admin-gated. Only send it when the
    // toggle is shown; otherwise leave the flag as-is on the server.
    if (editType.value === 'telegram' && auth.can('tenant.manager_bot.config')) {
      payload.isManager = editIsManager.value
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
      <Button v-if="auth.can('tenant.bridge.create')" label="Add Bridge" icon="pi pi-plus" @click="openCreate" />
    </div>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column header="Name"><template #body><Skeleton width="60%" /></template></Column>
      <Column header="Bot Username"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Role"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="App"><template #body><Skeleton width="40%" /></template></Column>
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
      <Column field="botUsername" header="Bot Username" />
      <Column header="Role">
        <template #body="{ data }">
          <Tag
            v-if="data.isManager"
            value="Manager"
            :severity="data.managerError ? 'warn' : 'success'"
            v-tooltip.top="data.managerError || 'Creates new bots via the deep-link flow'"
          />
          <span v-else style="color: var(--p-text-muted-color)">App bot</span>
        </template>
      </Column>
      <Column header="App">
        <template #body="{ data }">
          <span v-if="data.isSystem" style="font-style: italic">Airlock Assistant</span>
          <template v-else>
            {{ agentsStore.agents.find(a => a.id === data.agentId)?.name || data.agentId || '-' }}
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
        <Message severity="warn" :closable="false">
          Keep the suggested bot <b>username</b> exactly as Telegram pre-fills it - airlock binds the new bot back to this workspace by that username, so changing it leaves the bot orphaned. You can freely edit the bot's display name.
        </Message>
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
        <!-- Token source: paste an existing bot's token, or kick off
             the Telegram Managed Bots flow that creates a new bot.
             Hidden when the manager bot isn't configured — the
             create-new path has nothing to dispatch to. -->
        <div v-if="form.type === 'telegram' && managerBotConfigured" style="display: flex; flex-direction: column; gap: 0.5rem">
          <div class="bot-source-switch">
            <button
              type="button"
              class="bot-source-option"
              :class="{ active: createTokenSource === 'create_new' }"
              @click="createTokenSource = 'create_new'"
            >
              <i class="pi pi-send" />
              <span>Create in Telegram</span>
            </button>
            <button
              type="button"
              class="bot-source-option"
              :class="{ active: createTokenSource === 'paste' }"
              @click="createTokenSource = 'paste'"
            >
              <i class="pi pi-key" />
              <span>Paste token</span>
            </button>
          </div>
          <small v-if="createTokenSource === 'create_new'" style="color: var(--p-text-muted-color)">
            Create-new opens Telegram with the airlock manager bot to walk through bot creation. Keep the suggested username unchanged - airlock uses it to bind the bot back.
          </small>
          <small v-else style="color: var(--p-text-muted-color)">
            Paste a token from BotFather for a bot you already created.
          </small>
        </div>
        <!-- System bridge: admin-only. A system bridge isn't bound to
             an agent; inbound DMs route to the in-airlock sysagent
             (operator chat surface). -->
        <div v-if="auth.can('tenant.bridge.system')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">System bridge</div>
            <small style="color: var(--p-text-muted-color)">
              Routes inbound DMs to the Airlock Assistant instead of an app. Admin-only.
            </small>
          </div>
          <ToggleSwitch v-model="createIsSystem" />
        </div>
        <!-- A manager bridge is never agent-bound (it's the bot that creates
             other bots): hide the agent picker when manager is on. Keep this
             near the top so mobile keyboards don't obscure it. -->
        <div v-if="!createIsSystem && !form.isManager" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeAgentId">App</label>
          <Select
            id="bridgeAgentId"
            v-model="form.agentId"
            :options="agentOptions"
            optionLabel="name"
            optionValue="id"
            placeholder="Select an app"
            style="width: 100%"
          >
            <template #option="{ option }">
              <div style="display: flex; flex-direction: column">
                <span><span style="font-weight: 600">{{ option.name }}</span> <span style="color: var(--p-text-muted-color); font-size: 0.85em">{{ option.slug }}</span></span>
                <small style="color: var(--p-text-muted-color)">{{ option.ownerName || 'unknown owner' }}{{ option.isOwner ? ' · you' : '' }}</small>
              </div>
            </template>
          </Select>
        </div>
        <div v-if="createTokenSource === 'paste'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeToken">Token</label>
          <Password id="bridgeToken" v-model="form.token" :feedback="false" toggleMask />
          <small style="color: var(--p-text-muted-color)">The bridge name is taken from the bot's display name and kept in sync automatically.</small>
        </div>
        <div v-if="createTokenSource === 'create_new'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeBotName">Bot name</label>
          <InputText id="bridgeBotName" v-model="form.name" placeholder="My Telegram Bot" />
          <small style="color: var(--p-text-muted-color)">Suggested name for the new bot. The bridge then mirrors the bot's display name.</small>
        </div>
        <!-- Manager capability: Telegram-only, admin-only. Lets this bot
             create new bots for users via the deep-link flow. The pasted
             token's bot must have can_manage_bots enabled in BotFather. -->
        <div v-if="form.type === 'telegram' && createTokenSource === 'paste' && auth.can('tenant.manager_bot.config')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">Manager bot</div>
            <small style="color: var(--p-text-muted-color)">
              Enables the "Create new bot via Telegram" flow. Requires <code>can_manage_bots</code> in BotFather. At most one across the instance.
            </small>
          </div>
          <ToggleSwitch v-model="form.isManager" />
        </div>
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
        <div v-if="auth.can('tenant.bridge.system')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">System bridge</div>
            <small style="color: var(--p-text-muted-color)">
              Routes inbound DMs to the Airlock Assistant instead of an app. Admin-only.
            </small>
          </div>
          <ToggleSwitch v-model="editIsSystem" />
        </div>

        <!-- Manager capability: Telegram-only, admin-only. Lets this bot
             create new bots for users via the deep-link flow. The bot's
             token must have can_manage_bots enabled in BotFather. -->
        <div v-if="editType === 'telegram' && auth.can('tenant.manager_bot.config')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">Manager bot</div>
            <small style="color: var(--p-text-muted-color)">
              Enables the "Create new bot via Telegram" flow. Requires <code>can_manage_bots</code> in BotFather. At most one across the instance.
            </small>
          </div>
          <ToggleSwitch v-model="editIsManager" />
        </div>

        <!-- A manager bridge is never agent-bound: hide the agent picker when
             manager (or system) is on. -->
        <template v-if="!editIsSystem && !editIsManager">
        <!-- Agent binding -->
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="editAgent">App</label>
          <Select
            id="editAgent"
            v-model="editAgentID"
            :options="agentOptions"
            optionLabel="name"
            optionValue="id"
            placeholder="Select an app"
            filter
            :filterFields="['name', 'slug', 'ownerName']"
            autoFilterFocus
            style="width: 100%"
          >
            <template #option="{ option }">
              <div style="display: flex; flex-direction: column">
                <span><span style="font-weight: 600">{{ option.name }}</span> <span style="color: var(--p-text-muted-color); font-size: 0.85em">{{ option.slug }}</span></span>
                <small style="color: var(--p-text-muted-color)">{{ option.ownerName || 'unknown owner' }}{{ option.isOwner ? ' · you' : '' }}</small>
              </div>
            </template>
          </Select>
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

<style scoped>
.bot-source-switch {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

.bot-source-option {
  border: 1px solid var(--p-surface-border);
  border-radius: 0.5rem;
  background: var(--p-surface-0);
  color: var(--p-text-color);
  padding: 0.65rem 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.45rem;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  min-width: 0;
}

.bot-source-option span {
  white-space: nowrap;
}

.bot-source-option.active {
  border-color: var(--p-primary-color);
  background: color-mix(in srgb, var(--p-primary-color) 12%, transparent);
  color: var(--p-primary-color);
}

:root.dark .bot-source-option {
  background: var(--p-surface-800);
}

@media (max-width: 420px) {
  .bot-source-switch {
    grid-template-columns: 1fr;
  }
}
</style>
