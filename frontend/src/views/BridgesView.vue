<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useBridgesStore } from '@/stores/bridges'
import { useAgentsStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { useAirlockI18n } from '@/i18n'

const store = useBridgesStore()
const agentsStore = useAgentsStore()
const auth = useAuthStore()
const toast = useToast()
const confirm = useConfirm()
const { t, locale } = useAirlockI18n()

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

function statusLabel(status: string): string {
  if (status === 'active') return t('resources.bridges.statusActive')
  if (status === 'error') return t('resources.bridges.statusError')
  return t('resources.bridges.unknownStatus')
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
    return a.name.localeCompare(b.name, locale.value)
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
    toast.add({ severity: 'success', summary: t('resources.bridges.created'), life: 3000 })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('resources.errors.createFailed'), life: 5000 })
  }
}

async function copyDeepLink() {
  if (!pendingDeepLink.value) return
  try {
    await navigator.clipboard.writeText(pendingDeepLink.value)
    deepLinkCopied.value = true
    setTimeout(() => { deepLinkCopied.value = false }, 2000)
  } catch {
    toast.add({ severity: 'error', summary: t('resources.bridges.copyFailed'), life: 4000 })
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
    toast.add({ severity: 'error', summary: t('resources.bridges.pickApp'), life: 4000 })
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
    toast.add({ severity: 'success', summary: t('resources.bridges.updated'), life: 3000 })
    editVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('resources.errors.updateFailed'), life: 5000 })
  }
}

function confirmDelete(bridge: { id: string; name: string }) {
  confirm.require({
    message: t('resources.bridges.confirmDelete', { name: bridge.name }),
    header: t('resources.bridges.confirmDeleteHeader'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteBridge(bridge.id)
        toast.add({ severity: 'success', summary: t('resources.bridges.deleted'), life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('resources.errors.deleteFailed'), life: 5000 })
      }
    },
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">{{ t('resources.bridges.title') }}</h1>
      <Button v-if="auth.can('tenant.bridge.create')" :label="t('resources.actions.addBridge')" icon="pi pi-plus" @click="openCreate" />
    </div>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column :header="t('resources.bridges.name')"><template #body><Skeleton width="60%" /></template></Column>
      <Column :header="t('resources.bridges.botUsername')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('resources.bridges.role')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column :header="t('resources.bridges.app')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('resources.bridges.owner')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('resources.bridges.status')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column :header="t('resources.bridges.actions')"><template #body><Skeleton width="3rem" /></template></Column>
    </DataTable>

    <!-- Data table -->
    <DataTable v-else :value="store.bridges" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('resources.bridges.empty') }}
        </div>
      </template>
      <Column field="name" :header="t('resources.bridges.name')" />
      <Column field="botUsername" :header="t('resources.bridges.botUsername')" />
      <Column :header="t('resources.bridges.role')">
        <template #body="{ data }">
          <Tag
            v-if="data.isManager"
            :value="t('resources.bridges.manager')"
            :severity="data.managerError ? 'warn' : 'success'"
            v-tooltip.top="data.managerError || t('resources.bridges.managerTooltip')"
          />
          <span v-else style="color: var(--p-text-muted-color)">{{ t('resources.bridges.appBot') }}</span>
        </template>
      </Column>
      <Column :header="t('resources.bridges.app')">
        <template #body="{ data }">
          <span v-if="data.isSystem" style="font-style: italic">{{ t('resources.bridges.airlockAssistant') }}</span>
          <template v-else>
            {{ agentsStore.agents.find(a => a.id === data.agentId)?.name || data.agentId || '-' }}
          </template>
        </template>
      </Column>
      <Column :header="t('resources.bridges.owner')">
        <template #body="{ data }">
          <span v-if="data.owner" v-tooltip.top="data.owner.email">
            {{ data.owner.displayName || data.owner.email }}
          </span>
          <span v-else style="color: var(--p-text-muted-color)">{{ t('resources.bridges.systemOwner') }}</span>
        </template>
      </Column>
      <Column :header="t('resources.bridges.status')">
        <template #body="{ data }">
          <Tag :value="statusLabel(data.status)" :severity="data.status === 'active' ? 'success' : 'secondary'" />
        </template>
      </Column>
      <Column :header="t('resources.bridges.actions')">
        <template #body="{ data }">
          <div style="display: flex; gap: 0.25rem">
            <Button v-if="canReassign(data)" icon="pi pi-pencil" severity="secondary" text rounded v-tooltip.top="t('resources.actions.editBridge')" @click="openEdit(data)" />
            <Button v-if="canDelete(data)" icon="pi pi-trash" severity="danger" text rounded @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create dialog -->
    <Dialog v-model:visible="dialogVisible" :header="t('resources.actions.addBridge')" modal style="width: 30rem">
      <!-- Deep-link panel: shown after the Managed Bots session is
           created. Big tappable link is the iOS browser fallback for
           window.open being blocked. -->
      <div v-if="pendingDeepLink" style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-info-circle" style="color: var(--p-blue-500)" />
          <span style="font-weight: 600">{{ t('resources.bridges.openTelegramTitle') }}</span>
        </div>
        <small style="color: var(--p-text-muted-color)">
          {{ t('resources.bridges.openTelegramHelp') }}
        </small>
        <Message severity="warn" :closable="false">
          {{ t('resources.bridges.keepUsername') }}
        </Message>
        <a
          :href="pendingDeepLink"
          target="_blank"
          rel="noopener"
          style="display: flex; align-items: center; justify-content: center; gap: 0.5rem; padding: 0.75rem 1rem; background: var(--p-primary-color); color: var(--p-primary-contrast-color); border-radius: 6px; text-decoration: none; font-weight: 600"
        >
          <i class="pi pi-send" />
          <span>{{ t('resources.actions.openTelegram') }}</span>
        </a>
        <div style="display: flex; gap: 0.5rem; align-items: center">
          <InputText :value="pendingDeepLink" readonly style="flex: 1; font-size: 0.8rem" />
          <Button
            :icon="deepLinkCopied ? 'pi pi-check' : 'pi pi-copy'"
            :label="deepLinkCopied ? t('resources.actions.copied') : t('resources.actions.copy')"
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
              <span>{{ t('resources.bridges.createInTelegram') }}</span>
            </button>
            <button
              type="button"
              class="bot-source-option"
              :class="{ active: createTokenSource === 'paste' }"
              @click="createTokenSource = 'paste'"
            >
              <i class="pi pi-key" />
              <span>{{ t('resources.bridges.pasteToken') }}</span>
            </button>
          </div>
          <small v-if="createTokenSource === 'create_new'" style="color: var(--p-text-muted-color)">
            {{ t('resources.bridges.createInTelegramHelp') }}
          </small>
          <small v-else style="color: var(--p-text-muted-color)">
            {{ t('resources.bridges.pasteTokenHelp') }}
          </small>
        </div>
        <!-- System bridge: admin-only. A system bridge isn't bound to
             an agent; inbound DMs route to the in-airlock sysagent
             (operator chat surface). -->
        <div v-if="auth.can('tenant.bridge.system')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">{{ t('resources.bridges.systemBridge') }}</div>
            <small style="color: var(--p-text-muted-color)">
              {{ t('resources.bridges.systemBridgeHelp') }}
            </small>
          </div>
          <ToggleSwitch v-model="createIsSystem" />
        </div>
        <!-- A manager bridge is never agent-bound (it's the bot that creates
             other bots): hide the agent picker when manager is on. Keep this
             near the top so mobile keyboards don't obscure it. -->
        <div v-if="!createIsSystem && !form.isManager" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeAgentId">{{ t('resources.bridges.app') }}</label>
          <Select
            id="bridgeAgentId"
            v-model="form.agentId"
            :options="agentOptions"
            optionLabel="name"
            optionValue="id"
            :placeholder="t('resources.bridges.selectApp')"
            style="width: 100%"
          >
            <template #option="{ option }">
              <div style="display: flex; flex-direction: column">
                <span><span style="font-weight: 600">{{ option.name }}</span> <span style="color: var(--p-text-muted-color); font-size: 0.85em">{{ option.slug }}</span></span>
                <small style="color: var(--p-text-muted-color)">{{ option.ownerName || t('resources.bridges.unknownOwner') }}{{ option.isOwner ? t('resources.bridges.you') : '' }}</small>
              </div>
            </template>
          </Select>
        </div>
        <div v-if="createTokenSource === 'paste'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeToken">{{ t('resources.bridges.token') }}</label>
          <Password id="bridgeToken" v-model="form.token" :feedback="false" toggleMask />
          <small style="color: var(--p-text-muted-color)">{{ t('resources.bridges.syncedNameHelp') }}</small>
        </div>
        <div v-if="createTokenSource === 'create_new'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="bridgeBotName">{{ t('resources.bridges.botName') }}</label>
          <InputText id="bridgeBotName" v-model="form.name" :placeholder="t('resources.bridges.botNamePlaceholder')" />
          <small style="color: var(--p-text-muted-color)">{{ t('resources.bridges.botNameHelp') }}</small>
        </div>
        <!-- Manager capability: Telegram-only, admin-only. Lets this bot
             create new bots for users via the deep-link flow. The pasted
             token's bot must have can_manage_bots enabled in BotFather. -->
        <div v-if="form.type === 'telegram' && createTokenSource === 'paste' && auth.can('tenant.manager_bot.config')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">{{ t('resources.bridges.managerBot') }}</div>
            <small style="color: var(--p-text-muted-color)">
              {{ t('resources.bridges.managerBotHelp') }}
            </small>
          </div>
          <ToggleSwitch v-model="form.isManager" />
        </div>
      </div>
      <template #footer>
        <template v-if="pendingDeepLink">
          <Button :label="t('resources.actions.done')" @click="dialogVisible = false" />
        </template>
        <template v-else>
          <Button :label="t('resources.actions.cancel')" severity="secondary" text @click="dialogVisible = false" />
          <Button :label="t('resources.actions.create')" @click="onSubmit" />
        </template>
      </template>
    </Dialog>

    <!-- Edit dialog (agent reassignment + per-bridge settings) -->
    <Dialog v-model:visible="editVisible" :header="t('resources.bridges.editNamed', { name: editing?.name ?? t('resources.bridges.bridgeFallback') })" modal style="width: 30rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">

        <!-- System bridge toggle (admin-only). Flipping it switches the
             bridge's surface: on → routes inbound DMs to the in-airlock
             sysagent (no per-agent binding, no public-DM controls); off
             → binds to a specific agent picked below. Backend requires
             admin to cross the boundary in either direction. -->
        <div v-if="auth.can('tenant.bridge.system')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">{{ t('resources.bridges.systemBridge') }}</div>
            <small style="color: var(--p-text-muted-color)">
              {{ t('resources.bridges.systemBridgeHelp') }}
            </small>
          </div>
          <ToggleSwitch v-model="editIsSystem" />
        </div>

        <!-- Manager capability: Telegram-only, admin-only. Lets this bot
             create new bots for users via the deep-link flow. The bot's
             token must have can_manage_bots enabled in BotFather. -->
        <div v-if="editType === 'telegram' && auth.can('tenant.manager_bot.config')" style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div>
            <div style="font-weight: 600">{{ t('resources.bridges.managerBot') }}</div>
            <small style="color: var(--p-text-muted-color)">
              {{ t('resources.bridges.managerBotHelp') }}
            </small>
          </div>
          <ToggleSwitch v-model="editIsManager" />
        </div>

        <!-- A manager bridge is never agent-bound: hide the agent picker when
             manager (or system) is on. -->
        <template v-if="!editIsSystem && !editIsManager">
        <!-- Agent binding -->
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="editAgent">{{ t('resources.bridges.app') }}</label>
          <Select
            id="editAgent"
            v-model="editAgentID"
            :options="agentOptions"
            optionLabel="name"
            optionValue="id"
            :placeholder="t('resources.bridges.selectApp')"
            filter
            :filterFields="['name', 'slug', 'ownerName']"
            autoFilterFocus
            style="width: 100%"
          >
            <template #option="{ option }">
              <div style="display: flex; flex-direction: column">
                <span><span style="font-weight: 600">{{ option.name }}</span> <span style="color: var(--p-text-muted-color); font-size: 0.85em">{{ option.slug }}</span></span>
                <small style="color: var(--p-text-muted-color)">{{ option.ownerName || t('resources.bridges.unknownOwner') }}{{ option.isOwner ? t('resources.bridges.you') : '' }}</small>
              </div>
            </template>
          </Select>
        </div>
        </template>

      </div>
      <template #footer>
        <Button :label="t('resources.actions.cancel')" severity="secondary" text @click="editVisible = false" />
        <Button :label="t('resources.actions.save')" @click="onEdit" />
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
