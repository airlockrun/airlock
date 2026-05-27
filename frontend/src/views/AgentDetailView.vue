<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { useCatalogStore } from '@/stores/catalog'
import { useAgentsStore } from '@/stores/agents'
import { useAgentStatus } from '@/composables/useAgentStatus'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import ConnectionsTab from '@/components/agent/ConnectionsTab.vue'
import ExecEndpointsTab from '@/components/agent/ExecEndpointsTab.vue'
import WebhooksTab from '@/components/agent/WebhooksTab.vue'
import CronsTab from '@/components/agent/CronsTab.vue'
import RoutesTab from '@/components/agent/RoutesTab.vue'
import MCPServersTab from '@/components/agent/MCPServersTab.vue'
import EnvVarsTab from '@/components/agent/EnvVarsTab.vue'
import ToolsTab from '@/components/agent/ToolsTab.vue'
import MembersTab from '@/components/agent/MembersTab.vue'
import SiblingsTab from '@/components/agent/SiblingsTab.vue'
import ModelsTab from '@/components/agent/ModelsTab.vue'
import RunsTab from '@/components/agent/RunsTab.vue'
import BuildsTab from '@/components/agent/BuildsTab.vue'
import SourceTab from '@/components/agent/SourceTab.vue'
import BuildLogPanel from '@/components/agent/BuildLogPanel.vue'
import { useBuildsStore } from '@/stores/builds'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()

const catalog = useCatalogStore()
const buildsStore = useBuildsStore()
const agentsStore = useAgentsStore()

// --- Rename (name + slug) ---
const renameOpen = ref(false)
const renameName = ref('')
const renameSlug = ref('')
const renaming = ref(false)
const slugChanged = computed(
  () => !!agent.value && renameSlug.value.trim() !== agent.value.slug,
)

function openRename() {
  if (!agent.value) return
  renameName.value = agent.value.name
  renameSlug.value = agent.value.slug
  renameOpen.value = true
}

async function saveRename() {
  if (!agent.value) return
  const name = renameName.value.trim()
  const slug = renameSlug.value.trim()
  if (!name) {
    toast.add({ severity: 'warn', summary: 'Name is required', life: 3000 })
    return
  }
  if (slug.length < 2 || slug.length > 63 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    toast.add({
      severity: 'warn',
      summary: 'Invalid slug',
      detail: '2–63 chars: lowercase letters/digits, single dashes between.',
      life: 4000,
    })
    return
  }
  renaming.value = true
  try {
    const updated = await agentsStore.renameAgent(agent.value.id, name, slug)
    agent.value = updated
    renameOpen.value = false
    toast.add({ severity: 'success', summary: 'Agent renamed', life: 2500 })
    // Repaint the address bar to the new slug (same cosmetic mechanism
    // as the router's vanity-URL afterEach; route.params.id stays UUID).
    const parts = window.location.pathname.split('/')
    if (parts[1] === 'agents' && parts[2]) {
      parts[2] = updated.slug
      history.replaceState(
        history.state,
        '',
        parts.join('/') + window.location.search + window.location.hash,
      )
    }
  } catch (e: any) {
    const status = e?.response?.status
    toast.add({
      severity: 'error',
      summary: status === 409 ? 'Slug already taken' : 'Rename failed',
      detail: e?.response?.data?.error,
      life: 5000,
    })
  } finally {
    renaming.value = false
  }
}

const agentId = route.params.id as string
const agent = ref<AgentInfo | null>(null)
const loading = ref(true)
const activeTab = ref(0)
const activeBuildId = ref<string | undefined>(undefined)

// Bumped on every event that should refresh the data tabs (build
// terminal, agent sync). Used as a `:key` on the TabPanels container
// so each tab unmounts/remounts and re-runs its onMounted fetch —
// avoids wiring a WS subscription into every tab component.
const tabsKey = ref(0)

const actionItems = computed(() => {
  const items = []
  // Three-state lifecycle:
  //   Running   = status=active + running → offer Suspend + Stop
  //   Suspended = status=active + !running → offer Start (kicks container)
  //                                          + Stop (parks it)
  //   Stopped   = status=stopped → offer Start (resumes)
  // 'failed' agents still offer Start in case the operator wants to
  // try the existing image; status flips to active on success.
  const status = agent.value?.status ?? ''
  const running = !!agent.value?.running
  if (status === 'active') {
    if (running) {
      items.push({ label: 'Suspend', icon: 'pi pi-pause', command: () => doSuspend() })
      items.push({ label: 'Stop', icon: 'pi pi-stop', command: () => confirmStop() })
    } else {
      items.push({ label: 'Start', icon: 'pi pi-play', command: () => doStart() })
      items.push({ label: 'Stop', icon: 'pi pi-stop', command: () => confirmStop() })
    }
  } else if (status === 'stopped' || status === 'failed') {
    items.push({ label: 'Start', icon: 'pi pi-play', command: () => doStart() })
  }
  items.push({ label: 'Upgrade', icon: 'pi pi-arrow-up', command: () => doUpgrade() })
  items.push({ label: 'Delete', icon: 'pi pi-trash', command: () => confirmDelete() })
  return items
})

const statusTooltip = computed(() => {
  const status = agent.value?.status ?? ''
  const running = !!agent.value?.running
  if (status === 'active' && running) return 'A container is live'
  if (status === 'active' && !running) return 'No container running — starts automatically on next use'
  if (status === 'stopped') return 'Stopped — will not auto-resume; click Start'
  return ''
})

interface SetupStatus {
  connections: number
  mcpServers: number
  envVars: number
  total: number
}
const setupStatus = ref<SetupStatus | null>(null)

async function loadSetupStatus() {
  try {
    const { data } = await api.get(`/api/v1/agents/${agentId}/setup-status`)
    setupStatus.value = data as SetupStatus
  } catch {
    // Non-fatal — header just won't show the badge.
    setupStatus.value = null
  }
}

// Refresh on tab switches — operator just configured something on the
// previous tab, switching tabs is a natural moment to update the
// header badge. No emits needed from tabs.
watch(() => activeTab.value, () => loadSetupStatus())

const setupTooltip = computed(() => {
  const s = setupStatus.value
  if (!s || s.total === 0) return ''
  const parts: string[] = []
  if (s.connections) parts.push(`${s.connections} connection${s.connections === 1 ? '' : 's'}`)
  if (s.mcpServers) parts.push(`${s.mcpServers} MCP server${s.mcpServers === 1 ? '' : 's'}`)
  if (s.envVars) parts.push(`${s.envVars} env var${s.envVars === 1 ? '' : 's'}`)
  return `${parts.join(', ')} need${s.total === 1 ? 's' : ''} setup`
})

let unsubBuild: (() => void) | null = null
let unsubSynced: (() => void) | null = null

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${agentId}`)
    agent.value = fromJson(GetAgentDetailResponseSchema, data).agent ?? null
  } catch {
    toast.add({ severity: 'error', summary: 'Agent not found', life: 3000 })
    router.push('/agents')
    return
  } finally {
    loading.value = false
  }
  catalog.fetchConfiguredModels()
  loadSetupStatus()

  // If a build is currently in progress, grab its id so BuildLogPanel can
  // fetch the persisted log snapshot and dedupe against live WS messages.
  if (agent.value?.status === 'building' || agent.value?.upgradeStatus === 'building') {
    try {
      await buildsStore.fetchBuilds(agentId)
      const inProgress = buildsStore.builds.find((b) => b.status === 'building')
      if (inProgress) activeBuildId.value = inProgress.id
    } catch { /* ignore */ }
  }

  // WS subscriptions are server-driven (agent_members) — no client subscribe call.
  unsubBuild = ws.onMessage('agent.build', (payload: any) => {
    if (payload?.agentId !== agentId) return
    if (payload.buildId) activeBuildId.value = payload.buildId
    if (payload.status === 'started') {
      // New build kicked off while we were watching; buildId already captured
      // above. Mirror the server-side state transition so BuildLogPanel
      // (gated on agent.status/upgradeStatus === 'building') renders
      // immediately instead of waiting for a page refresh.
      if (agent.value) {
        if (agent.value.status === 'draft' || agent.value.status === 'failed') {
          agent.value.status = 'building'
        } else {
          agent.value.upgradeStatus = 'building'
        }
      }
      return
    }
    if (payload.status === 'complete') {
      if (agent.value) {
        agent.value.status = 'active'
        agent.value.upgradeStatus = 'idle'
      }
      toast.add({ severity: 'success', summary: 'Build complete', life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'failed') {
      if (agent.value) agent.value.upgradeStatus = 'failed'
      toast.add({ severity: 'error', summary: payload.error || 'Build failed', life: 10000 })
      tabsKey.value++
    } else if (payload.status === 'cancelled') {
      if (agent.value) {
        agent.value.upgradeStatus = 'failed'
        if (agent.value.status === 'building') agent.value.status = 'failed'
      }
      toast.add({ severity: 'warn', summary: 'Build cancelled', life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'refused') {
      // The request was out of scope — the agent itself is untouched.
      // An initial build still has no image, so it lands on 'failed';
      // an upgrade just returns to idle.
      if (agent.value) {
        agent.value.upgradeStatus = 'idle'
        if (agent.value.status === 'building') agent.value.status = 'failed'
      }
      toast.add({
        severity: 'warn',
        summary: 'Request declined',
        detail: payload.error || "Outside the agent builder's scope",
        life: 8000,
      })
      tabsKey.value++
    }
  })

  // Agent finished a sync (initial boot after build, restart, upgrade) —
  // its declared surface (tools, webhooks, crons, routes, MCP, connections,
  // model slots) just changed. Bump tabsKey so each tab remounts and
  // refetches; saves wiring a WS listener into every tab component.
  unsubSynced = ws.onMessage('agent.synced', (payload: any) => {
    if (payload?.agentId !== agentId) return
    tabsKey.value++
    loadSetupStatus()
    toast.add({
      severity: 'success',
      summary: 'Synced',
      detail: `${agent.value?.slug ?? 'Agent'} synced`,
      life: 2500,
    })
  })
})

onUnmounted(() => {
  unsubBuild?.()
  unsubSynced?.()
})

function confirmStop() {
  confirm.require({
    message:
      `Stop agent "${agent.value?.name}"? It will not auto-resume on the ` +
      'next trigger — you\'ll have to click Start to bring it back.',
    header: 'Confirm Stop',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${agentId}/stop`, {})
        if (agent.value) {
          agent.value.status = 'stopped'
          agent.value.running = false
        }
        toast.add({ severity: 'success', summary: 'Agent stopped', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Stop failed', life: 5000 })
      }
    },
  })
}

async function doSuspend() {
  try {
    await api.post(`/api/v1/agents/${agentId}/suspend`, {})
    if (agent.value) agent.value.running = false
    toast.add({
      severity: 'info',
      summary: 'Agent suspended',
      detail: 'Auto-resumes on the next trigger.',
      life: 3000,
    })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Suspend failed', life: 5000 })
  }
}

async function doStart() {
  try {
    await api.post(`/api/v1/agents/${agentId}/start`, {})
    if (agent.value) agent.value.status = 'active'
    toast.add({ severity: 'success', summary: 'Agent started', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Start failed', life: 5000 })
  }
}

function confirmDelete() {
  confirm.require({
    message: `Delete agent "${agent.value?.name}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${agentId}`)
        toast.add({ severity: 'success', summary: 'Agent deleted', life: 3000 })
        router.push('/agents')
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}

const showUpgradeDialog = ref(false)
const upgradeDescription = ref('')
// Empty description = bare rebuild (re-image current source against the
// latest agentsdk, no code changes). Any text = a codegen upgrade.
const rebuildMode = computed(() => upgradeDescription.value.trim() === '')

function doUpgrade() {
  upgradeDescription.value = ''
  showUpgradeDialog.value = true
}

async function submitUpgrade() {
  showUpgradeDialog.value = false
  try {
    const wasRebuild = rebuildMode.value
    await api.post(`/api/v1/agents/${agentId}/upgrade`, { description: upgradeDescription.value })
    if (agent.value) agent.value.upgradeStatus = 'queued'
    toast.add({ severity: 'info', summary: wasRebuild ? 'Rebuild queued' : 'Upgrade queued', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Upgrade failed', life: 5000 })
  }
}

async function cancelBuild() {
  try {
    await api.post(`/api/v1/agents/${agentId}/builds/cancel`)
    toast.add({ severity: 'info', summary: 'Build cancelled', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Cancel failed', life: 5000 })
  }
}

function goToChat() {
  router.push(`/agents/${agentId}/chat`)
}

</script>

<template>
  <div v-if="loading" style="display: flex; flex-direction: column; gap: 1rem">
    <Skeleton width="40%" height="2rem" />
    <Skeleton width="20%" height="1.5rem" />
    <Skeleton width="100%" height="20rem" />
  </div>

  <div v-else-if="agent">
    <!-- Breadcrumb -->
    <Breadcrumb :model="[{ label: 'Agents', to: '/agents' }, { label: agent.name }]" style="margin-bottom: 1rem">
      <template #item="{ item }">
        <router-link v-if="item.to" :to="item.to" style="text-decoration: none; color: var(--p-primary-color)">
          {{ item.label }}
        </router-link>
        <span v-else>{{ item.label }}</span>
      </template>
    </Breadcrumb>

    <!-- Header -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.75rem">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <h1 style="margin: 0; font-size: 1.5rem">
            <span v-if="agent.emoji" style="margin-right: 0.4rem">{{ agent.emoji }}</span>{{ agent.name }}
          </h1>
          <span style="color: var(--p-text-muted-color)">{{ agent.slug }}</span>
          <Button
            icon="pi pi-pencil"
            text
            rounded
            size="small"
            severity="secondary"
            aria-label="Rename agent"
            v-tooltip.bottom="'Rename'"
            @click="openRename"
          />
          <!-- Single badge that folds container state into the lifecycle:
               Running/Suspended/Stopped/Building/Error/Draft. See
               useAgentStatus for the (status, running) → label map. -->
          <Tag
            :value="useAgentStatus(agent.status, agent.running).label"
            :severity="useAgentStatus(agent.status, agent.running).severity"
            v-tooltip.bottom="statusTooltip"
          />
          <Tag
            v-if="setupStatus && setupStatus.total > 0"
            :value="`Needs setup (${setupStatus.total})`"
            severity="warn"
            v-tooltip.bottom="setupTooltip"
          />
        </div>
        <p v-if="agent.description" style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">{{ agent.description }}</p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button label="Chat" icon="pi pi-comments" @click="goToChat" />
        <SplitButton label="Actions" :model="actionItems" severity="secondary" />
      </div>
    </div>

    <!-- Build/upgrade log panel -->
    <BuildLogPanel
      :agent-id="agentId"
      :build-id="activeBuildId"
      :active="agent.status === 'building' || agent.upgradeStatus === 'building'"
      style="margin-bottom: 1rem"
      @cancel="cancelBuild"
    />

    <!-- Error message -->
    <Message v-if="agent.errorMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 20rem; overflow-y: auto">{{ agent.errorMessage }}</pre>
    </Message>

    <!-- Tabs -->
    <Tabs v-model:value="activeTab">
      <TabList>
        <Tab :value="0">Connections</Tab>
        <Tab :value="1">Exec Endpoints</Tab>
        <Tab :value="2">MCP Servers</Tab>
        <Tab :value="3">Environment</Tab>
        <Tab :value="4">Tools</Tab>
        <Tab :value="5">Models</Tab>
        <Tab :value="6">Routes</Tab>
        <Tab :value="7">Webhooks</Tab>
        <Tab :value="8">Crons</Tab>
        <Tab :value="9">Members</Tab>
        <Tab :value="10">Siblings</Tab>
        <Tab :value="11">Runs</Tab>
        <Tab :value="12">Builds</Tab>
        <Tab :value="13">Source</Tab>
      </TabList>
      <TabPanels :key="tabsKey">
        <TabPanel :value="0"><ConnectionsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="1"><ExecEndpointsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="2"><MCPServersTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="3"><EnvVarsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="4"><ToolsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="5"><ModelsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="6"><RoutesTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="7"><WebhooksTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="8"><CronsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="9"><MembersTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="10"><SiblingsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="11"><RunsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="12"><BuildsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="13"><SourceTab :agent-id="agentId" /></TabPanel>
      </TabPanels>
    </Tabs>

    <!-- Upgrade dialog -->
    <Dialog v-model:visible="showUpgradeDialog" :header="rebuildMode ? 'Rebuild Agent' : 'Upgrade Agent'" modal style="width: 30rem">
      <p style="margin-top: 0">Describe what to change or fix:</p>
      <Textarea v-model="upgradeDescription" rows="4" style="width: 100%" placeholder="e.g. Add a /history page that shows past voting rounds" autofocus />
      <small style="display: block; margin-top: 0.5rem; color: var(--p-text-muted-color)">
        Leave empty to <strong>rebuild</strong> against the latest agentsdk — no code changes. If the SDK API changed and the code no longer compiles, the rebuild fails; add a description so the builder can adapt it.
      </small>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showUpgradeDialog = false" />
        <Button :label="rebuildMode ? 'Rebuild' : 'Upgrade'" :icon="rebuildMode ? 'pi pi-refresh' : 'pi pi-arrow-up'" @click="submitUpgrade" />
      </template>
    </Dialog>

    <Dialog v-model:visible="renameOpen" header="Rename agent" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Name</label>
          <InputText v-model="renameName" style="width: 100%" autofocus />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Slug</label>
          <InputText v-model="renameSlug" style="width: 100%" />
          <small style="display: block; margin-top: 0.35rem; color: var(--p-text-muted-color)">
            Lowercase letters, digits and single dashes (2–63 chars).
          </small>
        </div>
        <Message v-if="slugChanged" severity="warn" :closable="false">
          Changing the slug re-points sibling <code>agent_&lt;slug&gt;</code> bindings and
          breaks any externally-configured MCP URL using the old slug. In-app
          links keep working.
        </Message>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text :disabled="renaming" @click="renameOpen = false" />
        <Button label="Save" icon="pi pi-check" :loading="renaming" @click="saveRename" />
      </template>
    </Dialog>
  </div>
</template>
