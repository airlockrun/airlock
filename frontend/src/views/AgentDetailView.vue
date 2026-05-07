<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { useCatalogStore } from '@/stores/catalog'
import { useAgentStatus } from '@/composables/useAgentStatus'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import ConnectionsTab from '@/components/agent/ConnectionsTab.vue'
import WebhooksTab from '@/components/agent/WebhooksTab.vue'
import CronsTab from '@/components/agent/CronsTab.vue'
import RoutesTab from '@/components/agent/RoutesTab.vue'
import MCPServersTab from '@/components/agent/MCPServersTab.vue'
import EnvVarsTab from '@/components/agent/EnvVarsTab.vue'
import ToolsTab from '@/components/agent/ToolsTab.vue'
import MembersTab from '@/components/agent/MembersTab.vue'
import ModelsTab from '@/components/agent/ModelsTab.vue'
import RunsTab from '@/components/agent/RunsTab.vue'
import BuildsTab from '@/components/agent/BuildsTab.vue'
import BuildLogPanel from '@/components/agent/BuildLogPanel.vue'
import { useBuildsStore } from '@/stores/builds'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()

const catalog = useCatalogStore()
const buildsStore = useBuildsStore()

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
  if (agent.value?.status === 'active') {
    items.push({ label: 'Stop', icon: 'pi pi-stop', command: () => confirmStop() })
  } else if (agent.value?.status === 'stopped' || agent.value?.status === 'failed') {
    items.push({ label: 'Start', icon: 'pi pi-play', command: () => doStart() })
  }
  items.push({ label: 'Upgrade', icon: 'pi pi-arrow-up', command: () => doUpgrade() })
  items.push({ label: 'Delete', icon: 'pi pi-trash', command: () => confirmDelete() })
  return items
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
      // New build kicked off while we were watching; buildId already captured above.
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
  })
})

onUnmounted(() => {
  unsubBuild?.()
  unsubSynced?.()
})

function confirmStop() {
  confirm.require({
    message: `Stop agent "${agent.value?.name}"?`,
    header: 'Confirm Stop',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${agentId}/stop`, {})
        if (agent.value) agent.value.status = 'stopped'
        toast.add({ severity: 'success', summary: 'Agent stopped', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Stop failed', life: 5000 })
      }
    },
  })
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

function doUpgrade() {
  upgradeDescription.value = ''
  showUpgradeDialog.value = true
}

async function submitUpgrade() {
  showUpgradeDialog.value = false
  try {
    await api.post(`/api/v1/agents/${agentId}/upgrade`, { description: upgradeDescription.value })
    if (agent.value) agent.value.upgradeStatus = 'queued'
    toast.add({ severity: 'info', summary: 'Upgrade queued', life: 3000 })
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
          <h1 style="margin: 0; font-size: 1.5rem">{{ agent.name }}</h1>
          <span style="color: var(--p-text-muted-color)">{{ agent.slug }}</span>
          <Tag :value="useAgentStatus(agent.status).label" :severity="useAgentStatus(agent.status).severity" />
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
        <Tab :value="1">MCP Servers</Tab>
        <Tab :value="2">Environment</Tab>
        <Tab :value="3">Tools</Tab>
        <Tab :value="4">Models</Tab>
        <Tab :value="5">Routes</Tab>
        <Tab :value="6">Webhooks</Tab>
        <Tab :value="7">Crons</Tab>
        <Tab :value="8">Members</Tab>
        <Tab :value="9">Runs</Tab>
        <Tab :value="10">Builds</Tab>
      </TabList>
      <TabPanels :key="tabsKey">
        <TabPanel :value="0"><ConnectionsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="1"><MCPServersTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="2"><EnvVarsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="3"><ToolsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="4"><ModelsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="5"><RoutesTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="6"><WebhooksTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="7"><CronsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="8"><MembersTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="9"><RunsTab :agent-id="agentId" /></TabPanel>
        <TabPanel :value="10"><BuildsTab :agent-id="agentId" /></TabPanel>
      </TabPanels>
    </Tabs>

    <!-- Upgrade dialog -->
    <Dialog v-model:visible="showUpgradeDialog" header="Upgrade Agent" modal style="width: 30rem">
      <p style="margin-top: 0">Describe what to change or fix:</p>
      <Textarea v-model="upgradeDescription" rows="4" style="width: 100%" placeholder="e.g. Add a /history page that shows past voting rounds" autofocus />
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showUpgradeDialog = false" />
        <Button label="Upgrade" icon="pi pi-arrow-up" @click="submitUpgrade" />
      </template>
    </Dialog>
  </div>
</template>
