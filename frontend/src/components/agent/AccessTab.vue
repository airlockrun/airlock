<script setup lang="ts">
// AccessTab: how this agent can be reached from outside. Who can use it as a
// member is set under Members; these switches control external connections
// (MCP) and anonymous access.
import { ref, computed, onMounted } from 'vue'
import api from '@/api/client'
import { useToast } from 'primevue/usetoast'

interface A2ASettings {
  mcpEnabled: boolean
  allowPublicMcp: boolean
  allowPublicRoutes: boolean
}

const props = defineProps<{ agentId: string }>()
const toast = useToast()

const loading = ref(true)
const settings = ref<A2ASettings>({ mcpEnabled: true, allowPublicMcp: false, allowPublicRoutes: true })

// The MCP endpoint other apps connect to. Same origin as the web app.
const mcpUrl = computed(() => `${window.location.origin}/api/agent/${props.agentId}/mcp`)

async function loadSettings() {
  loading.value = true
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/a2a-settings`)
    settings.value = {
      mcpEnabled: !!data?.settings?.mcpEnabled,
      allowPublicMcp: !!data?.settings?.allowPublicMcp,
      allowPublicRoutes: !!data?.settings?.allowPublicRoutes,
    }
  } finally {
    loading.value = false
  }
}

async function saveSettings() {
  // Anonymous access is meaningless with MCP off — the server normalizes it;
  // mirror that here so the UI matches.
  if (!settings.value.mcpEnabled) {
    settings.value.allowPublicMcp = false
  }
  try {
    await api.put(`/api/v1/agents/${props.agentId}/a2a-settings`, { settings: settings.value })
    toast.add({ severity: 'success', summary: 'Saved', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Save failed', life: 5000 })
  }
}

async function copyMcpUrl() {
  try {
    await navigator.clipboard.writeText(mcpUrl.value)
    toast.add({ severity: 'success', summary: 'URL copied', life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: 'Copy failed — select the URL and copy manually', life: 4000 })
  }
}

onMounted(loadSettings)
</script>

<template>
  <div>
    <h3 style="margin-top: 0">Access</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      How this agent can be reached from outside. Who can use it is set under <strong>Members</strong>.
    </p>

    <div style="display: flex; flex-direction: column; gap: 1.25rem">
      <div>
        <label style="display: flex; align-items: center; gap: 0.75rem">
          <ToggleSwitch v-model="settings.mcpEnabled" :disabled="loading" />
          <span>Let other apps connect to this agent (MCP)</span>
        </label>
        <small style="display: block; color: var(--p-text-muted-color); margin: 0.25rem 0 0 3.5rem">
          For tools like Claude Desktop and other agents.
        </small>
        <div v-if="settings.mcpEnabled" style="margin: 0.5rem 0 0 3.5rem; font-size: 0.85rem">
          <span style="color: var(--p-text-muted-color)">Connection URL: </span>
          <span class="copy-uri" role="button" tabindex="0" v-tooltip.bottom="'Click to copy'"
                @click="copyMcpUrl" @keydown.enter="copyMcpUrl">
            <code style="word-break: break-all">{{ mcpUrl }}</code>
            <i class="pi pi-copy" style="font-size: 0.75rem; opacity: 0.6" />
          </span>
        </div>
      </div>

      <div>
        <label style="display: flex; align-items: center; gap: 0.75rem">
          <ToggleSwitch v-model="settings.allowPublicMcp" :disabled="loading || !settings.mcpEnabled" />
          <span>Allow connecting without signing in</span>
        </label>
        <small style="display: block; color: var(--p-text-muted-color); margin: 0.25rem 0 0 3.5rem">
          Anyone can connect; only public tools are exposed.
        </small>
      </div>

      <div>
        <label style="display: flex; align-items: center; gap: 0.75rem">
          <ToggleSwitch v-model="settings.allowPublicRoutes" :disabled="loading" />
          <span>Allow public web pages without signing in</span>
        </label>
        <small style="display: block; color: var(--p-text-muted-color); margin: 0.25rem 0 0 3.5rem">
          Lets anyone open this agent's pages marked public.
        </small>
      </div>

      <div>
        <Button label="Save" size="small" :disabled="loading" @click="saveSettings" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.copy-uri {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  cursor: pointer;
  border-radius: 0.3rem;
  padding: 0.05rem 0.25rem;
}
.copy-uri:hover {
  background: var(--p-surface-100);
}
:root.dark .copy-uri:hover {
  background: var(--p-surface-800);
}
</style>
