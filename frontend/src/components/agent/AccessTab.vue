<script setup lang="ts">
// AccessTab: the agent's protocol-surface toggles, orthogonal to the grant
// ladder. WHO may make an authed MCP/A2A call is decided by membership
// (Members tab — grant the "All users" group to open the agent to everyone);
// these three toggles govern the MCP master switch and the anonymous /
// public-route surfaces.
import { ref, onMounted } from 'vue'
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
  // Anonymous MCP is meaningless with the endpoint off — the server
  // normalizes it, mirror that here so the UI shows the rule.
  if (!settings.value.mcpEnabled) {
    settings.value.allowPublicMcp = false
  }
  try {
    await api.put(`/api/v1/agents/${props.agentId}/a2a-settings`, { settings: settings.value })
    toast.add({ severity: 'success', summary: 'Access settings saved', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'save failed', life: 5000 })
  }
}

onMounted(loadSettings)
</script>

<template>
  <div>
    <h3 style="margin-top: 0">Protocol access</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      These govern the anonymous and protocol surfaces only. To control which authenticated
      users or agents may call this agent, use <strong>Members</strong> — grant the
      <em>All users</em> group to open it to every registered user.
    </p>
    <div style="display: flex; flex-direction: column; gap: 0.75rem">
      <label style="display: flex; align-items: center; gap: 0.75rem">
        <ToggleSwitch v-model="settings.mcpEnabled" :disabled="loading" />
        <span>
          Allow MCP access to this agent — serve the <code>/api/agent/&lt;uuid&gt;/mcp</code>
          endpoint to grant-authorized callers (members &amp; sibling agents).
        </span>
      </label>
      <label style="display: flex; align-items: center; gap: 0.75rem">
        <ToggleSwitch v-model="settings.allowPublicMcp" :disabled="loading || !settings.mcpEnabled" />
        <span>
          Allow <strong>public</strong> (anonymous, no-JWT) MCP access to this agent's
          public-tier tools. Requires MCP access on.
        </span>
      </label>
      <label style="display: flex; align-items: center; gap: 0.75rem">
        <ToggleSwitch v-model="settings.allowPublicRoutes" :disabled="loading" />
        <span>
          Allow <strong>public</strong> access to this agent's public web routes
          (its <code>AccessPublic</code> subdomain routes).
        </span>
      </label>
      <div>
        <Button label="Save access settings" size="small" :disabled="loading" @click="saveSettings" />
      </div>
    </div>
  </div>
</template>
