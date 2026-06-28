<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'

interface ExecEndpoint {
  id: string
  slug: string
  description: string
  llmHint: string
  access: string
  transport: string
  host: string
  port: number
  sshUser: string
  publicKeyOpenssh: string
  publicKeyComment: string
  hostKeyFingerprint: string
  hostKeyPinnedAt: string
  lastUsedAt: string
}

interface TestResult {
  ok: boolean
  exitCode: number
  durationMs: number
  stdout?: string
  stderr?: string
  error?: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()

const toast = useToast()
const endpoints = ref<ExecEndpoint[]>([])
watch(endpoints, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)

// Per-row config form state. Keyed by slug so multiple rows can be
// configured concurrently without crosstalk.
const formHost = ref<Record<string, string>>({})
const formPort = ref<Record<string, number>>({})
const formUser = ref<Record<string, string>>({})
const saving = ref<Record<string, boolean>>({})
const testing = ref<Record<string, boolean>>({})
const lastTest = ref<Record<string, TestResult | null>>({})

// Per-endpoint collapse. Endpoints start collapsed and show a header
// preview (slug + description + status + user@host:port summary) — the
// full configuration form is vertically heavy and most agents have one or
// two endpoints, so the section's overview reads better as a compact list.
const collapsed = ref<Record<string, boolean>>({})
function toggleCollapse(slug: string) {
  collapsed.value[slug] = !(collapsed.value[slug] ?? true)
}
function isCollapsed(slug: string): boolean {
  return collapsed.value[slug] ?? true
}
function endpointPreview(ep: ExecEndpoint): string {
  const user = ep.sshUser || formUser.value[ep.slug] || ''
  const host = ep.host || formHost.value[ep.slug] || ''
  const port = ep.port || formPort.value[ep.slug] || 22
  if (!host) return 'not configured'
  return `${user ? user + '@' : ''}${host}${port && port !== 22 ? ':' + port : ''}`
}

async function refresh() {
  const { data } = await api.get(`/api/v1/agents/${props.agentId}/exec-endpoints`)
  endpoints.value = (data?.endpoints || []) as ExecEndpoint[]
  // Seed per-row form values from current row state.
  for (const ep of endpoints.value) {
    if (!(ep.slug in formHost.value)) {
      formHost.value[ep.slug] = ep.host
      formPort.value[ep.slug] = ep.port || 22
      formUser.value[ep.slug] = ep.sshUser
    }
  }
}

async function save(ep: ExecEndpoint) {
  saving.value[ep.slug] = true
  try {
    await api.put(`/api/v1/agents/${props.agentId}/exec-endpoints/${ep.slug}`, {
      host: formHost.value[ep.slug],
      port: formPort.value[ep.slug],
      sshUser: formUser.value[ep.slug],
    })
    toast.add({ severity: 'success', summary: 'Saved', life: 2000 })
    await refresh()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Save failed', life: 5000 })
  } finally {
    saving.value[ep.slug] = false
  }
}

async function rotate(ep: ExecEndpoint) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${ep.slug}/rotate-keypair`)
    toast.add({ severity: 'success', summary: 'New keypair generated — copy the public key and update authorized_keys on the target', life: 5000 })
    await refresh()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Rotate failed', life: 5000 })
  }
}

async function unpin(ep: ExecEndpoint) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${ep.slug}/unpin-host-key`)
    toast.add({ severity: 'success', summary: 'Host key cleared — next connect will re-TOFU', life: 3000 })
    await refresh()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Unpin failed', life: 5000 })
  }
}

async function testConnection(ep: ExecEndpoint) {
  testing.value[ep.slug] = true
  lastTest.value[ep.slug] = null
  try {
    const { data } = await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${ep.slug}/test`)
    const result = (data?.result ?? {}) as TestResult
    lastTest.value[ep.slug] = result
    if (result.ok) {
      toast.add({ severity: 'success', summary: `Connection OK (${result.durationMs}ms)`, life: 3000 })
    } else if (result.error) {
      toast.add({ severity: 'error', summary: result.error, life: 6000 })
    } else {
      toast.add({ severity: 'warn', summary: `Exit ${result.exitCode}`, life: 4000 })
    }
    await refresh() // host-key may have been pinned on first success
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Test failed', life: 5000 })
  } finally {
    testing.value[ep.slug] = false
  }
}

async function copyPublicKey(ep: ExecEndpoint) {
  try {
    await navigator.clipboard.writeText(ep.publicKeyOpenssh)
    toast.add({ severity: 'success', summary: 'Public key copied', life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: 'Copy failed — select the key text and copy manually', life: 4000 })
  }
}

function statusFor(ep: ExecEndpoint): { label: string; severity: string } {
  if (!ep.transport || !ep.host) return { label: 'Not configured', severity: 'warn' }
  if (!ep.publicKeyOpenssh) return { label: 'No keypair', severity: 'warn' }
  if (!ep.hostKeyFingerprint) return { label: 'Awaiting first connect (TOFU)', severity: 'info' }
  return { label: 'Configured', severity: 'success' }
}

onMounted(async () => {
  try {
    await refresh()
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div v-if="!loading && endpoints.length === 0" style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
      No exec endpoints registered. Add a <code>RegisterExecEndpoint</code> call to your agent's <code>main()</code> to declare one.
    </div>

    <div v-for="ep in endpoints" :key="ep.slug" class="exec-endpoint-card">
      <div class="exec-header" @click="toggleCollapse(ep.slug)">
        <i
          class="pi exec-chevron"
          :class="isCollapsed(ep.slug) ? 'pi-chevron-right' : 'pi-chevron-down'"
        />
        <div style="flex: 1; min-width: 0">
          <h3 style="margin: 0">{{ ep.slug }}</h3>
          <p style="margin: 0.25rem 0; color: var(--p-text-muted-color); font-size: 0.85rem">{{ ep.description }}</p>
          <p
            v-if="isCollapsed(ep.slug)"
            style="margin: 0.25rem 0 0; font-size: 0.8rem; color: var(--p-text-muted-color)"
          >
            <code>{{ endpointPreview(ep) }}</code>
          </p>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <Tag :value="statusFor(ep).label" :severity="statusFor(ep).severity" />
          <span style="font-size: 0.75rem; color: var(--p-text-muted-color)">access: {{ ep.access }}</span>
        </div>
      </div>

      <div v-show="!isCollapsed(ep.slug)" class="exec-form">
        <div class="form-row">
          <label>Transport</label>
          <span style="font-size: 0.85rem">SSH (only supported transport)</span>
        </div>
        <div class="form-row">
          <label>Host</label>
          <InputText v-model="formHost[ep.slug]" placeholder="e.g. vps.example.com or 10.0.0.5" style="flex: 1" />
        </div>
        <div class="form-row">
          <label>Port</label>
          <InputNumber v-model="formPort[ep.slug]" :min="1" :max="65535" :useGrouping="false" style="width: 8rem" />
        </div>
        <div class="form-row">
          <label>User</label>
          <InputText v-model="formUser[ep.slug]" placeholder="root" style="flex: 1" />
        </div>
        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem">
          <Button label="Save" size="small" :loading="saving[ep.slug]" @click="save(ep)" />
          <Button v-if="ep.publicKeyOpenssh" label="Test connection" size="small" outlined :loading="testing[ep.slug]" @click="testConnection(ep)" />
        </div>
      </div>

      <div v-if="ep.publicKeyOpenssh" v-show="!isCollapsed(ep.slug)" class="exec-section">
        <h4 style="margin: 0 0 0.5rem 0">Public key (paste into target's <code>~/.ssh/authorized_keys</code>)</h4>
        <p style="margin: 0 0 0.5rem 0; font-size: 0.75rem; color: var(--p-text-muted-color)">
          Comment: <code>{{ ep.publicKeyComment }}</code> — useful for grepping
          old keys out of authorized_keys after a rotation.
        </p>
        <div class="pubkey-box">
          <code>{{ ep.publicKeyOpenssh }}</code>
        </div>
        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem">
          <Button label="Copy" icon="pi pi-copy" size="small" outlined @click="copyPublicKey(ep)" />
          <Button label="Rotate keypair" icon="pi pi-refresh" size="small" severity="secondary" outlined @click="rotate(ep)" />
        </div>
      </div>

      <div v-if="ep.hostKeyFingerprint" v-show="!isCollapsed(ep.slug)" class="exec-section">
        <h4 style="margin: 0 0 0.5rem 0">Host key</h4>
        <p style="margin: 0; font-size: 0.85rem">
          Fingerprint: <code>{{ ep.hostKeyFingerprint }}</code>
          <span v-if="ep.hostKeyPinnedAt" style="color: var(--p-text-muted-color); margin-left: 0.5rem">
            (pinned {{ ep.hostKeyPinnedAt }})
          </span>
        </p>
        <div style="margin-top: 0.5rem">
          <Button label="Unpin & re-TOFU" icon="pi pi-unlock" size="small" severity="secondary" outlined @click="unpin(ep)" />
        </div>
      </div>

      <div v-if="lastTest[ep.slug]" v-show="!isCollapsed(ep.slug)" class="exec-section">
        <h4 style="margin: 0 0 0.5rem 0">Last test result</h4>
        <pre class="code-chip" style="margin: 0; padding: 0.75rem; font-size: 0.8rem; white-space: pre-wrap">{{ JSON.stringify(lastTest[ep.slug], null, 2) }}</pre>
      </div>
    </div>

    <div v-if="loading" style="padding: 1rem">
      <Skeleton height="6rem" />
    </div>
  </div>
</template>

<style scoped>
.exec-endpoint-card {
  border: 1px solid var(--p-surface-200);
  border-radius: 0.5rem;
  padding: 1.25rem;
  margin-bottom: 1rem;
  background: var(--p-surface-50);
}
:root.dark .exec-endpoint-card {
  background: var(--p-surface-900);
  border-color: var(--p-surface-700);
}
.exec-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 0.75rem;
  margin-bottom: 1rem;
  cursor: pointer;
  user-select: none;
}
.exec-chevron {
  font-size: 0.75rem;
  color: var(--p-text-muted-color);
  margin-top: 0.35rem;
}
.exec-form {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.form-row {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.form-row label {
  width: 6rem;
  font-size: 0.85rem;
  color: var(--p-text-muted-color);
}
.exec-section {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px dashed var(--p-surface-200);
}
:root.dark .exec-section {
  border-top-color: var(--p-surface-700);
}
.pubkey-box {
  background: var(--p-surface-100);
  border-radius: 0.3rem;
  padding: 0.75rem;
  font-size: 0.78rem;
  word-break: break-all;
}
:root.dark .pubkey-box {
  background: var(--p-surface-800);
}
</style>
