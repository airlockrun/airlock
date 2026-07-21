<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import type { ExecEndpointInfo, ExecEndpointTestResult } from '@/gen/airlock/v1/types_pb'
import type { NeedInfo } from '@/gen/airlock/v1/api_pb'
import { ListExecEndpointsResponseSchema, TestExecEndpointResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useAgentResources } from '@/composables/useAgentResources'
import { hasCapability, resourceLabel } from '@/utils/resources'
import ResourceBindingDialog from './ResourceBindingDialog.vue'
import { serializeExecEndpointRequest } from '@/utils/resourceRequests'

const props = withDefaults(defineProps<{ agentId: string; yourAccess?: string }>(), { yourAccess: '' })
const emit = defineEmits<{ populated: [count: number]; mutated: [] }>()
const toast = useToast()
const confirm = useConfirm()
const resources = useAgentResources(props.agentId)
const endpoints = ref<ExecEndpointInfo[]>([])
const loading = ref(true)
const loadError = ref('')
const bindingOpen = ref(false)
const selectedNeed = ref<NeedInfo | null>(null)
const formHost = ref<Record<string, string>>({})
const formPort = ref<Record<string, number>>({})
const formUser = ref<Record<string, string>>({})
const saving = ref<Record<string, boolean>>({})
const testing = ref<Record<string, boolean>>({})
const lastTest = ref<Record<string, ExecEndpointTestResult | null>>({})
const collapsed = ref<Record<string, boolean>>({})

const needs = computed(() => resources.needs.value.filter((need) => need.type === 'exec_endpoint'))
watch(needs, (rows) => emit('populated', rows.length), { immediate: true })
const endpointsBySlug = computed(() => new Map(endpoints.value.map((endpoint) => [endpoint.slug, endpoint])))
const canAdmin = computed(() => props.yourAccess === 'admin')

function endpoint(need: NeedInfo): ExecEndpointInfo | undefined { return endpointsBySlug.value.get(need.slug) }
function canManage(need: NeedInfo): boolean {
  const resource = resources.resourceFor(need)
  return !!resource && hasCapability(resource.capabilities, 'manage')
}
function displayName(need: NeedInfo): string {
  const resource = resources.resourceFor(need)
  return resource ? resourceLabel(resource) : need.description || need.slug
}
function isCollapsed(slug: string): boolean { return collapsed.value[slug] ?? true }
function toggle(slug: string) { collapsed.value[slug] = !isCollapsed(slug) }
function preview(need: NeedInfo): string {
  const ep = endpoint(need)
  const host = ep?.host || formHost.value[need.slug] || ''
  const user = ep?.sshUser || formUser.value[need.slug] || ''
  const port = ep?.port || formPort.value[need.slug] || 22
  return host ? `${user ? `${user}@` : ''}${host}${port !== 22 ? `:${port}` : ''}` : 'not configured'
}
function status(need: NeedInfo): { label: string; severity: string } {
  if (!need.bound) return { label: 'Unbound', severity: 'warn' }
  const ep = endpoint(need)
  if (!ep?.host) return { label: 'Needs setup', severity: 'warn' }
  if (!ep.publicKeyOpenssh) return { label: 'No keypair', severity: 'warn' }
  if (!ep.hostKeyFingerprint) return { label: 'Awaiting first connect', severity: 'info' }
  return { label: 'Ready', severity: 'success' }
}
function impactWarning(need: NeedInfo): string {
  const resource = resources.resourceFor(need)
  return resource && resource.agentCount > 1
    ? `Host, key, and endpoint changes affect all ${resource.agentCount} apps using this shared resource.`
    : ''
}

async function refresh() {
  const [response] = await Promise.all([
    api.get(`/api/v1/agents/${props.agentId}/exec-endpoints`),
    resources.refresh(),
  ])
  endpoints.value = fromJson(ListExecEndpointsResponseSchema, response.data).endpoints
  for (const ep of endpoints.value) {
    formHost.value[ep.slug] = ep.host
    formPort.value[ep.slug] = ep.port || 22
    formUser.value[ep.slug] = ep.sshUser
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    await refresh()
  } catch (error: any) {
    loadError.value = error.response?.data?.error || error.message || 'Failed to load exec endpoints'
    emit('populated', 1)
  } finally {
    loading.value = false
  }
}

function openSetup(need: NeedInfo) { selectedNeed.value = need; bindingOpen.value = true }

async function save(need: NeedInfo) {
  saving.value[need.slug] = true
  try {
    await api.put(`/api/v1/agents/${props.agentId}/exec-endpoints/${encodeURIComponent(need.slug)}`, serializeExecEndpointRequest({
      host: formHost.value[need.slug],
      port: formPort.value[need.slug],
      sshUser: formUser.value[need.slug],
      displayName: '',
      createNew: false,
    }))
    await refresh()
    emit('mutated')
    toast.add({ severity: 'success', summary: 'Endpoint saved', life: 2500 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || 'Save failed', life: 5000 })
  } finally {
    saving.value[need.slug] = false
  }
}

async function rotate(need: NeedInfo) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${encodeURIComponent(need.slug)}/rotate-keypair`)
    await refresh()
    emit('mutated')
    toast.add({ severity: 'success', summary: 'New keypair generated', detail: 'Update authorized_keys on every target using this resource.', life: 6000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || 'Rotate failed', life: 5000 })
  }
}

async function unpin(need: NeedInfo) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${encodeURIComponent(need.slug)}/unpin-host-key`)
    await refresh()
    emit('mutated')
    toast.add({ severity: 'success', summary: 'Host key cleared', detail: 'The next connection will pin the presented key.', life: 4000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || 'Unpin failed', life: 5000 })
  }
}

async function testConnection(need: NeedInfo) {
  testing.value[need.slug] = true
  lastTest.value[need.slug] = null
  try {
    const { data } = await api.post(`/api/v1/agents/${props.agentId}/exec-endpoints/${encodeURIComponent(need.slug)}/test`)
    const result = fromJson(TestExecEndpointResponseSchema, data).result
    if (!result) throw new Error('No test result returned')
    lastTest.value[need.slug] = result
    if (result.ok) toast.add({ severity: 'success', summary: `Connection OK (${result.durationMs.toString()}ms)`, life: 3000 })
    else toast.add({ severity: 'error', summary: result.error || `Exit ${result.exitCode}`, life: 6000 })
    await refresh()
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || 'Test failed', life: 5000 })
  } finally {
    testing.value[need.slug] = false
  }
}

async function copyKey(need: NeedInfo) {
  const key = endpoint(need)?.publicKeyOpenssh
  if (!key) return
  try {
    await navigator.clipboard.writeText(key)
    toast.add({ severity: 'success', summary: 'Public key copied', life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: 'Copy failed - select and copy the key manually', life: 4000 })
  }
}

function disconnect(need: NeedInfo) {
  confirm.require({
    header: 'Disconnect from this app?',
    message: `${displayName(need)} and its SSH configuration stay available to other apps.`,
    acceptLabel: 'Disconnect from this app',
    rejectLabel: 'Cancel',
    accept: async () => {
      try {
        await resources.unbind(need)
        await refresh()
        emit('mutated')
        toast.add({ severity: 'success', summary: 'Exec resource disconnected from this app', life: 3000 })
      } catch (error: any) {
        toast.add({ severity: 'error', summary: error.response?.data?.error || 'Disconnect failed', life: 5000 })
      }
    },
  })
}

async function changed() { await refresh(); emit('mutated') }
async function configureBound(need: NeedInfo) {
  selectedNeed.value = need
  try {
    await refresh()
    collapsed.value[need.slug] = false
  } catch (error: any) {
    toast.add({ severity: 'error', summary: error.response?.data?.error || error.message || 'Failed to load endpoint setup', life: 6000 })
  }
}

onMounted(load)
</script>

<template>
  <Message v-if="loadError" severity="error" :closable="false">
    <div class="load-error"><span>{{ loadError }}</span><Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <div v-else-if="!loading && needs.length === 0" class="empty">
    No exec endpoints registered. Add a <code>RegisterExecEndpoint</code> call to declare one.
  </div>
  <div v-for="need in loadError ? [] : needs" :key="need.slug" class="exec-card">
    <div class="exec-header" :class="{ clickable: need.bound }" @click="need.bound && toggle(need.slug)">
      <i v-if="need.bound" class="pi" :class="isCollapsed(need.slug) ? 'pi-chevron-right' : 'pi-chevron-down'" />
      <div class="header-main">
        <h3>{{ displayName(need) }}</h3>
        <div class="secondary">App handle: <code>{{ need.slug }}</code><span v-if="need.description"> · {{ need.description }}</span></div>
        <code v-if="need.bound && isCollapsed(need.slug)" class="preview">{{ preview(need) }}</code>
      </div>
      <Tag :value="status(need).label" :severity="status(need).severity" />
    </div>

    <div v-if="canAdmin" class="resource-actions">
      <Button v-if="!need.bound" label="Set up" size="small" @click="openSetup(need)" />
      <template v-else>
        <Button label="Switch resource" size="small" text @click="openSetup(need)" />
        <Button label="Disconnect from this app" size="small" text severity="danger" @click="disconnect(need)" />
      </template>
    </div>

    <div v-if="need.bound && !isCollapsed(need.slug)" class="endpoint-body">
      <Message v-if="impactWarning(need) && canManage(need)" severity="warn" :closable="false">{{ impactWarning(need) }}</Message>
      <Message v-if="!canManage(need)" severity="info" :closable="false">You can use this endpoint through the app, but only a resource manager can change its SSH configuration.</Message>
      <template v-if="canManage(need)">
        <div class="form-row"><label>Transport</label><span>SSH</span></div>
        <div class="form-row"><label>Host</label><InputText v-model="formHost[need.slug]" placeholder="vps.example.com" /></div>
        <div class="form-row"><label>Port</label><InputNumber v-model="formPort[need.slug]" :min="1" :max="65535" :use-grouping="false" /></div>
        <div class="form-row"><label>User</label><InputText v-model="formUser[need.slug]" placeholder="root" /></div>
        <div class="button-row">
          <Button label="Save" size="small" :loading="saving[need.slug]" @click="save(need)" />
          <Button v-if="endpoint(need)?.publicKeyOpenssh" label="Test connection" size="small" outlined :loading="testing[need.slug]" @click="testConnection(need)" />
        </div>
      </template>

      <div v-if="endpoint(need)?.publicKeyOpenssh" class="exec-section">
        <h4>Public key</h4>
        <p class="secondary">Paste into the target's <code>~/.ssh/authorized_keys</code>. Comment: <code>{{ endpoint(need)?.publicKeyComment }}</code></p>
        <div class="pubkey"><code>{{ endpoint(need)?.publicKeyOpenssh }}</code></div>
        <div v-if="canManage(need)" class="button-row">
          <Button label="Copy" icon="pi pi-copy" size="small" outlined @click="copyKey(need)" />
          <Button label="Rotate keypair" icon="pi pi-refresh" size="small" severity="secondary" outlined @click="rotate(need)" />
        </div>
      </div>
      <div v-if="endpoint(need)?.hostKeyFingerprint" class="exec-section">
        <h4>Host key</h4>
        <p>Fingerprint: <code>{{ endpoint(need)?.hostKeyFingerprint }}</code></p>
        <Button v-if="canManage(need)" label="Unpin and trust on next connect" size="small" severity="secondary" outlined @click="unpin(need)" />
      </div>
      <pre v-if="lastTest[need.slug]" class="test-result">{{ JSON.stringify(lastTest[need.slug], (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) }}</pre>
    </div>
  </div>
  <div v-if="loading"><Skeleton height="7rem" /></div>

  <ResourceBindingDialog
    v-model:visible="bindingOpen"
    :agent-id="agentId"
    :need="selectedNeed"
    auth-mode="none"
    @changed="changed"
    @configure="configureBound"
  />
</template>

<style scoped>
.empty { text-align: center; padding: 2rem; color: var(--p-text-muted-color); }
.exec-card { border: 1px solid var(--p-content-border-color); border-radius: 0.65rem; padding: 1rem; margin-bottom: 0.85rem; }
.exec-header { display: flex; align-items: flex-start; gap: 0.75rem; }
.exec-header.clickable { cursor: pointer; }
.exec-header > .pi { margin-top: 0.35rem; color: var(--p-text-muted-color); font-size: 0.75rem; }
.header-main { flex: 1; min-width: 0; }
.header-main h3, .exec-section h4 { margin: 0; }
.secondary, .preview { color: var(--p-text-muted-color); font-size: 0.8rem; }
.preview { display: block; margin-top: 0.35rem; }
.resource-actions, .button-row { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem; }
.endpoint-body { display: flex; flex-direction: column; gap: 0.65rem; margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed var(--p-content-border-color); }
.form-row { display: grid; grid-template-columns: 6rem minmax(0, 1fr); align-items: center; gap: 0.75rem; }
.form-row label { color: var(--p-text-muted-color); font-size: 0.85rem; }
.exec-section { padding-top: 0.85rem; margin-top: 0.35rem; border-top: 1px dashed var(--p-content-border-color); }
.exec-section p { margin: 0.4rem 0; }
.pubkey, .test-result { padding: 0.75rem; border-radius: 0.4rem; background: var(--p-surface-100); word-break: break-all; overflow-x: auto; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
:root.dark .pubkey, :root.dark .test-result { background: var(--p-surface-800); }
@media (max-width: 38rem) {
  .form-row { grid-template-columns: 1fr; gap: 0.25rem; }
}
</style>
