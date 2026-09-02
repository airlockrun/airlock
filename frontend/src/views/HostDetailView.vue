<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import type { GetHostResponse } from '@/gen/airlock/v1/api_pb'
import type { ConnectorInfo } from '@/gen/airlock/v1/types_pb'
import { getHost, requestRemove, requestRollback, requestShell } from '@/api/hosts'
import { useNow } from '@/composables/useNow'
import { useAirlockI18n } from '@/i18n'
import { hasCapability } from '@/utils/resources'
import { connectorReadiness, hostStatus, isHostStale } from '@/utils/connectors'

const route = useRoute()
const toast = useToast()
const { t } = useAirlockI18n()
const detail = ref<GetHostResponse | null>(null)
const loading = ref(true)
const shellOpen = ref(false)
const command = ref('')
const commandArguments = ref('[]')
const saving = ref(false)
const now = useNow()

const host = computed(() => detail.value?.host)
const stale = computed(() => !host.value || isHostStale(host.value.lastSeenAt, now.value))
const canManage = computed(() => hasCapability(host.value?.capabilities ?? [], 'manage'))
const canFull = computed(() => canManage.value && !stale.value && host.value?.accessMode === 'full')
const canUpdate = computed(() => canManage.value && !stale.value && (host.value?.accessMode === 'full' || host.value?.accessMode === 'update_only'))
const status = computed(() => host.value ? hostStatus(host.value, now.value, t) : null)

const capabilityMessageIds = {
  view: 'connectors.common.capability.view',
  bind: 'connectors.common.capability.bind',
  manage: 'connectors.common.capability.manage',
} as const

const managementKindMessageIds = {
  shell: 'connectors.host.detail.managementKind.shell',
  connector_install: 'connectors.host.detail.managementKind.connectorInstall',
  connector_update: 'connectors.host.detail.managementKind.connectorUpdate',
  connector_remove: 'connectors.host.detail.managementKind.connectorRemove',
  connector_rollback: 'connectors.host.detail.managementKind.connectorRollback',
} as const

const managementStatusMessageIds = {
  queued: 'connectors.host.detail.managementStatus.queued',
  running: 'connectors.host.detail.managementStatus.running',
  succeeded: 'connectors.host.detail.managementStatus.succeeded',
  failed: 'connectors.host.detail.managementStatus.failed',
  cancelled: 'connectors.host.detail.managementStatus.cancelled',
  timed_out: 'connectors.host.detail.managementStatus.timedOut',
} as const

function capabilityLabel(capability: string): string {
  const id = capabilityMessageIds[capability as keyof typeof capabilityMessageIds]
  return id ? t(id) : capability
}

function accessModeLabel(mode: string): string {
  if (mode === 'full') return t('connectors.host.access.full')
  if (mode === 'update_only') return t('connectors.host.access.updateOnly')
  if (mode === 'none') return t('connectors.host.access.none')
  return mode
}

function managementKindLabel(kind: string): string {
  const id = managementKindMessageIds[kind as keyof typeof managementKindMessageIds]
  return id ? t(id) : kind
}

function managementStatusLabel(status: string): string {
  const id = managementStatusMessageIds[status as keyof typeof managementStatusMessageIds]
  return id ? t(id) : status
}

function apiError(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null) {
    const typed = error as { response?: { data?: { error?: unknown } } }
    if (typeof typed.response?.data?.error === 'string') return typed.response.data.error
  }
  return fallback
}

async function load() {
  loading.value = true
  try { detail.value = await getHost(String(route.params.hostId)) }
  catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.host.detail.loadFailed')), life: 5000 }) }
  finally { loading.value = false }
}

async function submitShell() {
  if (!host.value) return
  saving.value = true
  try {
    const args = JSON.parse(commandArguments.value)
    if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) throw new Error(t('connectors.host.detail.argumentsInvalid'))
    await requestShell(host.value.id, command.value, args)
    shellOpen.value = false
    toast.add({ severity: 'success', summary: t('connectors.host.detail.workQueued'), life: 3000 })
    await load()
  } catch (error: unknown) {
    const fallback = error instanceof Error ? error.message : t('connectors.host.detail.requestFailed')
    const message = apiError(error, fallback)
    toast.add({ severity: 'error', summary: message, life: 5000 })
  }
  finally { saving.value = false }
}

async function remove(connector: ConnectorInfo) {
  saving.value = true
  try { await requestRemove(connector.id); toast.add({ severity: 'success', summary: t('connectors.host.detail.removalQueued'), life: 3000 }); await load() }
  catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.host.detail.removalFailed')), life: 5000 }) }
  finally { saving.value = false }
}

async function rollback(connector: ConnectorInfo) {
  saving.value = true
  try { await requestRollback(connector.id); toast.add({ severity: 'success', summary: t('connectors.host.detail.rollbackQueued'), life: 3000 }); await load() }
  catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.host.detail.rollbackFailed')), life: 5000 }) }
  finally { saving.value = false }
}

onMounted(load)
</script>

<template>
  <div class="host-detail">
    <Skeleton v-if="loading" height="18rem" />
    <template v-else-if="host">
      <div class="heading">
        <div><h1>{{ host.name }}</h1><p>{{ host.platform }} / {{ host.architecture }} · airlock-host {{ host.version }}</p></div>
        <div class="heading-tags"><Tag v-if="status" :value="status.label" :severity="status.severity" /><Tag :value="accessModeLabel(host.accessMode)" :severity="host.accessMode === 'full' ? 'success' : host.accessMode === 'update_only' ? 'warn' : 'secondary'" /></div>
      </div>
      <div class="host-access">
        <span><small>{{ t('connectors.host.detail.owner') }}</small><strong>{{ host.ownerName || host.ownerUserId }}</strong></span>
        <span class="capabilities"><small>{{ t('connectors.host.detail.yourAccess') }}</small><Tag v-for="capability in host.capabilities" :key="capability" :value="capabilityLabel(capability)" severity="secondary" /></span>
      </div>
      <Message severity="info" :closable="false">{{ t('connectors.host.detail.accessExplanation') }}</Message>
      <Message v-if="stale" severity="warn" :closable="false">{{ t('connectors.host.detail.staleWarning') }}</Message>
       <div class="toolbar"><Button :label="t('connectors.host.detail.shell')" icon="pi pi-terminal" outlined :disabled="!canFull" @click="shellOpen = true" /></div>
      <Card>
        <template #title>{{ t('connectors.host.detail.hostedConnectors') }}</template>
        <template #content>
          <DataTable :value="detail?.connectors ?? []" responsive-layout="scroll" stripedRows>
            <template #empty><div class="empty">{{ t('connectors.host.detail.noConnectors') }}</div></template>
            <Column field="displayName" :header="t('connectors.host.detail.connector')" />
            <Column field="artifactVersion" :header="t('connectors.host.detail.version')" />
            <Column :header="t('connectors.host.detail.readiness')"><template #body="{ data }"><Tag :value="connectorReadiness(data.readiness, t).label" :severity="connectorReadiness(data.readiness, t).severity" /></template></Column>
             <Column header=""><template #body="{ data }"><div class="row-actions"><Button :label="t('connectors.host.detail.rollback')" size="small" text :disabled="!canUpdate" @click="rollback(data)" /><Button :label="t('connectors.host.detail.remove')" size="small" severity="danger" text :disabled="!canFull" @click="remove(data)" /></div></template></Column>
          </DataTable>
        </template>
      </Card>
      <Card>
        <template #title>{{ t('connectors.host.detail.managementHistory') }}</template>
        <template #content>
          <DataTable :value="detail?.managementJobs ?? []" responsive-layout="scroll" size="small">
            <template #empty><div class="empty">{{ t('connectors.host.detail.noManagementRequests') }}</div></template>
            <Column field="kind" :header="t('connectors.host.detail.kind')"><template #body="{ data }">{{ managementKindLabel(data.kind) }}</template></Column>
            <Column field="status" :header="t('connectors.host.detail.status')"><template #body="{ data }"><Tag :value="managementStatusLabel(data.status)" /></template></Column>
            <Column field="errorMessage" :header="t('connectors.host.detail.result')" />
          </DataTable>
        </template>
      </Card>
    </template>

    <Dialog v-model:visible="shellOpen" modal :header="t('connectors.host.detail.runShellCommand')" :style="{ width: 'min(36rem, calc(100vw - 2rem))' }">
      <div class="form">
        <label>{{ t('connectors.host.detail.executable') }}<InputText v-model="command" placeholder="/usr/bin/uname" /></label>
        <label>{{ t('connectors.host.detail.argumentsJson') }}<InputText v-model="commandArguments" placeholder='["-a"]' /></label>
      </div>
      <template #footer><Button :label="t('connectors.tab.cancel')" text @click="shellOpen = false" /><Button :label="t('connectors.host.detail.queueRequest')" :loading="saving" @click="submitShell" /></template>
    </Dialog>
  </div>
</template>

<style scoped>
.host-detail { max-width: 72rem; margin: 0 auto; display: grid; gap: 1rem; }
.heading, .heading-tags, .toolbar, .row-actions, .host-access, .capabilities { display: flex; align-items: center; justify-content: space-between; gap: .75rem; }
.toolbar { justify-content: flex-end; }
.host-access { justify-content: flex-start; flex-wrap: wrap; }
.host-access > span { display: flex; align-items: center; gap: .4rem; }
.host-access small { color: var(--p-text-muted-color); }
.capabilities { justify-content: flex-start; }
h1 { margin: 0 0 .25rem; } p { margin: 0; color: var(--p-text-muted-color); }
.empty { padding: 1.5rem; text-align: center; color: var(--p-text-muted-color); }
.form { display: grid; gap: 1rem; }.form label { display: grid; gap: .4rem; font-weight: 600; }.form small { color: var(--p-text-muted-color); }
@media (max-width: 640px) { .heading { align-items: start; } .toolbar { justify-content: stretch; } .toolbar > * { flex: 1; } }
</style>
