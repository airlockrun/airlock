<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { JobResponseError, useJobsStore } from '@/stores/jobs'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import {
  JobLifecycleEventSchema,
  JobProgressEventSchema,
  JobsSubscribedEventSchema,
} from '@/gen/airlock/v1/realtime_pb'
import type { JobInfo } from '@/gen/airlock/v1/types_pb'
import {
  formatJobJson,
  formatJobTimestamp as formatTimestamp,
  isActiveJob,
  jobStatusLabel,
  jobStatusSeverity,
  jobStatusText,
  progressPercent,
} from '@/utils/jobs'
import { useAirlockI18n } from '@/i18n'

const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useJobsStore()
const { t, formatDate, formatNumber } = useAirlockI18n()
const agentId = route.params.id as string
const jobId = route.params.jobId as string
const agentName = ref(agentId.slice(0, 8))
const loading = ref(true)
const mutating = ref(false)
const unsubscribers: (() => void)[] = []
let pollTimer: number | null = null
let refreshing = false
let refreshAgain = false

const job = computed(() => store.job?.id === jobId ? store.job : null)
const isActive = computed(() => !!job.value && isActiveJob(job.value))

watch(isActive, updatePolling)

function errorDetail(error: any): string {
  if (error instanceof JobResponseError) return t(error.messageId)
  return error?.response?.data?.error ?? error?.message ?? t('operations.common.unknownError')
}

function formatJobTimestamp(timestamp: Parameters<typeof formatTimestamp>[0]): string {
  return formatTimestamp(timestamp, formatDate)
}

async function refresh() {
  if (refreshing) {
    refreshAgain = true
    return
  }
  refreshing = true
  try {
    await store.fetchJob(jobId)
  } finally {
    refreshing = false
    if (refreshAgain) {
      refreshAgain = false
      void refresh().catch(() => {})
    }
  }
}

function updatePolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer)
    pollTimer = null
  }
  if (isActive.value) pollTimer = window.setInterval(() => void refresh().catch(() => {}), 15_000)
}

function confirmCancel(current: JobInfo) {
  confirm.require({
    header: t('operations.job.cancel.title'),
    message: t('operations.job.cancel.message', {
      handler: current.handlerName,
      version: current.handlerVersion,
    }),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('operations.job.cancel.button'),
    rejectLabel: t('operations.job.cancel.keepRunning'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      mutating.value = true
      try {
        await store.cancel(jobId)
        toast.add({
          severity: 'info',
          summary: current.status === 'running'
            ? t('operations.build.blockers.cancellationRequested')
            : t('operations.build.blockers.jobCancelled'),
          life: 3000,
        })
      } catch (error) {
        toast.add({ severity: 'error', summary: t('operations.build.cancelFailed'), detail: errorDetail(error), life: 5000 })
      } finally {
        mutating.value = false
      }
    },
  })
}

async function retry() {
  mutating.value = true
  try {
    await store.retry(jobId)
    await refresh()
    toast.add({ severity: 'success', summary: t('operations.job.retry.queued'), life: 3000 })
  } catch (error) {
    toast.add({ severity: 'error', summary: t('operations.job.retry.failed'), detail: errorDetail(error), life: 5000 })
  } finally {
    mutating.value = false
  }
}

function sourceDescription(current: JobInfo): string {
  if (current.cronSlug) return t('operations.job.source.cron', { slug: current.cronSlug })
  return initiatorKindLabel(current.initiatorKind)
}

function initiatorKindLabel(kind: string): string {
  switch (kind) {
    case 'user': return t('operations.job.initiator.user')
    case 'anonymous': return t('operations.job.initiator.anonymous')
    case 'system': return t('operations.job.initiator.system')
    case '': return t('operations.common.unknown')
    default: return t('operations.job.initiator.unknown', { value: kind })
  }
}

function initiatorAccessLabel(access: string): string {
  switch (access) {
    case 'public': return t('operations.job.initiator.access.public')
    case 'user': return t('operations.job.initiator.access.user')
    case 'admin': return t('operations.job.initiator.access.admin')
    case '': return t('operations.common.unknown')
    default: return t('operations.job.initiator.unknown', { value: access })
  }
}

onMounted(async () => {
  store.beginAgentList(agentId)
  unsubscribers.push(
    ws.onMessage('job.lifecycle', (payload) => {
      try {
        const event = fromJson(JobLifecycleEventSchema, payload as any)
        const summary = event.summary
        if (!summary || summary.agentId !== agentId || summary.id !== jobId) return
        const previousVersion = job.value?.stateVersion ?? -1n
        store.mergeLifecycle(event)
        if (summary.stateVersion > previousVersion) void refresh().catch(() => {})
      } catch { /* malformed event */ }
    }),
    ws.onMessage('job.progress', (payload) => {
      try {
        const event = fromJson(JobProgressEventSchema, payload as any)
        if (event.agentId === agentId && event.jobId === jobId) store.mergeProgress(event)
      } catch { /* malformed event */ }
    }),
    ws.onMessage('jobs.subscribed', (payload) => {
      try {
        const event = fromJson(JobsSubscribedEventSchema, payload as any)
        if (event.agentId === agentId) void refresh().catch(() => {})
      } catch { /* malformed event */ }
    }),
    ws.onMessage('_connected', () => void refresh().catch(() => {})),
    ws.onMessage('resync', () => void refresh().catch(() => {})),
  )
  ws.subscribeJobs(agentId)

  try {
    await Promise.all([
      refresh(),
      api.get(`/api/v1/agents/${agentId}`).then(({ data }) => {
        const agent = fromJson(GetAgentDetailResponseSchema, data).agent
        if (agent) agentName.value = agent.name
      }).catch(() => {}),
    ])
  } catch (error) {
    toast.add({ severity: 'error', summary: t('operations.job.notFound'), detail: errorDetail(error), life: 4000 })
    router.push(`/agents/${agentId}`)
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  ws.unsubscribeJobs(agentId)
  for (const unsubscribe of unsubscribers) unsubscribe()
  if (pollTimer !== null) window.clearInterval(pollTimer)
  store.clearDetail(jobId)
})
</script>

<template>
  <div v-if="loading">
    <Skeleton width="40%" height="2rem" style="margin-bottom: 1rem" />
    <Skeleton width="100%" height="24rem" />
  </div>

  <div v-else-if="job">
    <h1 style="margin: 0 0 1rem; font-size: 1.25rem">{{ t('operations.job.title', { agent: agentName, id: job.id.slice(0, 8) }) }}</h1>

    <div class="job-header">
      <code>{{ job.handlerName }}@v{{ job.handlerVersion }}</code>
      <Tag :value="jobStatusLabel(job, t)" :severity="jobStatusSeverity(job)" />
      <span>{{ t('operations.job.attemptsUsed', {
        usedFormatted: formatNumber(job.attemptCount),
        limitFormatted: formatNumber(job.attemptLimit),
        count: job.attemptCount,
      }) }}</span>
      <Button
        v-if="isActiveJob(job) && !job.cancelRequestedAt"
        :label="t('operations.job.cancel.button')"
        icon="pi pi-times"
        severity="danger"
        outlined
        size="small"
        :loading="mutating"
        @click="confirmCancel(job)"
      />
      <Button
        v-else-if="job.status === 'failed' || job.status === 'cancelled'"
        :label="t('operations.job.retry.button')"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        size="small"
        :loading="mutating"
        @click="retry"
      />
    </div>

    <section v-if="job.progress" class="detail-section">
      <h3>{{ t('operations.job.progress') }}</h3>
      <div class="progress-heading">
        <strong>{{ job.progress.phase || t('operations.job.working') }}</strong>
        <span v-if="job.progress.message">{{ job.progress.message }}</span>
      </div>
      <ProgressBar
        v-if="progressPercent(job.progress) !== null"
        :value="progressPercent(job.progress)!"
        style="height: 0.75rem; max-width: 42rem"
      />
      <ProgressBar v-else mode="indeterminate" style="height: 0.75rem; max-width: 42rem" />
      <small class="muted">
        {{ t('operations.job.progressAttempt', { formattedAttempt: formatNumber(job.progress.attempt) }) }}
        <template v-if="progressPercent(job.progress) !== null">
          · {{ formatNumber(job.progress.completed) }}/{{ formatNumber(job.progress.total) }}
        </template>
        · {{ t('operations.job.progressUpdated', { time: formatJobTimestamp(job.progress.updatedAt) }) }}
      </small>
    </section>

    <Message v-if="job.lastError" severity="error" :closable="false" style="margin-bottom: 1.5rem">
      {{ job.lastError }}
    </Message>

    <section class="detail-section">
      <h3>{{ t('operations.job.metadata') }}</h3>
      <dl class="metadata-grid">
        <div><dt>{{ t('operations.job.metadata.jobId') }}</dt><dd>{{ job.id }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.agentId') }}</dt><dd>{{ job.agentId }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.source') }}</dt><dd>{{ sourceDescription(job) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.cronId') }}</dt><dd>{{ job.cronId || '-' }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.sourceRun') }}</dt><dd><RouterLink v-if="job.sourceRunId" :to="{ name: 'run-detail', params: { id: agentId, runId: job.sourceRunId } }">{{ job.sourceRunId }}</RouterLink><span v-else>-</span></dd></div>
        <div><dt>{{ t('operations.job.metadata.initiatorAccess') }}</dt><dd>{{ initiatorAccessLabel(job.initiatorAccess) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.initiatorUser') }}</dt><dd>{{ job.initiatorUserId || '-' }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.configuredAttempts') }}</dt><dd>{{ formatNumber(job.maxAttempts) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.attemptLimit') }}</dt><dd>{{ formatNumber(job.attemptLimit) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.timeout') }}</dt><dd>{{ t('operations.job.metadata.timeoutMs', { value: formatNumber(job.timeoutMs) }) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.stateVersion') }}</dt><dd>{{ formatNumber(job.stateVersion) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.scheduled') }}</dt><dd>{{ formatJobTimestamp(job.scheduledAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.nextAttempt') }}</dt><dd>{{ formatJobTimestamp(job.nextAttemptAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.created') }}</dt><dd>{{ formatJobTimestamp(job.createdAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.updated') }}</dt><dd>{{ formatJobTimestamp(job.updatedAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.started') }}</dt><dd>{{ formatJobTimestamp(job.startedAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.completed') }}</dt><dd>{{ formatJobTimestamp(job.completedAt) }}</dd></div>
        <div><dt>{{ t('operations.job.metadata.cancellationRequested') }}</dt><dd>{{ formatJobTimestamp(job.cancelRequestedAt) }}</dd></div>
      </dl>
    </section>

    <div class="json-grid detail-section">
      <section>
        <h3>{{ t('operations.job.input') }}</h3>
        <pre class="json-panel">{{ formatJobJson(job.inputJson) }}</pre>
      </section>
      <section>
        <h3>{{ t('operations.job.output') }}</h3>
        <pre class="json-panel">{{ formatJobJson(job.outputJson) }}</pre>
      </section>
    </div>

    <section class="detail-section">
      <h3>{{ t('operations.job.attempts') }}</h3>
      <DataTable
        :value="store.attempts"
        stripedRows
        responsive-layout="scroll"
        :table-style="{ minWidth: '70rem' }"
      >
        <template #empty>
          <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">{{ t('operations.job.attempts.empty') }}</div>
        </template>
        <Column field="attemptNumber" header="#" />
        <Column :header="t('operations.job.attempts.status')"><template #body="{ data: attempt }"><Tag :value="jobStatusText(attempt.status, t)" severity="secondary" /></template></Column>
        <Column :header="t('operations.job.attempts.run')">
          <template #body="{ data: attempt }">
            <RouterLink v-if="attempt.runId" :to="{ name: 'run-detail', params: { id: agentId, runId: attempt.runId } }">{{ attempt.runId.slice(0, 8) }}</RouterLink>
            <span v-else>-</span>
          </template>
        </Column>
        <Column :header="t('operations.job.attempts.runtime')"><template #body="{ data: attempt }">{{ formatNumber(attempt.runtimeGeneration) }}</template></Column>
        <Column :header="t('operations.job.attempts.leased')"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.leasedAt) }}</template></Column>
        <Column :header="t('operations.job.attempts.leaseExpires')"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.leaseExpiresAt) }}</template></Column>
        <Column :header="t('operations.job.metadata.started')"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.startedAt) }}</template></Column>
        <Column :header="t('operations.job.metadata.completed')"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.completedAt) }}</template></Column>
        <Column :header="t('operations.job.attempts.error')">
          <template #body="{ data: attempt }">
            <div v-if="attempt.errorKind || attempt.errorMessage" class="attempt-error">
              <strong v-if="attempt.errorKind">{{ attempt.errorKind }}</strong>
              <span>{{ attempt.errorMessage }}</span>
            </div>
            <span v-else>-</span>
          </template>
        </Column>
      </DataTable>
    </section>
  </div>
</template>

<style scoped>
.job-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  color: var(--p-text-muted-color);
  font-size: 0.875rem;
}
.detail-section { margin-bottom: 1.5rem; }
.detail-section h3 { margin-bottom: 0.75rem; }
.progress-heading { display: flex; flex-direction: column; gap: 0.2rem; margin-bottom: 0.6rem; }
.muted { display: block; margin-top: 0.5rem; color: var(--p-text-muted-color); }
.metadata-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: 0.9rem 1.25rem;
}
.metadata-grid div { min-width: 0; }
.metadata-grid dt { color: var(--p-text-muted-color); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }
.metadata-grid dd { margin-top: 0.2rem; overflow-wrap: anywhere; }
.json-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.json-panel {
  min-height: 8rem;
  max-height: 28rem;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  padding: 0.75rem;
  border: 1px solid var(--p-content-border-color);
  border-radius: 0.5rem;
  background: var(--p-surface-100);
  font-size: 0.8rem;
}
:root.dark .json-panel { background: var(--p-surface-800); }
.attempt-error { display: flex; flex-direction: column; gap: 0.2rem; max-width: 20rem; color: var(--p-red-500); overflow-wrap: anywhere; }
@media (max-width: 768px) {
  .json-grid { grid-template-columns: 1fr; }
  .metadata-grid { grid-template-columns: 1fr; }
}
</style>
