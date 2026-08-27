<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useRoute, useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { useJobsStore } from '@/stores/jobs'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import {
  JobLifecycleEventSchema,
  JobProgressEventSchema,
  JobsSubscribedEventSchema,
} from '@/gen/airlock/v1/realtime_pb'
import type { JobInfo } from '@/gen/airlock/v1/types_pb'
import {
  formatJobJson,
  formatJobTimestamp,
  isActiveJob,
  jobStatusLabel,
  jobStatusSeverity,
  progressPercent,
} from '@/utils/jobs'

const route = useRoute()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useJobsStore()
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
  return error?.response?.data?.error ?? error?.message ?? 'unknown error'
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
    header: 'Cancel background job?',
    message: `Cancel ${current.handlerName}@v${current.handlerVersion}? A running handler may take a moment to stop.`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Cancel job',
    rejectLabel: 'Keep running',
    acceptClass: 'p-button-danger',
    accept: async () => {
      mutating.value = true
      try {
        await store.cancel(jobId)
        toast.add({
          severity: 'info',
          summary: current.status === 'running' ? 'Cancellation requested' : 'Job cancelled',
          life: 3000,
        })
      } catch (error) {
        toast.add({ severity: 'error', summary: 'Cancel failed', detail: errorDetail(error), life: 5000 })
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
    toast.add({ severity: 'success', summary: 'Job queued for retry', life: 3000 })
  } catch (error) {
    toast.add({ severity: 'error', summary: 'Retry failed', detail: errorDetail(error), life: 5000 })
  } finally {
    mutating.value = false
  }
}

function sourceDescription(current: JobInfo): string {
  if (current.cronSlug) return `Cron ${current.cronSlug}`
  return current.initiatorKind || '-'
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
    toast.add({ severity: 'error', summary: 'Job not found', detail: errorDetail(error), life: 4000 })
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
    <h1 style="margin: 0 0 1rem; font-size: 1.25rem">{{ agentName }} · Job {{ job.id.slice(0, 8) }}</h1>

    <div class="job-header">
      <code>{{ job.handlerName }}@v{{ job.handlerVersion }}</code>
      <Tag :value="jobStatusLabel(job)" :severity="jobStatusSeverity(job)" />
      <span>{{ job.attemptCount }}/{{ job.attemptLimit }} attempts used</span>
      <Button
        v-if="isActiveJob(job) && !job.cancelRequestedAt"
        label="Cancel job"
        icon="pi pi-times"
        severity="danger"
        outlined
        size="small"
        :loading="mutating"
        @click="confirmCancel(job)"
      />
      <Button
        v-else-if="job.status === 'failed' || job.status === 'cancelled'"
        label="Retry job"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        size="small"
        :loading="mutating"
        @click="retry"
      />
    </div>

    <section v-if="job.progress" class="detail-section">
      <h3>Progress</h3>
      <div class="progress-heading">
        <strong>{{ job.progress.phase || 'Working' }}</strong>
        <span v-if="job.progress.message">{{ job.progress.message }}</span>
      </div>
      <ProgressBar
        v-if="progressPercent(job.progress) !== null"
        :value="progressPercent(job.progress)!"
        style="height: 0.75rem; max-width: 42rem"
      />
      <ProgressBar v-else mode="indeterminate" style="height: 0.75rem; max-width: 42rem" />
      <small class="muted">
        Attempt {{ job.progress.attempt }}
        <template v-if="progressPercent(job.progress) !== null">
          · {{ job.progress.completed.toString() }}/{{ job.progress.total.toString() }}
        </template>
        · updated {{ formatJobTimestamp(job.progress.updatedAt) }}
      </small>
    </section>

    <Message v-if="job.lastError" severity="error" :closable="false" style="margin-bottom: 1.5rem">
      {{ job.lastError }}
    </Message>

    <section class="detail-section">
      <h3>Metadata and provenance</h3>
      <dl class="metadata-grid">
        <div><dt>Job ID</dt><dd>{{ job.id }}</dd></div>
        <div><dt>Agent ID</dt><dd>{{ job.agentId }}</dd></div>
        <div><dt>Source</dt><dd>{{ sourceDescription(job) }}</dd></div>
        <div><dt>Cron ID</dt><dd>{{ job.cronId || '-' }}</dd></div>
        <div><dt>Source run</dt><dd><RouterLink v-if="job.sourceRunId" :to="{ name: 'run-detail', params: { id: agentId, runId: job.sourceRunId } }">{{ job.sourceRunId }}</RouterLink><span v-else>-</span></dd></div>
        <div><dt>Initiator access</dt><dd>{{ job.initiatorAccess || '-' }}</dd></div>
        <div><dt>Initiator user</dt><dd>{{ job.initiatorUserId || '-' }}</dd></div>
        <div><dt>Configured attempts</dt><dd>{{ job.maxAttempts }}</dd></div>
        <div><dt>Current attempt limit</dt><dd>{{ job.attemptLimit }}</dd></div>
        <div><dt>Timeout</dt><dd>{{ job.timeoutMs.toString() }} ms</dd></div>
        <div><dt>State version</dt><dd>{{ job.stateVersion.toString() }}</dd></div>
        <div><dt>Scheduled</dt><dd>{{ formatJobTimestamp(job.scheduledAt) }}</dd></div>
        <div><dt>Next attempt</dt><dd>{{ formatJobTimestamp(job.nextAttemptAt) }}</dd></div>
        <div><dt>Created</dt><dd>{{ formatJobTimestamp(job.createdAt) }}</dd></div>
        <div><dt>Updated</dt><dd>{{ formatJobTimestamp(job.updatedAt) }}</dd></div>
        <div><dt>Started</dt><dd>{{ formatJobTimestamp(job.startedAt) }}</dd></div>
        <div><dt>Completed</dt><dd>{{ formatJobTimestamp(job.completedAt) }}</dd></div>
        <div><dt>Cancellation requested</dt><dd>{{ formatJobTimestamp(job.cancelRequestedAt) }}</dd></div>
      </dl>
    </section>

    <div class="json-grid detail-section">
      <section>
        <h3>Input</h3>
        <pre class="json-panel">{{ formatJobJson(job.inputJson) }}</pre>
      </section>
      <section>
        <h3>Output</h3>
        <pre class="json-panel">{{ formatJobJson(job.outputJson) }}</pre>
      </section>
    </div>

    <section class="detail-section">
      <h3>Attempts</h3>
      <DataTable
        :value="store.attempts"
        stripedRows
        responsive-layout="scroll"
        :table-style="{ minWidth: '70rem' }"
      >
        <template #empty>
          <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">No attempts yet.</div>
        </template>
        <Column field="attemptNumber" header="#" />
        <Column header="Status"><template #body="{ data: attempt }"><Tag :value="attempt.status" severity="secondary" /></template></Column>
        <Column header="Run">
          <template #body="{ data: attempt }">
            <RouterLink v-if="attempt.runId" :to="{ name: 'run-detail', params: { id: agentId, runId: attempt.runId } }">{{ attempt.runId.slice(0, 8) }}</RouterLink>
            <span v-else>-</span>
          </template>
        </Column>
        <Column header="Runtime"><template #body="{ data: attempt }">{{ attempt.runtimeGeneration.toString() }}</template></Column>
        <Column header="Leased"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.leasedAt) }}</template></Column>
        <Column header="Lease Expires"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.leaseExpiresAt) }}</template></Column>
        <Column header="Started"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.startedAt) }}</template></Column>
        <Column header="Completed"><template #body="{ data: attempt }">{{ formatJobTimestamp(attempt.completedAt) }}</template></Column>
        <Column header="Error">
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
