<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { ws } from '@/api/ws'
import { useJobsStore } from '@/stores/jobs'
import type { JobInfo } from '@/gen/airlock/v1/types_pb'
import {
  JobLifecycleEventSchema,
  JobProgressEventSchema,
  JobsSubscribedEventSchema,
} from '@/gen/airlock/v1/realtime_pb'
import {
  formatJobTimestamp,
  isActiveJob,
  jobStatusLabel,
  jobStatusSeverity,
  progressPercent,
} from '@/utils/jobs'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useJobsStore()
const mutating = ref<string | null>(null)
const hasActiveJobs = computed(() => store.jobs.some(isActiveJob))
const unsubscribers: (() => void)[] = []
let pollTimer: number | null = null
let refreshing = false
let refreshAgain = false

watch(() => store.jobs.length, (count) => emit('populated', count), { immediate: true })
watch(hasActiveJobs, updatePolling)

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
    await store.fetchFirstPage(props.agentId)
  } catch (error) {
    toast.add({ severity: 'error', summary: 'Jobs could not be loaded', detail: errorDetail(error), life: 5000 })
  } finally {
    refreshing = false
    if (refreshAgain) {
      refreshAgain = false
      void refresh()
    }
  }
}

function updatePolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer)
    pollTimer = null
  }
  if (hasActiveJobs.value) {
    pollTimer = window.setInterval(() => void refresh(), 15_000)
  }
}

function navigateToJob(event: { data: JobInfo }) {
  router.push({ name: 'job-detail', params: { id: props.agentId, jobId: event.data.id } })
}

function sourceLabel(job: JobInfo): string {
  if (job.cronSlug) return `Cron: ${job.cronSlug}`
  return job.initiatorKind || 'Unknown'
}

function confirmCancel(job: JobInfo) {
  confirm.require({
    header: 'Cancel background job?',
    message: `Cancel ${job.handlerName}@v${job.handlerVersion}? A running handler may take a moment to stop.`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Cancel job',
    rejectLabel: 'Keep running',
    acceptClass: 'p-button-danger',
    accept: async () => {
      mutating.value = job.id
      try {
        await store.cancel(job.id)
        toast.add({ severity: 'info', summary: job.status === 'running' ? 'Cancellation requested' : 'Job cancelled', life: 3000 })
      } catch (error) {
        toast.add({ severity: 'error', summary: 'Cancel failed', detail: errorDetail(error), life: 5000 })
      } finally {
        mutating.value = null
      }
    },
  })
}

async function retry(job: JobInfo) {
  mutating.value = job.id
  try {
    await store.retry(job.id)
    toast.add({ severity: 'success', summary: 'Job queued for retry', life: 3000 })
  } catch (error) {
    toast.add({ severity: 'error', summary: 'Retry failed', detail: errorDetail(error), life: 5000 })
  } finally {
    mutating.value = null
  }
}

onMounted(() => {
  store.beginAgentList(props.agentId)
  unsubscribers.push(
    ws.onMessage('job.lifecycle', (payload) => {
      try {
        const event = fromJson(JobLifecycleEventSchema, payload as any)
        if (event.summary?.agentId === props.agentId) store.mergeLifecycle(event)
      } catch { /* malformed event */ }
    }),
    ws.onMessage('job.progress', (payload) => {
      try {
        const event = fromJson(JobProgressEventSchema, payload as any)
        if (event.agentId === props.agentId) store.mergeProgress(event)
      } catch { /* malformed event */ }
    }),
    ws.onMessage('jobs.subscribed', (payload) => {
      try {
        const event = fromJson(JobsSubscribedEventSchema, payload as any)
        if (event.agentId === props.agentId) void refresh()
      } catch { /* malformed event */ }
    }),
    ws.onMessage('_connected', () => void refresh()),
    ws.onMessage('resync', () => void refresh()),
  )
  ws.subscribeJobs(props.agentId)
  void refresh()
})

onUnmounted(() => {
  ws.unsubscribeJobs(props.agentId)
  for (const unsubscribe of unsubscribers) unsubscribe()
  if (pollTimer !== null) window.clearInterval(pollTimer)
})
</script>

<template>
  <div>
    <DataTable
      v-if="!store.loading || store.jobs.length > 0"
      :value="store.jobs"
      stripedRows
      selectionMode="single"
      responsive-layout="scroll"
      :table-style="{ minWidth: '82rem' }"
      class="cursor-pointer"
      @row-select="navigateToJob"
    >
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">No jobs yet.</div>
      </template>
      <Column header="Handler">
        <template #body="{ data: item }"><code>{{ item.handlerName }}@v{{ item.handlerVersion }}</code></template>
      </Column>
      <Column header="Status">
        <template #body="{ data: item }">
          <Tag :value="jobStatusLabel(item)" :severity="jobStatusSeverity(item)" />
        </template>
      </Column>
      <Column header="Progress">
        <template #body="{ data: item }">
          <div v-if="item.progress" class="progress-cell">
            <div class="progress-label">
              <strong>{{ item.progress.phase || 'Working' }}</strong>
              <span v-if="item.progress.message">{{ item.progress.message }}</span>
            </div>
            <ProgressBar
              v-if="progressPercent(item.progress) !== null"
              :value="progressPercent(item.progress)!"
              style="height: 0.45rem"
              :show-value="false"
            />
            <ProgressBar v-else mode="indeterminate" style="height: 0.45rem" />
            <small v-if="progressPercent(item.progress) !== null">
              {{ item.progress.completed.toString() }}/{{ item.progress.total.toString() }} ({{ progressPercent(item.progress) }}%)
            </small>
          </div>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>
      <Column header="Attempts">
        <template #body="{ data: item }">{{ item.attemptCount }}/{{ item.attemptLimit }}</template>
      </Column>
      <Column header="Cron / Source">
        <template #body="{ data: item }">
          <div class="source-cell">
            <span>{{ sourceLabel(item) }}</span>
            <small v-if="item.sourceRunId">Run {{ item.sourceRunId.slice(0, 8) }}</small>
          </div>
        </template>
      </Column>
      <Column header="Timeline">
        <template #body="{ data: item }">
          <div class="timeline-cell">
            <span v-if="item.scheduledAt">Scheduled {{ formatJobTimestamp(item.scheduledAt) }}</span>
            <span>Created {{ formatJobTimestamp(item.createdAt) }}</span>
            <span>Updated {{ formatJobTimestamp(item.updatedAt) }}</span>
          </div>
        </template>
      </Column>
      <Column header="Last Error">
        <template #body="{ data: item }">
          <span v-if="item.lastError" class="error-cell" :title="item.lastError">{{ item.lastError }}</span>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: item }">
          <Button
            v-if="isActiveJob(item) && !item.cancelRequestedAt"
            label="Cancel"
            icon="pi pi-times"
            severity="danger"
            size="small"
            text
            :loading="mutating === item.id"
            @click.stop="confirmCancel(item)"
          />
          <Button
            v-else-if="item.status === 'failed' || item.status === 'cancelled'"
            label="Retry"
            icon="pi pi-refresh"
            severity="secondary"
            size="small"
            text
            :loading="mutating === item.id"
            @click.stop="retry(item)"
          />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column v-for="header in ['Handler', 'Status', 'Progress', 'Attempts', 'Cron / Source', 'Timeline', 'Last Error', '']" :key="header" :header="header">
        <template #body><Skeleton /></template>
      </Column>
    </DataTable>

    <div v-if="store.nextCursor" class="flex justify-center mt-4">
      <Button label="Load More" outlined :loading="store.loading" @click="store.loadMore(agentId)" />
    </div>
  </div>
</template>

<style scoped>
.progress-cell, .source-cell, .timeline-cell {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.8rem;
}
.progress-cell { min-width: 12rem; max-width: 18rem; }
.progress-label { display: flex; flex-direction: column; gap: 0.1rem; }
.progress-label span, .source-cell small, .timeline-cell, .progress-cell small { color: var(--p-text-muted-color); }
.error-cell {
  display: -webkit-box;
  max-width: 18rem;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  color: var(--p-red-500);
  overflow-wrap: anywhere;
}
</style>
