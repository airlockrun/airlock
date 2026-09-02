<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { ws } from '@/api/ws'
import { JobResponseError, useJobsStore } from '@/stores/jobs'
import type { JobInfo } from '@/gen/airlock/v1/types_pb'
import {
  JobLifecycleEventSchema,
  JobProgressEventSchema,
  JobsSubscribedEventSchema,
} from '@/gen/airlock/v1/realtime_pb'
import {
  formatJobTimestamp as formatTimestamp,
  isActiveJob,
  jobStatusLabel,
  jobStatusSeverity,
  progressPercent,
} from '@/utils/jobs'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useJobsStore()
const { t, formatDate, formatNumber } = useAirlockI18n()
const mutating = ref<string | null>(null)
const hasActiveJobs = computed(() => store.jobs.some(isActiveJob))
const unsubscribers: (() => void)[] = []
let pollTimer: number | null = null
let refreshing = false
let refreshAgain = false

watch(() => store.jobs.length, (count) => emit('populated', count), { immediate: true })
watch(hasActiveJobs, updatePolling)

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
    await store.fetchFirstPage(props.agentId)
  } catch (error) {
    toast.add({ severity: 'error', summary: t('operations.job.loadFailed'), detail: errorDetail(error), life: 5000 })
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
  if (job.cronSlug) return t('operations.job.source.cronList', { slug: job.cronSlug })
  switch (job.initiatorKind) {
    case 'user': return t('operations.job.initiator.user')
    case 'anonymous': return t('operations.job.initiator.anonymous')
    case 'system': return t('operations.job.initiator.system')
    case '': return t('operations.common.unknown')
    default: return t('operations.job.initiator.unknown', { value: job.initiatorKind })
  }
}

function confirmCancel(job: JobInfo) {
  confirm.require({
    header: t('operations.job.cancel.title'),
    message: t('operations.job.cancel.message', {
      handler: job.handlerName,
      version: job.handlerVersion,
    }),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('operations.job.cancel.button'),
    rejectLabel: t('operations.job.cancel.keepRunning'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      mutating.value = job.id
      try {
        await store.cancel(job.id)
        toast.add({
          severity: 'info',
          summary: job.status === 'running'
            ? t('operations.build.blockers.cancellationRequested')
            : t('operations.build.blockers.jobCancelled'),
          life: 3000,
        })
      } catch (error) {
        toast.add({ severity: 'error', summary: t('operations.build.cancelFailed'), detail: errorDetail(error), life: 5000 })
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
    toast.add({ severity: 'success', summary: t('operations.job.retry.queued'), life: 3000 })
  } catch (error) {
    toast.add({ severity: 'error', summary: t('operations.job.retry.failed'), detail: errorDetail(error), life: 5000 })
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
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">{{ t('operations.job.list.empty') }}</div>
      </template>
      <Column :header="t('operations.job.list.handler')">
        <template #body="{ data: item }"><code>{{ item.handlerName }}@v{{ item.handlerVersion }}</code></template>
      </Column>
      <Column :header="t('operations.job.list.status')">
        <template #body="{ data: item }">
          <Tag :value="jobStatusLabel(item, t)" :severity="jobStatusSeverity(item)" />
        </template>
      </Column>
      <Column :header="t('operations.job.progress')">
        <template #body="{ data: item }">
          <div v-if="item.progress" class="progress-cell">
            <div class="progress-label">
              <strong>{{ item.progress.phase || t('operations.job.working') }}</strong>
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
              {{ formatNumber(item.progress.completed) }}/{{ formatNumber(item.progress.total) }} ({{ formatNumber(progressPercent(item.progress)! / 100, { style: 'percent', maximumFractionDigits: 0 }) }})
            </small>
          </div>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>
      <Column :header="t('operations.job.list.attempts')">
        <template #body="{ data: item }">{{ formatNumber(item.attemptCount) }}/{{ formatNumber(item.attemptLimit) }}</template>
      </Column>
      <Column :header="t('operations.job.list.cronSource')">
        <template #body="{ data: item }">
          <div class="source-cell">
            <span>{{ sourceLabel(item) }}</span>
            <small v-if="item.sourceRunId">{{ t('operations.job.list.sourceRun', { id: item.sourceRunId.slice(0, 8) }) }}</small>
          </div>
        </template>
      </Column>
      <Column :header="t('operations.job.list.timeline')">
        <template #body="{ data: item }">
          <div class="timeline-cell">
            <span v-if="item.scheduledAt">{{ t('operations.job.list.timelineScheduled', { time: formatJobTimestamp(item.scheduledAt) }) }}</span>
            <span>{{ t('operations.job.list.timelineCreated', { time: formatJobTimestamp(item.createdAt) }) }}</span>
            <span>{{ t('operations.job.list.timelineUpdated', { time: formatJobTimestamp(item.updatedAt) }) }}</span>
          </div>
        </template>
      </Column>
      <Column :header="t('operations.job.list.lastError')">
        <template #body="{ data: item }">
          <span v-if="item.lastError" class="error-cell" :title="item.lastError">{{ item.lastError }}</span>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: item }">
          <Button
            v-if="isActiveJob(item) && !item.cancelRequestedAt"
            :label="t('operations.job.cancel.action')"
            icon="pi pi-times"
            severity="danger"
            size="small"
            text
            :loading="mutating === item.id"
            @click.stop="confirmCancel(item)"
          />
          <Button
            v-else-if="item.status === 'failed' || item.status === 'cancelled'"
            :label="t('operations.job.retry.action')"
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
      <Column v-for="header in [
        t('operations.job.list.handler'),
        t('operations.job.list.status'),
        t('operations.job.progress'),
        t('operations.job.list.attempts'),
        t('operations.job.list.cronSource'),
        t('operations.job.list.timeline'),
        t('operations.job.list.lastError'),
        '',
      ]" :key="header" :header="header">
        <template #body><Skeleton /></template>
      </Column>
    </DataTable>

    <div v-if="store.nextCursor" class="flex justify-center mt-4">
      <Button :label="t('operations.common.loadMore')" outlined :loading="store.loading" @click="store.loadMore(agentId)" />
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
