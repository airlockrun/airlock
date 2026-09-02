<script setup lang="ts">
import { onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useRunsStore } from '@/stores/runs'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const router = useRouter()
const runsStore = useRunsStore()
const { t, formatDate, formatNumber } = useAirlockI18n()
watch(() => runsStore.runs.length, (n) => emit('populated', n), { immediate: true })

function runStatusSeverity(status: string): string {
  switch (status) {
    case 'done': case 'success': case 'completed': return 'success'
    case 'running': return 'warn'
    case 'tool_errors': case 'timeout': return 'warn'
    case 'error': case 'failed': return 'danger'
    case 'suspended': return 'info'
    default: return 'secondary'
  }
}

function runStatusLabel(status: string): string {
  switch (status) {
    case 'done': return t('operations.run.status.done')
    case 'success': return t('operations.run.status.success')
    case 'completed': return t('operations.run.status.completed')
    case 'running': return t('operations.run.status.running')
    case 'tool_errors': return t('operations.run.status.toolErrors')
    case 'timeout': return t('operations.run.status.timeout')
    case 'error': return t('operations.run.status.error')
    case 'failed': return t('operations.run.status.failed')
    case 'suspended': return t('operations.run.status.suspended')
    case 'cancelled': return t('operations.run.status.cancelled')
    default: return status
  }
}

function runTriggerLabel(trigger: string): string {
  switch (trigger) {
    case 'prompt': return t('operations.run.trigger.prompt')
    case 'bridge': return t('operations.run.trigger.bridge')
    case 'code': return t('operations.run.trigger.code')
    case 'webhook': return t('operations.run.trigger.webhook')
    case 'cron': return t('operations.run.trigger.cron')
    case 'a2a': return t('operations.run.trigger.a2a')
    case 'job': return t('operations.run.trigger.job')
    case 'background': return t('operations.run.trigger.background')
    case 'route': return t('operations.run.trigger.route')
    default: return trigger
  }
}

function formatTimestamp(ts: any): string {
  if (!ts) return '-'
  // Protobuf Timestamp has seconds (bigint or number) and nanos.
  if (ts.seconds !== undefined) {
    return formatDate(new Date(Number(ts.seconds) * 1000), {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
    })
  }
  // Fallback for string timestamps.
  const d = new Date(ts)
  return isNaN(d.getTime()) ? '-' : formatDate(d, {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatDuration(ms: number): string {
  if (!ms) return '-'
  if (ms < 1000) return t('operations.duration.milliseconds', { value: formatNumber(ms) })
  const seconds = Math.floor(ms / 1000)
  if (seconds < 60) return t('operations.duration.seconds', { value: formatNumber(seconds) })
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  if (minutes < 60) return t('operations.duration.minutesSeconds', {
    minutes: formatNumber(minutes),
    seconds: formatNumber(remainingSeconds),
  })
  const hours = Math.floor(minutes / 60)
  const remainingMinutes = minutes % 60
  return t('operations.duration.hoursMinutes', {
    hours: formatNumber(hours),
    minutes: formatNumber(remainingMinutes),
  })
}

function formatCost(cost: number): string {
  if (!cost) return '-'
  // Sub-cent costs (typical for nano/mini models) round to $0.00 with
  // 2 decimals — show 4 decimals below $1 so a 1K-in/500-out gpt-5-nano
  // call ($0.0003) doesn't read as zero.
  return formatNumber(cost, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: cost < 1 ? 4 : 2,
    maximumFractionDigits: cost < 1 ? 4 : 2,
  })
}

function navigateToRun(event: { data: { id: string } }) {
  router.push(`/agents/${props.agentId}/runs/${event.data.id}`)
}

function loadMore() {
  if (runsStore.nextCursor) {
    runsStore.fetchRuns(props.agentId, runsStore.nextCursor)
  }
}

onMounted(() => {
  runsStore.fetchRuns(props.agentId)
})
</script>

<template>
  <div>
    <DataTable
      v-if="!runsStore.loading || runsStore.runs.length > 0"
      :value="runsStore.runs"
      stripedRows
      selectionMode="single"
      @row-select="navigateToRun"
      class="cursor-pointer"
    >
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('operations.run.list.empty') }}
        </div>
      </template>
      <Column :header="t('operations.run.list.status')">
        <template #body="{ data: run }">
          <Tag :value="runStatusLabel(run.status)" :severity="runStatusSeverity(run.status)" />
        </template>
      </Column>
      <Column :header="t('operations.run.list.trigger')">
        <template #body="{ data: run }">
          <Tag :value="runTriggerLabel(run.triggerType)" severity="secondary" />
        </template>
      </Column>
      <Column :header="t('operations.run.list.started')">
        <template #body="{ data: run }">
          {{ formatTimestamp(run.startedAt) }}
        </template>
      </Column>
      <Column :header="t('operations.run.list.duration')">
        <template #body="{ data: run }">
          {{ formatDuration(run.durationMs) }}
        </template>
      </Column>
      <Column :header="t('operations.run.list.cost')">
        <template #body="{ data: run }">
          {{ formatCost(run.llmCostEstimate) }}
        </template>
      </Column>
      <Column :header="t('operations.run.list.version')">
        <template #body="{ data: run }">
          <span v-if="run.sourceRef" style="font-family: monospace; font-size: 0.8rem">
            {{ run.sourceRef.slice(0, 8) }}
          </span>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}, {}, {}]">
      <Column :header="t('operations.run.list.status')">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
      <Column :header="t('operations.run.list.trigger')">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column :header="t('operations.run.list.started')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('operations.run.list.duration')">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column :header="t('operations.run.list.cost')">
        <template #body><Skeleton width="3rem" /></template>
      </Column>
      <Column :header="t('operations.run.list.version')">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
    </DataTable>

    <div v-if="runsStore.nextCursor" class="flex justify-center mt-4">
      <Button
        :label="t('operations.common.loadMore')"
        outlined
        :loading="runsStore.loading"
        @click="loadMore"
      />
    </div>
  </div>
</template>
