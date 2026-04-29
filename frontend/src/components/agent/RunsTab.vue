<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useRunsStore } from '@/stores/runs'

const props = defineProps<{ agentId: string }>()
const router = useRouter()
const runsStore = useRunsStore()

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

function formatTimestamp(ts: any): string {
  if (!ts) return '—'
  // Protobuf Timestamp has seconds (bigint or number) and nanos.
  if (ts.seconds !== undefined) {
    return new Date(Number(ts.seconds) * 1000).toLocaleString()
  }
  // Fallback for string timestamps.
  const d = new Date(ts)
  return isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function formatDuration(ms: number): string {
  if (!ms) return '—'
  if (ms < 1000) return `${ms}ms`
  const seconds = Math.floor(ms / 1000)
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`
  const hours = Math.floor(minutes / 60)
  const remainingMinutes = minutes % 60
  return `${hours}h ${remainingMinutes}m`
}

function formatCost(cost: number): string {
  if (!cost) return '—'
  return `$${cost.toFixed(2)}`
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
      <Column header="Status">
        <template #body="{ data: run }">
          <Tag :value="run.status" :severity="runStatusSeverity(run.status)" />
        </template>
      </Column>
      <Column header="Started">
        <template #body="{ data: run }">
          {{ formatTimestamp(run.startedAt) }}
        </template>
      </Column>
      <Column header="Duration">
        <template #body="{ data: run }">
          {{ formatDuration(run.durationMs) }}
        </template>
      </Column>
      <Column header="Cost">
        <template #body="{ data: run }">
          {{ formatCost(run.llmCostEstimate) }}
        </template>
      </Column>
      <Column header="Version">
        <template #body="{ data: run }">
          <span v-if="run.sourceRef" style="font-family: monospace; font-size: 0.8rem">
            {{ run.sourceRef.slice(0, 8) }}
          </span>
          <span v-else style="color: var(--p-text-muted-color)">—</span>
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}, {}, {}]">
      <Column header="Status">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
      <Column header="Started">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Duration">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column header="Cost">
        <template #body><Skeleton width="3rem" /></template>
      </Column>
      <Column header="Version">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
    </DataTable>

    <div v-if="runsStore.nextCursor" class="flex justify-center mt-4">
      <Button
        label="Load More"
        outlined
        :loading="runsStore.loading"
        @click="loadMore"
      />
    </div>
  </div>
</template>
