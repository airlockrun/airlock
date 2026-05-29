<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useBuildsStore } from '@/stores/builds'
import { useAgentsStore } from '@/stores/agents'
import type { AgentBuildInfo } from '@/gen/airlock/v1/types_pb'

const props = defineProps<{ agentId: string }>()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useBuildsStore()
const agentsStore = useAgentsStore()

const rollingBack = ref<string | null>(null)

const currentSourceRef = computed(() => {
  const agent = agentsStore.agents.find((a) => a.id === props.agentId)
  return agent?.sourceRef ?? ''
})

function statusSeverity(status: string): string {
  switch (status) {
    case 'complete': return 'success'
    case 'building': return 'warn'
    case 'failed': return 'danger'
    // refused: the request was out of scope — not an error, so not red.
    case 'refused': return 'warn'
    default: return 'secondary'
  }
}

function typeSeverity(type: string): string {
  // Rollback rows are visually distinct so the audit trail is
  // scannable. Build/upgrade keep the default chip color.
  return type === 'rollback' ? 'info' : 'secondary'
}

function formatCost(cost: number): string {
  if (!cost) return '—'
  if (cost < 1) return `$${cost.toFixed(4)}`
  return `$${cost.toFixed(2)}`
}

function formatTimestamp(ts: any): string {
  if (!ts) return '—'
  if (ts.seconds !== undefined) {
    return new Date(Number(ts.seconds) * 1000).toLocaleString()
  }
  const d = new Date(ts)
  return isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function shortHash(ref: string): string {
  return ref ? ref.slice(0, 12) : ''
}

function buildLabel(b: AgentBuildInfo): string {
  if (b.type === 'rollback') {
    const target = b.rollbackTargetSourceRef || b.rollbackTargetId
    return target ? `Rolled back to ${shortHash(target)}` : 'Rolled back (target deleted)'
  }
  return b.instructions || '—'
}

function canRollback(b: AgentBuildInfo): boolean {
  return (
    b.status === 'complete' &&
    b.sourceRef !== '' &&
    b.sourceRef !== currentSourceRef.value &&
    rollingBack.value === null
  )
}

function navigateToBuild(event: { data: AgentBuildInfo }) {
  router.push(`/agents/${props.agentId}/builds/${event.data.id}`)
}

function onRollback(b: AgentBuildInfo) {
  confirm.require({
    header: `Roll back to ${shortHash(b.sourceRef)}?`,
    message:
      'This reverses the agent to a previous build. Migrations will be ' +
      'down-applied — data added by newer migrations may be lost. ' +
      'Forward commits stay reachable via a pre-rollback branch. Continue?',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Roll back',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-warning',
    accept: async () => {
      rollingBack.value = b.id
      try {
        await store.rollback(props.agentId, b.id)
        toast.add({
          severity: 'info',
          summary: 'Rollback started',
          detail: 'Watch the builds list for progress.',
          life: 4000,
        })
        await store.fetchBuilds(props.agentId)
      } catch (err: any) {
        toast.add({
          severity: 'error',
          summary: 'Rollback failed to start',
          detail: err?.response?.data?.error ?? err?.message ?? 'unknown error',
          life: 6000,
        })
      } finally {
        rollingBack.value = null
      }
    },
  })
}

onMounted(() => {
  store.fetchBuilds(props.agentId)
})
</script>

<template>
  <div>
    <DataTable
      v-if="!store.loading || store.builds.length > 0"
      :value="store.builds"
      stripedRows
      selectionMode="single"
      @row-select="navigateToBuild"
      class="cursor-pointer"
    >
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No builds yet.
        </div>
      </template>
      <Column header="Type">
        <template #body="{ data: b }">
          <Tag :value="b.type" :severity="typeSeverity(b.type)" />
        </template>
      </Column>
      <Column header="Description">
        <template #body="{ data: b }">
          <span class="build-label">{{ buildLabel(b) }}</span>
        </template>
      </Column>
      <Column header="Status">
        <template #body="{ data: b }">
          <Tag :value="b.status" :severity="statusSeverity(b.status)" />
        </template>
      </Column>
      <Column header="Started">
        <template #body="{ data: b }">
          {{ formatTimestamp(b.startedAt) }}
        </template>
      </Column>
      <Column header="Cost">
        <template #body="{ data: b }">
          {{ formatCost(b.llmCostEstimate) }}
        </template>
      </Column>
      <Column header="Finished">
        <template #body="{ data: b }">
          {{ formatTimestamp(b.finishedAt) }}
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: b }">
          <Button
            v-if="canRollback(b)"
            icon="pi pi-history"
            label="Rollback"
            severity="secondary"
            size="small"
            text
            :loading="rollingBack === b.id"
            @click.stop="onRollback(b)"
          />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Type"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="Status"><template #body><Skeleton width="5rem" /></template></Column>
      <Column header="Started"><template #body><Skeleton /></template></Column>
      <Column header="Cost"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Finished"><template #body><Skeleton /></template></Column>
      <Column header=""><template #body><Skeleton width="5rem" /></template></Column>
    </DataTable>
  </div>
</template>

<style scoped>
.build-label {
  display: inline-block;
  max-width: 24rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: middle;
}
</style>
