<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useBuildsStore } from '@/stores/builds'
import type { AgentBuildInfo } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string; currentSourceRef: string; readOnlyGit?: boolean }>()
const emit = defineEmits<{ populated: [count: number] }>()
const router = useRouter()
const confirm = useConfirm()
const toast = useToast()
const store = useBuildsStore()
const { t, formatDate, formatNumber } = useAirlockI18n()
watch(() => store.builds.length, (n) => emit('populated', n), { immediate: true })

const rollingBack = ref<string | null>(null)

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
  if (!cost) return '-'
  return formatNumber(cost, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: cost < 1 ? 4 : 2,
    maximumFractionDigits: cost < 1 ? 4 : 2,
  })
}

function formatTimestamp(ts: any): string {
  if (!ts) return '-'
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

function shortHash(ref: string): string {
  return ref ? ref.slice(0, 12) : ''
}

function buildLabel(b: AgentBuildInfo): string {
  if (b.type === 'rollback') {
    const target = b.rollbackTargetSourceRef || b.rollbackTargetId
    return target
      ? t('operations.build.list.rolledBackTo', { target: shortHash(target) })
      : t('operations.build.list.rolledBackDeleted')
  }
  return b.instructions || '-'
}

function buildTypeLabel(type: string): string {
  switch (type) {
    case 'build': return t('operations.build.type.build')
    case 'upgrade': return t('operations.build.type.upgrade')
    case 'rollback': return t('operations.build.type.rollback')
    default: return type
  }
}

function buildStatusLabel(status: string): string {
  switch (status) {
    case 'building': return t('operations.build.status.building')
    case 'complete': return t('operations.build.status.complete')
    case 'failed': return t('operations.build.status.failed')
    case 'refused': return t('operations.build.status.refused')
    case 'cancelled': return t('operations.build.status.cancelled')
    default: return status
  }
}

function canRollback(b: AgentBuildInfo): boolean {
  return (
    !props.readOnlyGit &&
    b.status === 'complete' &&
    b.sourceRef !== '' &&
    b.sourceRef !== props.currentSourceRef &&
    rollingBack.value === null
  )
}

function navigateToBuild(event: { data: AgentBuildInfo }) {
  router.push(`/agents/${props.agentId}/builds/${event.data.id}`)
}

function onRollback(b: AgentBuildInfo) {
  confirm.require({
    header: t('operations.build.rollback.title', { target: shortHash(b.sourceRef) }),
    message: t('operations.build.rollback.message'),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('operations.build.rollback.accept'),
    rejectLabel: t('operations.common.cancel'),
    acceptClass: 'p-button-warning',
    accept: async () => {
      rollingBack.value = b.id
      try {
        await store.rollback(props.agentId, b.id)
        toast.add({
          severity: 'info',
          summary: t('operations.build.rollback.started'),
          detail: t('operations.build.rollback.watchProgress'),
          life: 4000,
        })
        await store.fetchBuilds(props.agentId)
      } catch (err: any) {
        toast.add({
          severity: 'error',
          summary: t('operations.build.rollback.failed'),
          detail: err?.response?.data?.error ?? err?.message ?? t('operations.common.unknownError'),
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
          {{ t('operations.build.list.empty') }}
        </div>
      </template>
      <Column :header="t('operations.build.list.type')">
        <template #body="{ data: b }">
          <Tag :value="buildTypeLabel(b.type)" :severity="typeSeverity(b.type)" />
        </template>
      </Column>
      <Column :header="t('operations.build.list.description')">
        <template #body="{ data: b }">
          <span class="build-label">{{ buildLabel(b) }}</span>
        </template>
      </Column>
      <Column :header="t('operations.build.list.status')">
        <template #body="{ data: b }">
          <Tag :value="buildStatusLabel(b.status)" :severity="statusSeverity(b.status)" />
        </template>
      </Column>
      <Column :header="t('operations.build.list.result')">
        <template #body="{ data: b }">
          <div class="result-cell">
            <Tag
              v-if="b.status === 'failed' && b.failureKind === 'infra'"
              :value="t('operations.build.platformError')"
              severity="warn"
              v-tooltip.top="t('operations.build.platformErrorTooltip')"
            />
            <div v-if="b.exitMessage" :class="b.exitStatus === 'success' ? 'result-ok' : 'result-bad'">
              <i :class="b.exitStatus === 'success' ? 'pi pi-check' : 'pi pi-times'" />
              <span class="result-text">{{ b.exitMessage }}</span>
            </div>
            <div v-if="b.errorMessage && b.errorMessage !== b.exitMessage" class="result-bad">
              <i class="pi pi-times" /> <span class="result-text">{{ b.errorMessage }}</span>
            </div>
            <span v-if="!b.exitMessage && !b.errorMessage" style="color: var(--p-text-muted-color)">-</span>
          </div>
        </template>
      </Column>
      <Column :header="t('operations.build.list.started')">
        <template #body="{ data: b }">
          {{ formatTimestamp(b.startedAt) }}
        </template>
      </Column>
      <Column :header="t('operations.build.list.model')">
        <template #body="{ data: b }">
          <span class="build-model">{{ b.buildModel || '-' }}</span>
        </template>
      </Column>
      <Column :header="t('operations.build.list.cost')">
        <template #body="{ data: b }">
          {{ formatCost(b.llmCostEstimate) }}
        </template>
      </Column>
      <Column :header="t('operations.build.list.finished')">
        <template #body="{ data: b }">
          {{ formatTimestamp(b.finishedAt) }}
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: b }">
          <Button
            v-if="canRollback(b)"
            icon="pi pi-history"
            :label="t('operations.build.rollback.button')"
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
      <Column :header="t('operations.build.list.type')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column :header="t('operations.build.list.description')"><template #body><Skeleton /></template></Column>
      <Column :header="t('operations.build.list.status')"><template #body><Skeleton width="5rem" /></template></Column>
      <Column :header="t('operations.build.list.result')"><template #body><Skeleton /></template></Column>
      <Column :header="t('operations.build.list.started')"><template #body><Skeleton /></template></Column>
      <Column :header="t('operations.build.list.model')"><template #body><Skeleton width="5rem" /></template></Column>
      <Column :header="t('operations.build.list.cost')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column :header="t('operations.build.list.finished')"><template #body><Skeleton /></template></Column>
      <Column header=""><template #body><Skeleton width="5rem" /></template></Column>
    </DataTable>
  </div>
</template>

<style scoped>
.build-label {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  max-width: 18rem;
  word-break: break-word;
  vertical-align: middle;
}
.build-model {
  font-size: 0.85rem;
  color: var(--p-text-muted-color);
}
.result-cell {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  max-width: 22rem;
  font-size: 0.85rem;
}
/* Clamp the result summary to a couple of lines so a long exit message
   doesn't inflate the row; the full text shows on the build detail page. */
.result-text {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  word-break: break-word;
}
.result-cell .pi {
  font-size: 0.7rem;
  margin-right: 0.2rem;
}
.result-ok {
  color: var(--p-green-500);
}
.result-bad {
  color: var(--p-red-400);
}
</style>
