<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useBuildsStore } from '@/stores/builds'

const props = defineProps<{ agentId: string }>()
const router = useRouter()
const store = useBuildsStore()

function statusSeverity(status: string): string {
  switch (status) {
    case 'complete': return 'success'
    case 'building': return 'warn'
    case 'failed': return 'danger'
    default: return 'secondary'
  }
}

function formatTimestamp(ts: any): string {
  if (!ts) return '—'
  if (ts.seconds !== undefined) {
    return new Date(Number(ts.seconds) * 1000).toLocaleString()
  }
  const d = new Date(ts)
  return isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function navigateToBuild(event: { data: { id: string } }) {
  router.push(`/agents/${props.agentId}/builds/${event.data.id}`)
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
          {{ b.type }}
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
      <Column header="Finished">
        <template #body="{ data: b }">
          {{ formatTimestamp(b.finishedAt) }}
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Type"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Status"><template #body><Skeleton width="5rem" /></template></Column>
      <Column header="Started"><template #body><Skeleton /></template></Column>
      <Column header="Finished"><template #body><Skeleton /></template></Column>
    </DataTable>
  </div>
</template>
