<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '@/api/client'
import { useToast } from 'primevue/usetoast'

interface Cron {
  name: string
  description: string
  schedule: string
  lastFiredAt: string
}

const props = defineProps<{ agentId: string }>()
const toast = useToast()

const crons = ref<Cron[]>([])
const loading = ref(true)

function mapCron(raw: Record<string, any>): Cron {
  return {
    name: raw.name ?? '',
    description: raw.description ?? '',
    schedule: raw.schedule ?? '',
    lastFiredAt: raw.lastFiredAt ?? raw.last_fired_at ?? '',
  }
}

function formatTimestamp(ts: string): string {
  if (!ts) return 'Never'
  return new Date(ts).toLocaleString()
}

async function fireNow(cron: Cron) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/crons/${cron.name}/fire`)
    toast.add({ severity: 'success', summary: 'Fired', detail: `Cron "${cron.name}" fired successfully.`, life: 3000 })
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: `Failed to fire cron "${cron.name}".`, life: 5000 })
  }
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/crons`)
    crons.value = (data.crons || []).map(mapCron)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="crons" stripedRows>
      <Column field="name" header="Name" />
      <Column field="description" header="Description" />
      <Column field="schedule" header="Schedule" />
      <Column header="Last Fired">
        <template #body="{ data: cron }">
          {{ formatTimestamp(cron.lastFiredAt) }}
        </template>
      </Column>
      <Column header="Fire Now">
        <template #body="{ data: cron }">
          <Button label="Fire Now" size="small" severity="warn" outlined @click="fireNow(cron)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Name">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Schedule">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Last Fired">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Fire Now">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
    </DataTable>
  </div>
</template>
