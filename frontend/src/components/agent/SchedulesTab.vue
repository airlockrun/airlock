<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useToast } from 'primevue/usetoast'

interface Schedule {
  slug: string
  kind: string
  description: string
  schedule: string
  lastFiredAt: string
  nextFireAt: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const toast = useToast()

const schedules = ref<Schedule[]>([])
watch(schedules, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)

function mapSchedule(raw: Record<string, any>): Schedule {
  return {
    slug: raw.slug ?? '',
    kind: raw.kind ?? '',
    description: raw.description ?? '',
    schedule: raw.schedule ?? '',
    lastFiredAt: raw.lastFiredAt ?? raw.last_fired_at ?? '',
    nextFireAt: raw.nextFireAt ?? raw.next_fire_at ?? '',
  }
}

function formatTimestamp(ts: string): string {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

async function fireNow(s: Schedule) {
  try {
    await api.post(`/api/v1/agents/${props.agentId}/schedules/${s.slug}/fire`)
    toast.add({ severity: 'success', summary: 'Fired', detail: `Schedule "${s.slug}" fired successfully.`, life: 3000 })
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: `Failed to fire schedule "${s.slug}".`, life: 5000 })
  }
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/schedules`)
    schedules.value = (data.schedules || []).map(mapSchedule)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="schedules" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No schedules registered.
        </div>
      </template>
      <Column field="slug" header="Slug" />
      <Column header="Kind">
        <template #body="{ data: s }">
          <Tag :value="s.kind" :severity="s.kind === 'cron' ? 'info' : 'secondary'" />
        </template>
      </Column>
      <Column field="description" header="Description" />
      <Column header="Schedule">
        <template #body="{ data: s }">
          {{ s.schedule || '—' }}
        </template>
      </Column>
      <Column header="Next Fire">
        <template #body="{ data: s }">
          {{ formatTimestamp(s.nextFireAt) }}
        </template>
      </Column>
      <Column header="Last Fired">
        <template #body="{ data: s }">
          {{ formatTimestamp(s.lastFiredAt) }}
        </template>
      </Column>
      <Column header="Fire Now">
        <template #body="{ data: s }">
          <Button label="Fire Now" size="small" severity="warn" outlined @click="fireNow(s)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Slug">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Kind">
        <template #body><Skeleton width="3rem" /></template>
      </Column>
      <Column header="Schedule">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Next Fire">
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
