<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import type { Timestamp } from '@bufbuild/protobuf/wkt'
import { useRouter } from 'vue-router'
import api from '@/api/client'
import { useToast } from 'primevue/usetoast'
import type { ScheduleInfo } from '@/gen/airlock/v1/types_pb'
import { FireScheduleResponseSchema, ListSchedulesResponseSchema } from '@/gen/airlock/v1/api_pb'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const toast = useToast()
const router = useRouter()

const schedules = ref<ScheduleInfo[]>([])
watch(schedules, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)
const firing = ref<string | null>(null)

function formatTimestamp(ts?: Timestamp): string {
  return ts ? timestampDate(ts).toLocaleString() : '-'
}

async function fireNow(s: ScheduleInfo) {
  firing.value = s.slug
  try {
    const { data } = await api.post(`/api/v1/agents/${props.agentId}/schedules/${s.slug}/fire`)
    const response = fromJson(FireScheduleResponseSchema, data)
    toast.add({ severity: 'success', summary: 'Job queued', detail: `Cron "${s.slug}" created a background job.`, life: 3000 })
    await router.push({ name: 'job-detail', params: { id: props.agentId, jobId: response.jobId } })
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: `Failed to fire schedule "${s.slug}".`, life: 5000 })
  } finally {
    firing.value = null
  }
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/schedules`)
    schedules.value = fromJson(ListSchedulesResponseSchema, data).schedules
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
      <Column field="description" header="Description" />
      <Column header="Job">
        <template #body="{ data: s }">
          <code>{{ s.handlerName }}@v{{ s.handlerVersion }}</code>
        </template>
      </Column>
      <Column header="Schedule">
        <template #body="{ data: s }">
          {{ s.schedule || '-' }}
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
          <Button label="Fire Now" size="small" severity="warn" outlined :disabled="!s.enabled" :loading="firing === s.slug" @click="fireNow(s)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Slug">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Job">
        <template #body><Skeleton width="8rem" /></template>
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
