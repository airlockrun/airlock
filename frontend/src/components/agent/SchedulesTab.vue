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
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const toast = useToast()
const router = useRouter()
const { t, formatDate } = useAirlockI18n()

const schedules = ref<ScheduleInfo[]>([])
watch(schedules, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)
const firing = ref<string | null>(null)

function formatTimestamp(ts?: Timestamp): string {
  return ts ? formatDate(timestampDate(ts), {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  }) : '-'
}

async function fireNow(s: ScheduleInfo) {
  firing.value = s.slug
  try {
    const { data } = await api.post(`/api/v1/agents/${props.agentId}/schedules/${s.slug}/fire`)
    const response = fromJson(FireScheduleResponseSchema, data)
    toast.add({
      severity: 'success',
      summary: t('operations.schedule.jobQueued'),
      detail: t('operations.schedule.jobQueuedDetail', { slug: s.slug }),
      life: 3000,
    })
    await router.push({ name: 'job-detail', params: { id: props.agentId, jobId: response.jobId } })
  } catch {
    toast.add({
      severity: 'error',
      summary: t('operations.common.error'),
      detail: t('operations.schedule.fireFailed', { slug: s.slug }),
      life: 5000,
    })
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
          {{ t('operations.schedule.empty') }}
        </div>
      </template>
      <Column field="slug" :header="t('operations.schedule.slug')" />
      <Column field="description" :header="t('operations.schedule.description')" />
      <Column :header="t('operations.schedule.job')">
        <template #body="{ data: s }">
          <code>{{ s.handlerName }}@v{{ s.handlerVersion }}</code>
        </template>
      </Column>
      <Column :header="t('operations.schedule.schedule')">
        <template #body="{ data: s }">
          {{ s.schedule || '-' }}
        </template>
      </Column>
      <Column :header="t('operations.schedule.nextFire')">
        <template #body="{ data: s }">
          {{ formatTimestamp(s.nextFireAt) }}
        </template>
      </Column>
      <Column :header="t('operations.schedule.lastFired')">
        <template #body="{ data: s }">
          {{ formatTimestamp(s.lastFiredAt) }}
        </template>
      </Column>
      <Column :header="t('operations.schedule.fireNow')">
        <template #body="{ data: s }">
          <Button :label="t('operations.schedule.fireNow')" size="small" severity="warn" outlined :disabled="!s.enabled" :loading="firing === s.slug" @click="fireNow(s)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column :header="t('operations.schedule.slug')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('operations.schedule.job')">
        <template #body><Skeleton width="8rem" /></template>
      </Column>
      <Column :header="t('operations.schedule.schedule')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('operations.schedule.nextFire')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('operations.schedule.lastFired')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('operations.schedule.fireNow')">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
    </DataTable>
  </div>
</template>
