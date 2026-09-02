<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'

interface Webhook {
  path: string
  description: string
  verifyMode: string
  secret: string
  lastReceivedAt: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const { t, formatDate } = useAirlockI18n()

const webhooks = ref<Webhook[]>([])
watch(webhooks, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)

function mapWebhook(raw: Record<string, any>): Webhook {
  return {
    path: raw.path ?? '',
    description: raw.description ?? '',
    verifyMode: raw.verifyMode ?? raw.verify_mode ?? '',
    secret: raw.secret ?? '',
    lastReceivedAt: raw.lastReceivedAt ?? raw.last_received_at ?? '',
  }
}

function formatTimestamp(ts: string): string {
  if (!ts) return t('agentConfig.webhooks.never')
  return formatDate(new Date(ts), {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
  })
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/webhooks`)
    webhooks.value = (data.webhooks || []).map(mapWebhook)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="webhooks" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('agentConfig.webhooks.empty') }}
        </div>
      </template>
      <Column field="path" :header="t('agentConfig.routes.path')" />
      <Column field="description" :header="t('agentConfig.common.description')" />
      <Column field="verifyMode" :header="t('agentConfig.webhooks.verifyMode')" />
      <Column :header="t('agentConfig.webhooks.secret')">
        <template #body="{ data: wh }">
          {{ wh.secret ? '••••••' : '-' }}
        </template>
      </Column>
      <Column :header="t('agentConfig.webhooks.lastReceived')">
        <template #body="{ data: wh }">
          {{ formatTimestamp(wh.lastReceivedAt) }}
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column :header="t('agentConfig.routes.path')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('agentConfig.webhooks.verifyMode')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('agentConfig.webhooks.secret')">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
      <Column :header="t('agentConfig.webhooks.lastReceived')">
        <template #body><Skeleton /></template>
      </Column>
    </DataTable>
  </div>
</template>
