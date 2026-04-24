<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '@/api/client'

interface Webhook {
  path: string
  description: string
  verifyMode: string
  secret: string
  lastReceivedAt: string
}

const props = defineProps<{ agentId: string }>()

const webhooks = ref<Webhook[]>([])
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
  if (!ts) return 'Never'
  return new Date(ts).toLocaleString()
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
      <Column field="path" header="Path" />
      <Column field="description" header="Description" />
      <Column field="verifyMode" header="Verify Mode" />
      <Column header="Secret">
        <template #body="{ data: wh }">
          {{ wh.secret ? '••••••' : '—' }}
        </template>
      </Column>
      <Column header="Last Received">
        <template #body="{ data: wh }">
          {{ formatTimestamp(wh.lastReceivedAt) }}
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Path">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Verify Mode">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Secret">
        <template #body><Skeleton width="5rem" /></template>
      </Column>
      <Column header="Last Received">
        <template #body><Skeleton /></template>
      </Column>
    </DataTable>
  </div>
</template>
