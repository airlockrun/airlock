<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { useConversationFeedStore } from '@/stores/conversationFeed'
import {
  type SystemRunInfo,
  ListSystemRunsResponseSchema,
} from '@/gen/airlock/v1/system_agent_pb'
import { useAirlockI18n } from '@/i18n'

const router = useRouter()
const toast = useToast()
const { t, formatDate, formatNumber } = useAirlockI18n()
const feed = useConversationFeedStore()

const runs = ref<SystemRunInfo[]>([])
const nextCursor = ref<string>('')
const loading = ref(false)
const loadingMore = ref(false)

async function fetchRuns(cursor?: string) {
  const params = cursor ? { cursor } : {}
  const { data } = await api.get('/api/v1/system/runs', { params })
  return fromJson(ListSystemRunsResponseSchema, data)
}

async function load() {
  loading.value = true
  try {
    // The feed backs the sidebar; refresh it so the unified left pane
    // reflects whatever the operator did since they last opened the
    // system view.
    void feed.loadFirst()
    const resp = await fetchRuns()
    runs.value = [...resp.runs]
    nextCursor.value = resp.nextCursor
  } catch (err: any) {
    toast.add({ severity: 'error', summary: t('chat.error.loadRunsFailed'), detail: err?.message, life: 5000 })
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  if (!nextCursor.value || loadingMore.value) return
  loadingMore.value = true
  try {
    const resp = await fetchRuns(nextCursor.value)
    runs.value.push(...resp.runs)
    nextCursor.value = resp.nextCursor
  } catch (err: any) {
    toast.add({ severity: 'error', summary: t('chat.error.loadMoreFailed'), detail: err?.message, life: 5000 })
  } finally {
    loadingMore.value = false
  }
}

function openNewChat() {
  // Route to the empty-conversation view; the row is minted server-side
  // on the first send (mirrors agent chat).
  router.push('/system/chat')
}

function fmtTime(ts?: { seconds?: bigint }): string {
  if (!ts?.seconds) return ''
  return formatDate(new Date(Number(ts.seconds) * 1000), {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
  })
}

function cost(v: number): string {
  if (!v) return '-'
  const fractionDigits = v < 0.01 ? 4 : 2
  return formatNumber(v, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  })
}

function snippet(s: string): string {
  const t = (s || '').trim()
  if (!t) return '-'
  return t.length > 60 ? t.slice(0, 60) + '…' : t
}

function statusSeverity(status: string): string {
  switch (status) {
    case 'running':
    case 'suspended':
      return 'info'
    case 'complete':
      return 'success'
    case 'error':
      return 'danger'
    case 'cancelled':
      return 'warn'
    default:
      return 'secondary'
  }
}

function statusLabel(status: string): string {
  const labels: Record<string, Parameters<typeof t>[0]> = {
    running: 'chat.systemAgent.status.running',
    suspended: 'chat.systemAgent.status.suspended',
    complete: 'chat.systemAgent.status.complete',
    error: 'chat.systemAgent.status.error',
    cancelled: 'chat.systemAgent.status.cancelled',
  }
  const id = labels[status]
  return id ? t(id) : status
}

function triggerLabel(trigger: string): string {
  const labels: Record<string, Parameters<typeof t>[0]> = {
    prompt: 'chat.systemAgent.trigger.prompt',
    bridge: 'chat.systemAgent.trigger.bridge',
    event: 'chat.systemAgent.trigger.event',
  }
  const id = labels[trigger]
  return id ? t(id) : trigger
}

onMounted(load)
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.75rem">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <h1 style="margin: 0; font-size: 1.875rem; font-weight: 700; line-height: 1.2">
            <span style="margin-right: 0.4rem">⚙️</span>{{ t('chat.systemAgent.assistantName') }}
          </h1>
          <Tag :value="t('chat.systemAgent.operator')" severity="info" />
        </div>
        <p style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">
          {{ t('chat.systemAgent.assistantDescription') }}
        </p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button :label="t('chat.systemAgent.chat')" icon="pi pi-comments" @click="openNewChat" />
      </div>
    </div>

    <Card>
      <template #title>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-history" />
          <span>{{ t('chat.systemAgent.runs') }}</span>
        </div>
      </template>
      <template #content>
        <div v-if="loading" style="display: flex; flex-direction: column; gap: 0.5rem">
          <Skeleton v-for="i in 4" :key="i" width="100%" height="2.5rem" />
        </div>

        <div v-else-if="runs.length === 0" style="text-align: center; padding: 1.5rem 0">
          <i class="pi pi-history" style="font-size: 2rem; color: var(--p-surface-400); margin-bottom: 0.5rem" />
          <p style="color: var(--p-text-muted-color); margin: 0.5rem 0 1rem">{{ t('chat.systemAgent.noRuns') }}</p>
          <Button :label="t('chat.systemAgent.chat')" icon="pi pi-comments" @click="openNewChat" />
        </div>

        <div v-else>
          <DataTable
            :value="runs"
            dataKey="id"
          >
            <Column :header="t('chat.systemAgent.column.message')">
              <template #body="{ data }">
                <span :title="data.messagePreview" style="color: var(--p-text-muted-color); font-size: 0.85rem">{{ snippet(data.messagePreview) }}</span>
                <div v-if="data.errorMessage" style="font-size: 0.8rem; color: var(--p-red-500)">{{ data.errorMessage }}</div>
              </template>
            </Column>
            <Column field="status" :header="t('chat.systemAgent.column.status')" style="width: 8rem">
              <template #body="{ data }">
                <Tag :value="statusLabel(data.status)" :severity="statusSeverity(data.status)" />
              </template>
            </Column>
            <Column field="triggerType" :header="t('chat.systemAgent.column.trigger')" style="width: 7rem">
              <template #body="{ data }">
                <Tag :value="triggerLabel(data.triggerType)" severity="secondary" />
              </template>
            </Column>
            <Column field="startedAt" :header="t('chat.systemAgent.column.started')" style="width: 14rem">
              <template #body="{ data }">
                <span style="color: var(--p-text-muted-color); font-size: 0.875rem">{{ fmtTime(data.startedAt) }}</span>
              </template>
            </Column>
            <Column :header="t('chat.systemAgent.column.cost')" style="width: 7rem">
              <template #body="{ data }">
                <span style="color: var(--p-text-muted-color); font-size: 0.875rem">{{ cost(data.llmCostEstimate) }}</span>
              </template>
            </Column>
          </DataTable>

          <div v-if="nextCursor" style="display: flex; justify-content: center; margin-top: 1rem">
            <Button :label="t('chat.systemAgent.loadMore')" :loading="loadingMore" outlined @click="loadMore" />
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
