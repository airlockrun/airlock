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

const router = useRouter()
const toast = useToast()
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
    toast.add({ severity: 'error', summary: 'Failed to load runs', detail: err?.message, life: 5000 })
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
    toast.add({ severity: 'error', summary: 'Failed to load more', detail: err?.message, life: 5000 })
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
  return new Date(Number(ts.seconds) * 1000).toLocaleString()
}

function cost(v: number): string {
  if (!v) return '—'
  return '$' + v.toFixed(v < 0.01 ? 4 : 2)
}

function snippet(s: string): string {
  const t = (s || '').trim()
  if (!t) return '—'
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

onMounted(load)
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.75rem">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <h1 style="margin: 0; font-size: 1.875rem; font-weight: 700; line-height: 1.2">
            <span style="margin-right: 0.4rem">⚙️</span>System Agent
          </h1>
          <Tag value="Operator" severity="info" />
        </div>
        <p style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">
          In-airlock chat for managing agents, bridges, connections, members, and runs through your own permissions.
        </p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button label="Chat" icon="pi pi-comments" @click="openNewChat" />
      </div>
    </div>

    <Card>
      <template #title>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-history" />
          <span>Runs</span>
        </div>
      </template>
      <template #content>
        <div v-if="loading" style="display: flex; flex-direction: column; gap: 0.5rem">
          <Skeleton v-for="i in 4" :key="i" width="100%" height="2.5rem" />
        </div>

        <div v-else-if="runs.length === 0" style="text-align: center; padding: 1.5rem 0">
          <i class="pi pi-history" style="font-size: 2rem; color: var(--p-surface-400); margin-bottom: 0.5rem" />
          <p style="color: var(--p-text-muted-color); margin: 0.5rem 0 1rem">No runs yet. Start a chat to do something.</p>
          <Button label="Chat" icon="pi pi-comments" @click="openNewChat" />
        </div>

        <div v-else>
          <DataTable
            :value="runs"
            dataKey="id"
          >
            <Column header="Message">
              <template #body="{ data }">
                <span :title="data.messagePreview" style="color: var(--p-text-muted-color); font-size: 0.85rem">{{ snippet(data.messagePreview) }}</span>
                <div v-if="data.errorMessage" style="font-size: 0.8rem; color: var(--p-red-500)">{{ data.errorMessage }}</div>
              </template>
            </Column>
            <Column field="status" header="Status" style="width: 8rem">
              <template #body="{ data }">
                <Tag :value="data.status" :severity="statusSeverity(data.status)" />
              </template>
            </Column>
            <Column field="triggerType" header="Trigger" style="width: 7rem">
              <template #body="{ data }">
                <Tag :value="data.triggerType" severity="secondary" />
              </template>
            </Column>
            <Column field="startedAt" header="Started" style="width: 14rem">
              <template #body="{ data }">
                <span style="color: var(--p-text-muted-color); font-size: 0.875rem">{{ fmtTime(data.startedAt) }}</span>
              </template>
            </Column>
            <Column header="Cost" style="width: 7rem">
              <template #body="{ data }">
                <span style="color: var(--p-text-muted-color); font-size: 0.875rem">{{ cost(data.llmCostEstimate) }}</span>
              </template>
            </Column>
          </DataTable>

          <div v-if="nextCursor" style="display: flex; justify-content: center; margin-top: 1rem">
            <Button label="Load more" :loading="loadingMore" outlined @click="loadMore" />
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
