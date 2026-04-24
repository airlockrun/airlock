import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { RunInfo, AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import { ListRunsResponseSchema, GetRunResponseSchema } from '@/gen/airlock/v1/api_pb'

export const useRunsStore = defineStore('runs', () => {
  const runs = ref<RunInfo[]>([])
  const nextCursor = ref<string | null>(null)
  const loading = ref(false)

  async function fetchRuns(agentId: string, cursor?: string) {
    loading.value = true
    try {
      const params: Record<string, string> = { limit: '20' }
      if (cursor) params.cursor = cursor
      const { data } = await api.get(`/api/v1/agents/${agentId}/runs`, { params })
      const response = fromJson(ListRunsResponseSchema, data)
      if (cursor) {
        runs.value = [...runs.value, ...response.runs]
      } else {
        runs.value = response.runs
      }
      nextCursor.value = response.nextCursor || null
    } finally {
      loading.value = false
    }
  }

  async function fetchRun(runId: string): Promise<{ run: RunInfo; messages: AgentMessageInfo[] }> {
    const { data } = await api.get(`/api/v1/runs/${runId}`)
    const response = fromJson(GetRunResponseSchema, data)
    return { run: response.run!, messages: [...response.messages] }
  }

  return { runs, nextCursor, loading, fetchRuns, fetchRun }
})
