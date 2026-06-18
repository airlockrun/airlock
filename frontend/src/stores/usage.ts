import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { GetUsageResponse } from '@/gen/airlock/v1/api_pb'
import { GetUsageResponseSchema } from '@/gen/airlock/v1/api_pb'

// Admin LLM spend-ledger rollups over a rolling window (days; 0 = all time).
export const useUsageStore = defineStore('usage', () => {
  const report = ref<GetUsageResponse | null>(null)
  const loading = ref(false)

  async function fetchUsage(days: number) {
    loading.value = true
    try {
      const { data } = await api.get(`/api/v1/usage?days=${days}`)
      report.value = fromJson(GetUsageResponseSchema, data)
    } finally {
      loading.value = false
    }
  }

  return { report, loading, fetchUsage }
})
