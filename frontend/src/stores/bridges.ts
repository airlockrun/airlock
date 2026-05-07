import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { BridgeInfo } from '@/gen/airlock/v1/types_pb'
import { ListBridgesResponseSchema } from '@/gen/airlock/v1/api_pb'

export const useBridgesStore = defineStore('bridges', () => {
  const bridges = ref<BridgeInfo[]>([])
  const loading = ref(false)

  async function fetchBridges() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/bridges')
      bridges.value = fromJson(ListBridgesResponseSchema, data).bridges
    } finally {
      loading.value = false
    }
  }

  async function createBridge(payload: { name: string; type: string; token: string; agentId?: string }): Promise<BridgeInfo> {
    const { data } = await api.post('/api/v1/bridges', payload)
    // createBridge returns a single BridgeInfo, not wrapped in a response message
    const created = fromJson(ListBridgesResponseSchema, { bridges: [data] }).bridges[0]
    bridges.value.unshift(created)
    return created
  }

  async function updateBridge(
    id: string,
    payload: {
      agentId: string
      settings?: {
        allowPublicDms: boolean
        publicSessionTtlSeconds: number
        publicSessionMode: 'session' | 'one_shot'
        publicPromptTimeoutSeconds: number
      }
    },
  ) {
    const { data } = await api.put(`/api/v1/bridges/${id}`, payload)
    // Returns a bare BridgeInfo — same ghetto-unwrap trick as createBridge.
    const updated = fromJson(ListBridgesResponseSchema, { bridges: [data] }).bridges[0]
    const idx = bridges.value.findIndex((b) => b.id === id)
    if (idx !== -1) bridges.value[idx] = updated
  }

  async function deleteBridge(id: string) {
    await api.delete(`/api/v1/bridges/${id}`)
    bridges.value = bridges.value.filter((b) => b.id !== id)
  }

  return { bridges, loading, fetchBridges, createBridge, updateBridge, deleteBridge }
})
