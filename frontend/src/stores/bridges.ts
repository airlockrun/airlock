import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { BridgeInfo } from '@/gen/airlock/v1/types_pb'
import { ListBridgesResponseSchema } from '@/gen/airlock/v1/api_pb'
import { CreateManagedBotSessionResponseSchema } from '@/gen/airlock/v1/types_pb'

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

  async function createBridge(payload: { name: string; type: string; token: string; agentId?: string; isManager?: boolean }): Promise<BridgeInfo> {
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
      isSystem?: boolean
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

  // createManagedBotSession kicks off the Telegram Managed Bots flow:
  // server inserts a session row + returns the manager-bot deep link
  // the UI opens in a new tab. The eventual bridge appears via the
  // next fetchBridges() refresh (or, when WS is wired, a bridge.created
  // push). Returns the deep link so the caller can window.open it.
  async function createManagedBotSession(payload: { agentId?: string; isSystem: boolean; suggestedName?: string }): Promise<string> {
    const { data } = await api.post('/api/v1/bridges/managed/sessions', payload)
    const resp = fromJson(CreateManagedBotSessionResponseSchema, data)
    return resp.deepLink
  }

  return { bridges, loading, fetchBridges, createBridge, updateBridge, deleteBridge, createManagedBotSession }
})
