import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import { ListAgentsResponseSchema } from '@/gen/airlock/v1/api_pb'

// Admin governance over every agent in the tenant — the surface behind
// Settings → Manage agents. Distinct from the agents store (the caller's own
// working set) so the main page never loads other people's agents.
export const useAgentGovernanceStore = defineStore('agentGovernance', () => {
  const agents = ref<AgentInfo[]>([])
  const loading = ref(false)

  async function fetchAll() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/agents/all')
      agents.value = fromJson(ListAgentsResponseSchema, data).agents
    } finally {
      loading.value = false
    }
  }

  function patch(id: string, fields: Partial<AgentInfo>) {
    const a = agents.value.find((x) => x.id === id)
    if (a) Object.assign(a, fields)
  }

  async function stop(id: string) {
    await api.post(`/api/v1/agents/${id}/stop`, {})
    patch(id, { status: 'stopped' })
  }

  async function start(id: string) {
    await api.post(`/api/v1/agents/${id}/start`, {})
    patch(id, { status: 'active' })
  }

  async function remove(id: string) {
    await api.delete(`/api/v1/agents/${id}`)
    agents.value = agents.value.filter((a) => a.id !== id)
  }

  // Claim grants the calling admin an admin membership on an agent they don't
  // belong to (the tenant-admin self-add escape). Afterwards they can open and
  // operate it through the normal agent surface.
  async function claim(id: string, selfUserId: string) {
    await api.post(`/api/v1/agents/${id}/members`, { userId: selfUserId, role: 'admin' })
    patch(id, { yourAccess: 'admin', isOwner: false })
  }

  return { agents, loading, fetchAll, stop, start, remove, claim }
})
