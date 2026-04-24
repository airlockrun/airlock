import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import type { AgentModelConfig } from '@/gen/airlock/v1/api_pb'
import {
  ListAgentsResponseSchema,
  CreateAgentResponseSchema,
  GetAgentModelConfigResponseSchema,
  UpdateAgentModelConfigRequestSchema,
  UpdateAgentModelConfigResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useAgentsStore = defineStore('agents', () => {
  const agents = ref<AgentInfo[]>([])
  const loading = ref(false)

  async function fetchAgents() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/agents')
      agents.value = fromJson(ListAgentsResponseSchema, data).agents
    } finally {
      loading.value = false
    }
  }

  async function createAgent(name: string, slug: string, buildModel: string, execModel: string, instructions?: string) {
    const payload: Record<string, string> = { name, slug, buildModel, execModel }
    if (instructions) payload.instructions = instructions
    const { data } = await api.post('/api/v1/agents', payload)
    const agent = fromJson(CreateAgentResponseSchema, data).agent!
    agents.value.unshift(agent)
    return agent
  }

  async function deleteAgent(id: string) {
    await api.delete(`/api/v1/agents/${id}`)
    agents.value = agents.value.filter((a) => a.id !== id)
  }

  async function stopAgent(id: string) {
    await api.post(`/api/v1/agents/${id}/stop`, {})
    const agent = agents.value.find((a) => a.id === id)
    if (agent) agent.status = 'stopped'
  }

  async function upgradeAgent(id: string) {
    await api.post(`/api/v1/agents/${id}/upgrade`, {})
    const agent = agents.value.find((a) => a.id === id)
    if (agent) agent.upgradeStatus = 'queued'
  }

  async function fetchModelConfig(id: string): Promise<AgentModelConfig> {
    const { data } = await api.get(`/api/v1/agents/${id}/models`)
    const resp = fromJson(GetAgentModelConfigResponseSchema, data)
    return resp.config!
  }

  async function updateModelConfig(id: string, config: AgentModelConfig): Promise<AgentModelConfig> {
    const body = toJson(UpdateAgentModelConfigRequestSchema, { $typeName: 'airlock.v1.UpdateAgentModelConfigRequest', config })
    const { data } = await api.put(`/api/v1/agents/${id}/models`, body)
    const resp = fromJson(UpdateAgentModelConfigResponseSchema, data)
    return resp.config!
  }

  return {
    agents,
    loading,
    fetchAgents,
    createAgent,
    deleteAgent,
    stopAgent,
    upgradeAgent,
    fetchModelConfig,
    updateModelConfig,
  }
})
