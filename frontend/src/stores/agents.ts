import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import type { AgentModelConfig } from '@/gen/airlock/v1/api_pb'
import {
  ListAgentsResponseSchema,
  CreateAgentResponseSchema,
  CloneAgentResponseSchema,
  TransferAgentOwnershipResponseSchema,
  UpdateAgentResponseSchema,
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

  async function createAgent(
    name: string,
    slug: string,
    buildModel: string,
    buildProviderId: string,
    execModel: string,
    execProviderId: string,
    instructions?: string,
    git?: { remoteUrl: string; credentialId: string; defaultBranch?: string },
  ) {
    const payload: Record<string, string> = {
      name,
      slug,
      buildModel,
      buildProviderId,
      execModel,
      execProviderId,
    }
    if (instructions) payload.instructions = instructions
    if (git?.remoteUrl) {
      payload.gitRemoteUrl = git.remoteUrl
      payload.gitCredentialId = git.credentialId
      if (git.defaultBranch) payload.gitDefaultBranch = git.defaultBranch
    }
    const { data } = await api.post('/api/v1/agents', payload)
    const agent = fromJson(CreateAgentResponseSchema, data).agent!
    agents.value.unshift(agent)
    return agent
  }

  async function deleteAgent(id: string) {
    await api.delete(`/api/v1/agents/${id}`)
    agents.value = agents.value.filter((a) => a.id !== id)
  }

  // Rename name and/or slug. Only the changed fields need be passed
  // (UpdateAgentRequest treats them as optional). Replaces the cached
  // row so the sidebar / vanity-URL layer pick up the new slug at once.
  async function renameAgent(id: string, name: string, slug: string) {
    const { data } = await api.patch(`/api/v1/agents/${id}`, { name, slug })
    const updated = fromJson(UpdateAgentResponseSchema, data).agent!
    const i = agents.value.findIndex((a) => a.id === id)
    if (i !== -1) agents.value[i] = updated
    return updated
  }

  // Clone forks an agent's code into a new agent owned by the caller. The new
  // agent starts building (status=draft/building) and appears at the top.
  async function cloneAgent(id: string, name: string, slug: string) {
    const { data } = await api.post(`/api/v1/agents/${id}/clone`, { name, slug })
    const agent = fromJson(CloneAgentResponseSchema, data).agent!
    agents.value.unshift(agent)
    return agent
  }

  // Transfer ownership to another tenant user. The caller (old owner) loses
  // access, so drop the row from the local list after a successful transfer.
  async function transferOwnership(id: string, newOwnerId: string) {
    const { data } = await api.post(`/api/v1/agents/${id}/transfer`, { newOwnerId })
    const updated = fromJson(TransferAgentOwnershipResponseSchema, data).agent!
    agents.value = agents.value.filter((a) => a.id !== id)
    return updated
  }

  async function stopAgent(id: string) {
    await api.post(`/api/v1/agents/${id}/stop`, {})
    const agent = agents.value.find((a) => a.id === id)
    if (agent) agent.status = 'stopped'
  }

  async function startAgent(id: string) {
    await api.post(`/api/v1/agents/${id}/start`, {})
    const agent = agents.value.find((a) => a.id === id)
    if (agent) agent.status = 'active'
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
    cloneAgent,
    transferOwnership,
    deleteAgent,
    renameAgent,
    stopAgent,
    startAgent,
    upgradeAgent,
    fetchModelConfig,
    updateModelConfig,
  }
})
