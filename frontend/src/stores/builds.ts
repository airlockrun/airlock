import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentBuildInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListAgentBuildsResponseSchema,
  GetAgentBuildResponseSchema,
  RollbackBuildRequestSchema,
} from '@/gen/airlock/v1/api_pb'
import { create } from '@bufbuild/protobuf'

export const useBuildsStore = defineStore('builds', () => {
  const builds = ref<AgentBuildInfo[]>([])
  const loading = ref(false)

  async function fetchBuilds(agentId: string) {
    loading.value = true
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}/builds`)
      builds.value = fromJson(ListAgentBuildsResponseSchema, data).builds
    } finally {
      loading.value = false
    }
  }

  async function fetchBuild(agentId: string, buildId: string): Promise<AgentBuildInfo> {
    const { data } = await api.get(`/api/v1/agents/${agentId}/builds/${buildId}`)
    return fromJson(GetAgentBuildResponseSchema, data).build!
  }

  async function rollback(agentId: string, buildId: string): Promise<void> {
    const req = create(RollbackBuildRequestSchema, { buildId })
    await api.post(`/api/v1/agents/${agentId}/rollback`, toJson(RollbackBuildRequestSchema, req))
  }

  return { builds, loading, fetchBuilds, fetchBuild, rollback }
})
