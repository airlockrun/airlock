import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentBuildInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListAgentBuildsResponseSchema,
  GetAgentBuildResponseSchema,
} from '@/gen/airlock/v1/api_pb'

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

  return { builds, loading, fetchBuilds, fetchBuild }
})
