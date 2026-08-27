import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { AgentBuildInfo, JobInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListAgentBuildsResponseSchema,
  GetAgentBuildResponseSchema,
  ListJobsResponseSchema,
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

  async function fetchJobBlockers(agentId: string, buildId: string, cursor?: string): Promise<{ jobs: JobInfo[], nextCursor: string | null }> {
    const { data } = await api.get(`/api/v1/agents/${agentId}/builds/${buildId}/job-blockers`, {
      params: { limit: '50', ...(cursor ? { cursor } : {}) },
    })
    const response = fromJson(ListJobsResponseSchema, data)
    return { jobs: response.jobs, nextCursor: response.nextCursor || null }
  }

  async function cancelJobBlocker(jobId: string): Promise<void> {
    await api.delete(`/api/v1/jobs/${jobId}`)
  }

  return { builds, loading, fetchBuilds, fetchBuild, fetchJobBlockers, cancelJobBlocker, rollback }
})
