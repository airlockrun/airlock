import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { JobAttemptInfo, JobInfo } from '@/gen/airlock/v1/types_pb'
import type { JobLifecycleEvent, JobProgressEvent } from '@/gen/airlock/v1/realtime_pb'
import {
  GetJobResponseSchema,
  ListJobsResponseSchema,
  RetryJobResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useJobsStore = defineStore('jobs', () => {
  const jobs = ref<JobInfo[]>([])
  const listAgentId = ref('')
  const nextCursor = ref<string | null>(null)
  const loading = ref(false)
  const job = ref<JobInfo | null>(null)
  const attempts = ref<JobAttemptInfo[]>([])
  const detailLoading = ref(false)
  let listRequest = 0

  function beginAgentList(agentId: string) {
    if (listAgentId.value === agentId) return
    listRequest++
    listAgentId.value = agentId
    jobs.value = []
    nextCursor.value = null
    loading.value = false
  }

  function preserveDetailPayload(target: JobInfo, summary: JobInfo): JobInfo {
    const inputJson = target.inputJson
    const outputJson = target.outputJson
    Object.assign(target, summary)
    target.inputJson = inputJson
    target.outputJson = outputJson
    return target
  }

  function mergeListJob(incoming: JobInfo): boolean {
    if (incoming.agentId !== listAgentId.value) return false
    const index = jobs.value.findIndex((item) => item.id === incoming.id)
    if (index === -1) {
      jobs.value.unshift(incoming)
      return true
    }
    if (incoming.stateVersion > jobs.value[index].stateVersion) {
      jobs.value[index] = incoming
      return true
    }
    return false
  }

  function mergeLifecycle(event: JobLifecycleEvent): boolean {
    const summary = event.summary
    if (!summary) return false

    let merged = mergeListJob(summary)
    if (job.value?.id === summary.id && summary.stateVersion > job.value.stateVersion) {
      preserveDetailPayload(job.value, summary)
      merged = true
    }
    return merged
  }

  function mergeProgress(event: JobProgressEvent): boolean {
    if (event.agentId !== listAgentId.value && event.jobId !== job.value?.id) return false
    let merged = false
    const index = jobs.value.findIndex((item) => item.id === event.jobId)
    if (index !== -1 && event.stateVersion > jobs.value[index].stateVersion) {
      jobs.value[index].progress = event.progress
      jobs.value[index].stateVersion = event.stateVersion
      merged = true
    }
    if (job.value?.id === event.jobId && event.stateVersion > job.value.stateVersion) {
      job.value.progress = event.progress
      job.value.stateVersion = event.stateVersion
      merged = true
    }
    return merged
  }

  async function fetchFirstPage(agentId: string) {
    beginAgentList(agentId)
    const request = ++listRequest
    const idsAtRequest = new Set(jobs.value.map((item) => item.id))
    loading.value = true
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}/jobs`, {
        params: { limit: '20' },
      })
      if (request !== listRequest || listAgentId.value !== agentId) return
      const response = fromJson(ListJobsResponseSchema, data)
      const current = new Map(jobs.value.map((item) => [item.id, item]))
      const page = response.jobs.map((item) => {
        const existing = current.get(item.id)
        return existing && existing.stateVersion > item.stateVersion ? existing : item
      })
      const arrivedDuringRequest = jobs.value.filter(
        (item) => !idsAtRequest.has(item.id) && !page.some((listed) => listed.id === item.id),
      )
      jobs.value = [...arrivedDuringRequest, ...page]
      nextCursor.value = response.nextCursor || null
    } finally {
      if (request === listRequest) loading.value = false
    }
  }

  async function loadMore(agentId: string) {
    const cursor = nextCursor.value
    if (!cursor || loading.value || listAgentId.value !== agentId) return
    const request = ++listRequest
    loading.value = true
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}/jobs`, {
        params: { limit: '20', cursor },
      })
      const response = fromJson(ListJobsResponseSchema, data)
      if (request !== listRequest || listAgentId.value !== agentId || nextCursor.value !== cursor) return
      for (const incoming of response.jobs) {
        const index = jobs.value.findIndex((item) => item.id === incoming.id)
        if (index === -1) {
          jobs.value.push(incoming)
        } else if (incoming.stateVersion > jobs.value[index].stateVersion) {
          jobs.value[index] = incoming
        }
      }
      nextCursor.value = response.nextCursor || null
    } finally {
      if (request === listRequest) loading.value = false
    }
  }

  async function fetchJob(jobId: string) {
    detailLoading.value = true
    try {
      const { data } = await api.get(`/api/v1/jobs/${jobId}`)
      const response = fromJson(GetJobResponseSchema, data)
      if (!response.job) throw new Error('job response did not include a job')

      const incoming = response.job
      const currentDetail = job.value?.id === jobId ? job.value : null
      const currentSummary = jobs.value.find((item) => item.id === jobId)
      const current = currentDetail && (!currentSummary || currentDetail.stateVersion >= currentSummary.stateVersion)
        ? currentDetail
        : currentSummary
      if (current && current.stateVersion > incoming.stateVersion) {
        preserveDetailPayload(incoming, current)
      }
      job.value = incoming
      attempts.value = [...response.attempts]
      mergeListJob(incoming)
      return { job: incoming, attempts: attempts.value }
    } finally {
      detailLoading.value = false
    }
  }

  async function cancel(jobId: string) {
    await api.delete(`/api/v1/jobs/${jobId}`)
    return (await fetchJob(jobId)).job
  }

  async function retry(jobId: string) {
    const { data } = await api.post(`/api/v1/jobs/${jobId}/retry`)
    const response = fromJson(RetryJobResponseSchema, data)
    if (!response.job) throw new Error('retry response did not include a job')
    const retried = response.job
    job.value = retried
    mergeListJob(retried)
    return retried
  }

  function clearDetail(jobId: string) {
    if (job.value?.id !== jobId) return
    job.value = null
    attempts.value = []
  }

  return {
    jobs,
    listAgentId,
    nextCursor,
    loading,
    job,
    attempts,
    detailLoading,
    beginAgentList,
    fetchFirstPage,
    loadMore,
    fetchJob,
    cancel,
    retry,
    mergeLifecycle,
    mergeProgress,
    clearDetail,
  }
})
