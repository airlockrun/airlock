import { computed, ref } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { CandidateInfo, NeedInfo, OwnedResourceInfo } from '@/gen/airlock/v1/api_pb'
import {
  ListCandidatesResponseSchema,
  ListNeedsResponseSchema,
  ListOwnedResourcesResponseSchema,
  StartAuthorizationForNeedResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import { canonicalAgentURL } from '@/composables/useOAuth'
import { serializeAuthorizationRequest } from '@/utils/resourceRequests'

export interface AuthorizationTarget {
  resourceId: string
  displayName: string
  createNew: boolean
}

export function useAgentResources(agentId: string) {
  const needs = ref<NeedInfo[]>([])
  const inventory = ref<OwnedResourceInfo[]>([])
  const loading = ref(false)
  const error = ref('')

  const inventoryById = computed(() => new Map(inventory.value.map((resource) => [resource.id, resource])))

  async function refresh() {
    loading.value = true
    error.value = ''
    try {
      const [needsResponse, resourcesResponse] = await Promise.all([
        api.get(`/api/v1/agents/${agentId}/needs`),
        api.get('/api/v1/resources'),
      ])
      needs.value = fromJson(ListNeedsResponseSchema, needsResponse.data).needs
      inventory.value = fromJson(ListOwnedResourcesResponseSchema, resourcesResponse.data).resources
    } catch (cause: any) {
      error.value = cause?.response?.data?.error || cause?.message || 'Failed to load resources'
      throw cause
    } finally {
      loading.value = false
    }
  }

  function resourceFor(need: NeedInfo): OwnedResourceInfo | undefined {
    return need.boundResourceId ? inventoryById.value.get(need.boundResourceId) : undefined
  }

  async function candidatesFor(need: NeedInfo): Promise<CandidateInfo[]> {
    const { data } = await api.get(
      `/api/v1/agents/${agentId}/needs/${need.type}/${encodeURIComponent(need.slug)}/candidates`,
    )
    return fromJson(ListCandidatesResponseSchema, data).candidates
  }

  async function bind(need: NeedInfo, resourceId: string) {
    await api.post(`/api/v1/agents/${agentId}/needs/${need.type}/${encodeURIComponent(need.slug)}/bind`, {
      resourceId,
    })
    await refresh()
  }

  async function unbind(need: NeedInfo) {
    await api.delete(`/api/v1/agents/${agentId}/needs/${need.type}/${encodeURIComponent(need.slug)}/bind`)
    await refresh()
  }

  async function createForNeed(need: NeedInfo, displayName: string): Promise<string> {
    const { data } = await api.post(
      `/api/v1/agents/${agentId}/needs/${need.type}/${encodeURIComponent(need.slug)}/create`,
      { displayName },
    )
    await refresh()
    return data.resourceId ?? ''
  }

  async function startAuthorization(need: NeedInfo, target: AuthorizationTarget): Promise<never> {
    const { data } = await api.post('/api/v1/resource-authorizations/start', serializeAuthorizationRequest({
      agentId,
      type: need.type,
      slug: need.slug,
      resourceId: target.resourceId,
      displayName: target.displayName,
      redirectUri: canonicalAgentURL(agentId),
      createNew: target.createNew,
    }))
    const response = fromJson(StartAuthorizationForNeedResponseSchema, data)
    if (!response.authorizeUrl) throw new Error('No authorization URL returned')
    window.location.href = response.authorizeUrl
    return new Promise<never>(() => {})
  }

  return {
    needs,
    inventory,
    loading,
    error,
    refresh,
    resourceFor,
    candidatesFor,
    bind,
    unbind,
    createForNeed,
    startAuthorization,
  }
}
