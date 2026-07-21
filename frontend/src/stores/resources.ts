import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { OwnedResourceInfo, ResourceConsumerInfo, ResourceGrantInfo } from '@/gen/airlock/v1/api_pb'
import {
  ListOwnedResourcesResponseSchema,
  ListResourceConsumersResponseSchema,
  ListResourceGrantsResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useResourcesStore = defineStore('resources', () => {
  const resources = ref<OwnedResourceInfo[]>([])
  const loading = ref(false)
  const error = ref('')

  function path(type: string, id: string): string {
    return `/api/v1/resources/${type}/${id}`
  }

  async function fetchResources() {
    loading.value = true
    error.value = ''
    try {
      const { data } = await api.get('/api/v1/resources')
      resources.value = fromJson(ListOwnedResourcesResponseSchema, data).resources
    } catch (cause: any) {
      error.value = cause?.response?.data?.error || cause?.message || 'Failed to load resources'
      throw cause
    } finally {
      loading.value = false
    }
  }

  async function fetchConsumers(type: string, id: string): Promise<ResourceConsumerInfo[]> {
    const { data } = await api.get(`${path(type, id)}/consumers`)
    return fromJson(ListResourceConsumersResponseSchema, data).consumers
  }

  async function fetchGrants(type: string, id: string): Promise<ResourceGrantInfo[]> {
    const { data } = await api.get(`${path(type, id)}/grants`)
    return fromJson(ListResourceGrantsResponseSchema, data).grants
  }

  async function rename(type: string, id: string, displayName: string) {
    await api.patch(path(type, id), { displayName })
    await fetchResources()
  }

  async function grant(type: string, id: string, granteeId: string, capabilities: string[]) {
    await api.post(`${path(type, id)}/grants`, {
      resourceType: type,
      resourceId: id,
      granteeId,
      capabilities,
    })
  }

  async function revokeGrant(type: string, id: string, grantId: string) {
    await api.delete(`${path(type, id)}/grants/${grantId}`)
  }

  async function revoke(type: string, id: string) {
    await api.post(`${path(type, id)}/revoke`)
    await fetchResources()
  }

  async function remove(type: string, id: string) {
    await api.delete(path(type, id))
    resources.value = resources.value.filter((resource) => resource.id !== id)
  }

  return {
    resources,
    loading,
    error,
    fetchResources,
    fetchConsumers,
    fetchGrants,
    rename,
    grant,
    revokeGrant,
    revoke,
    remove,
  }
})
