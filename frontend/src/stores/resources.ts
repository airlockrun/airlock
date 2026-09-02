import { ref } from 'vue'
import { defineStore } from 'pinia'
import { create, fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { GetConnectorResponse, OwnedResourceInfo, ResourceConsumerInfo, ResourceGrantInfo } from '@/gen/airlock/v1/api_pb'
import { useAirlockI18n } from '@/i18n'
import {
  CreateConnectionResourceRequestSchema,
  CreateConnectionResourceResponseSchema,
  ListOwnedResourcesResponseSchema,
  ListResourceConsumersResponseSchema,
  ListResourceGrantsResponseSchema,
  RenameResourceRequestSchema,
  TransferResourceOwnershipRequestSchema,
  UpsertResourceGrantRequestSchema,
} from '@/gen/airlock/v1/api_pb'
import { getConnectorDetail } from '@/api/connectors'

export const useResourcesStore = defineStore('resources', () => {
  const { t } = useAirlockI18n()
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
      error.value = cause?.response?.data?.error || cause?.message || t('resources.errors.loadResources')
      throw cause
    } finally {
      loading.value = false
    }
  }

  async function fetchConsumers(type: string, id: string): Promise<ResourceConsumerInfo[]> {
    const { data } = await api.get(`${path(type, id)}/consumers`)
    return fromJson(ListResourceConsumersResponseSchema, data).consumers
  }

  async function createConnection(input: {
    displayName: string
    baseUrl: string
    authMode: string
    token: string
    authInjectionType: string
    authInjectionName: string
  }) {
    const request = create(CreateConnectionResourceRequestSchema, input)
    const { data } = await api.post('/api/v1/resources/connections', toJson(CreateConnectionResourceRequestSchema, request))
    const created = fromJson(CreateConnectionResourceResponseSchema, data)
    await fetchResources()
    return created
  }

  async function rename(type: string, id: string, displayName: string) {
    const request = create(RenameResourceRequestSchema, { displayName })
    await api.patch(path(type, id), toJson(RenameResourceRequestSchema, request))
    await fetchResources()
  }

  async function revoke(type: string, id: string) {
    await api.post(`${path(type, id)}/revoke`)
    await fetchResources()
  }

  async function remove(type: string, id: string) {
    await api.delete(path(type, id))
    resources.value = resources.value.filter((resource) => resource.id !== id)
  }

  async function fetchConnector(id: string): Promise<GetConnectorResponse> {
    return getConnectorDetail(id)
  }

  async function fetchGrants(type: string, id: string): Promise<ResourceGrantInfo[]> {
    const { data } = await api.get(`${path(type, id)}/grants`)
    return fromJson(ListResourceGrantsResponseSchema, data).grants
  }

  async function saveGrant(type: string, id: string, userId: string, capabilities: string[]): Promise<ResourceGrantInfo[]> {
    const request = create(UpsertResourceGrantRequestSchema, { capabilities })
    await api.put(`${path(type, id)}/grants/${userId}`, toJson(UpsertResourceGrantRequestSchema, request))
    return fetchGrants(type, id)
  }

  async function removeGrant(type: string, id: string, userId: string): Promise<ResourceGrantInfo[]> {
    await api.delete(`${path(type, id)}/grants/${userId}`)
    return fetchGrants(type, id)
  }

  async function transfer(type: string, id: string, newOwnerUserId: string) {
    const request = create(TransferResourceOwnershipRequestSchema, { newOwnerUserId })
    await api.post(`${path(type, id)}/transfer`, toJson(TransferResourceOwnershipRequestSchema, request))
    await fetchResources()
  }

  return {
    resources,
    loading,
    error,
    fetchResources,
    fetchConsumers,
    createConnection,
    rename,
    revoke,
    remove,
    fetchConnector,
    fetchGrants,
    saveGrant,
    removeGrant,
    transfer,
  }
})
