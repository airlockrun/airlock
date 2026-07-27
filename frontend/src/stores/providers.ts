import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { create, fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { Provider, ProviderModel, ProviderModelCandidate } from '@/gen/airlock/v1/types_pb'
import {
  CreateProviderRequestSchema,
  CreateProviderResponseSchema,
  DiscoverProviderModelsResponseSchema,
  ListProviderModelsResponseSchema,
  ListProvidersResponseSchema,
  ReplaceProviderModelsRequestSchema,
  ReplaceProviderModelsResponseSchema,
  UpdateProviderRequestSchema,
  UpdateProviderResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export type CreateProviderPayload = {
  providerId: string
  slug: string
  displayName: string
  baseUrl: string
  apiKey: string
}

export type UpdateProviderPayload = {
  displayName?: string
  slug?: string
  baseUrl?: string
  apiKey?: string
  isEnabled?: boolean
}

export const useProvidersStore = defineStore('providers', () => {
  const providers = ref<Provider[]>([])
  const loading = ref(false)

  // O(1) lookup by row UUID. Used by the model pickers to resolve a slot's
  // provider FK back to (catalog provider_id, slug) for picker display
  // without re-walking the providers list per render.
  const byId = computed<Map<string, Provider>>(() => {
    const m = new Map<string, Provider>()
    for (const p of providers.value) m.set(p.id, p)
    return m
  })

  async function fetchProviders() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/providers')
      providers.value = fromJson(ListProvidersResponseSchema, data).providers
    } finally {
      loading.value = false
    }
  }

  async function createProvider(payload: CreateProviderPayload) {
    const req = create(CreateProviderRequestSchema, payload)
    const { data } = await api.post(
      '/api/v1/providers',
      toJson(CreateProviderRequestSchema, req),
    )
    providers.value.unshift(fromJson(CreateProviderResponseSchema, data).provider!)
  }

  async function updateProvider(id: string, payload: UpdateProviderPayload) {
    const req = create(UpdateProviderRequestSchema, payload)
    const { data } = await api.patch(
      `/api/v1/providers/${id}`,
      toJson(UpdateProviderRequestSchema, req),
    )
    const updated = fromJson(UpdateProviderResponseSchema, data).provider!
    const idx = providers.value.findIndex((p) => p.id === id)
    if (idx !== -1) providers.value[idx] = updated
  }

  async function fetchProviderModels(id: string): Promise<ProviderModel[]> {
    const { data } = await api.get(`/api/v1/providers/${id}/models`)
    return fromJson(ListProviderModelsResponseSchema, data).models
  }

  async function discoverProviderModels(id: string): Promise<ProviderModelCandidate[]> {
    const { data } = await api.post(`/api/v1/providers/${id}/discover-models`)
    return fromJson(DiscoverProviderModelsResponseSchema, data).candidates
  }

  async function replaceProviderModels(id: string, models: ProviderModel[]): Promise<ProviderModel[]> {
    const req = create(ReplaceProviderModelsRequestSchema, { models })
    const { data } = await api.put(
      `/api/v1/providers/${id}/models`,
      toJson(ReplaceProviderModelsRequestSchema, req),
    )
    return fromJson(ReplaceProviderModelsResponseSchema, data).models
  }

  async function deleteProvider(id: string) {
    await api.delete(`/api/v1/providers/${id}`)
    providers.value = providers.value.filter((p) => p.id !== id)
  }

  return {
    providers,
    loading,
    byId,
    fetchProviders,
    createProvider,
    updateProvider,
    fetchProviderModels,
    discoverProviderModels,
    replaceProviderModels,
    deleteProvider,
  }
})
