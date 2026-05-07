import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { Provider } from '@/gen/airlock/v1/types_pb'
import {
  ListProvidersResponseSchema,
  CreateProviderResponseSchema,
  UpdateProviderResponseSchema,
} from '@/gen/airlock/v1/api_pb'

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

  async function createProvider(payload: { providerId: string; slug: string; displayName: string; baseUrl: string; apiKey: string }) {
    const { data } = await api.post('/api/v1/providers', payload)
    providers.value.unshift(fromJson(CreateProviderResponseSchema, data).provider!)
  }

  async function updateProvider(id: string, payload: { displayName?: string; slug?: string; baseUrl?: string; apiKey?: string }) {
    const { data } = await api.patch(`/api/v1/providers/${id}`, payload)
    const updated = fromJson(UpdateProviderResponseSchema, data).provider!
    const idx = providers.value.findIndex((p) => p.id === id)
    if (idx !== -1) providers.value[idx] = updated
  }

  async function deleteProvider(id: string) {
    await api.delete(`/api/v1/providers/${id}`)
    providers.value = providers.value.filter((p) => p.id !== id)
  }

  return { providers, loading, byId, fetchProviders, createProvider, updateProvider, deleteProvider }
})
