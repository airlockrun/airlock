import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { ModelInfo, ProviderInfo, ProviderCapabilityInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListCatalogModelsResponseSchema,
  ListCatalogProvidersResponseSchema,
  ListCapabilitiesResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useCatalogStore = defineStore('catalog', () => {
  const models = ref<ModelInfo[]>([])
  const providers = ref<ProviderInfo[]>([])
  const capabilities = ref<ProviderCapabilityInfo[]>([])
  const loading = ref(false)

  async function fetchConfiguredModels() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/catalog/models?configured=true')
      models.value = fromJson(ListCatalogModelsResponseSchema, data).models
    } finally {
      loading.value = false
    }
  }

  async function fetchCatalogProviders() {
    try {
      const { data } = await api.get('/api/v1/catalog/providers')
      providers.value = fromJson(ListCatalogProvidersResponseSchema, data).providers
    } catch {
      // non-critical — form still works with manual input
    }
  }

  async function fetchCapabilities() {
    try {
      const { data } = await api.get('/api/v1/catalog/capabilities')
      capabilities.value = fromJson(ListCapabilitiesResponseSchema, data).providers
    } catch {
      // non-critical — matrix will be empty
    }
  }

  return {
    models,
    providers,
    capabilities,
    loading,
    fetchConfiguredModels,
    fetchCatalogProviders,
    fetchCapabilities,
  }
})
