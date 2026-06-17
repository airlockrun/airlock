import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { OwnedResourceInfo } from '@/gen/airlock/v1/api_pb'
import { ListOwnedResourcesResponseSchema } from '@/gen/airlock/v1/api_pb'

// The caller's owned connections / MCP servers / exec endpoints across all of
// their agents, with each one's agent-bind count. Read-only: resources are
// created and credentialed from an agent's needs, not here.
export const useResourcesStore = defineStore('resources', () => {
  const resources = ref<OwnedResourceInfo[]>([])
  const loading = ref(false)

  async function fetchResources() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/resources')
      resources.value = fromJson(ListOwnedResourcesResponseSchema, data).resources
    } finally {
      loading.value = false
    }
  }

  return { resources, loading, fetchResources }
})
