import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ListAllowedModelsResponseSchema } from '@/gen/airlock/v1/api_pb'

// The models the current caller may assign to an agent capability — the model
// picker's allow-list. `unrestricted` (tenant admin) means any configured model
// is assignable. System defaults are NOT included: a slot left unset falls back
// to the capability default, so it never needs to be picked explicitly.
export const useModelsAllowedStore = defineStore('modelsAllowed', () => {
  const unrestricted = ref(false)
  const allowed = ref<Set<string>>(new Set()) // `${providerRowId}::${model}`
  const loaded = ref(false)

  async function fetchAllowed() {
    const { data } = await api.get('/api/v1/models/allowed')
    const resp = fromJson(ListAllowedModelsResponseSchema, data)
    unrestricted.value = resp.unrestricted
    allowed.value = new Set(resp.models.map((m) => `${m.providerId}::${m.model}`))
    loaded.value = true
  }

  function isAllowed(providerRowId: string, model: string): boolean {
    return unrestricted.value || allowed.value.has(`${providerRowId}::${model}`)
  }

  return { unrestricted, allowed, loaded, fetchAllowed, isAllowed }
})
