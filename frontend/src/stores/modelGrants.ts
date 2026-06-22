import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { ModelGrantInfo } from '@/gen/airlock/v1/api_pb'
import { ListModelGrantsResponseSchema } from '@/gen/airlock/v1/api_pb'

// Well-known built-in "user" group. Allowing a model for this group allows it
// for everyone: the policy resolver folds admin > manager > user, so a grant on
// the user group is inherited by the higher roles too.
export const GROUP_USER = '00000000-0000-0000-0000-0000000000a3'

export const useModelGrantsStore = defineStore('modelGrants', () => {
  const grants = ref<ModelGrantInfo[]>([])
  const loading = ref(false)

  // `${providerRowId}::${model}` -> grant id, for O(1) toggle lookup. Grants are
  // keyed on the configured provider row (not the catalog id), matching the
  // runtime entitlement check.
  const grantByKey = computed<Map<string, string>>(() => {
    const m = new Map<string, string>()
    for (const g of grants.value) m.set(`${g.providerId}::${g.model}`, g.id)
    return m
  })

  async function fetchGrants() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/model-grants')
      grants.value = fromJson(ListModelGrantsResponseSchema, data).grants
    } finally {
      loading.value = false
    }
  }

  async function grant(providerId: string, model: string) {
    await api.post('/api/v1/model-grants', { providerId, model, granteeId: GROUP_USER })
    await fetchGrants()
  }

  async function revoke(id: string) {
    await api.delete(`/api/v1/model-grants/${id}`)
    grants.value = grants.value.filter((g) => g.id !== id)
  }

  // usage reports how a (provider, model) is configured before a disable:
  // agentCount agents pin it as an override (reset to the workspace default on
  // revoke); isSystemDefault means it stays usable as a configured default.
  async function usage(providerId: string, model: string): Promise<{ agentCount: number; isSystemDefault: boolean }> {
    const { data } = await api.get('/api/v1/model-grants/usage', { params: { providerId, model } })
    return { agentCount: Number(data?.agentCount ?? 0), isSystemDefault: !!data?.isSystemDefault }
  }

  function isAllowed(providerRowId: string, model: string): boolean {
    return grantByKey.value.has(`${providerRowId}::${model}`)
  }

  function grantId(providerRowId: string, model: string): string | undefined {
    return grantByKey.value.get(`${providerRowId}::${model}`)
  }

  return { grants, loading, grantByKey, fetchGrants, grant, revoke, usage, isAllowed, grantId }
})
