import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type { CandidateInfo, ConnectorTargetGroupCandidateInfo, NeedInfo } from '@/gen/airlock/v1/api_pb'
import type { ConnectorInfo } from '@/gen/airlock/v1/types_pb'
import {
  bindConnectorGroup,
  bindConnector,
  createConnectorTargetGroup,
  getConnector,
  listAgentConnectorNeeds,
  listConnectorCandidates,
  listConnectorTargetGroupCandidates,
  listConnectors,
  unbindConnector,
} from '@/api/connectors'
import { connectorMessages } from '@/i18n/messages/connectors'
import type { ConnectorTranslate } from '@/utils/connectors'

function message(id: keyof typeof connectorMessages, translate?: ConnectorTranslate): string {
  return translate ? translate(id) : connectorMessages[id].defaultMessage
}

function errorMessage(cause: unknown, fallback: keyof typeof connectorMessages, translate?: ConnectorTranslate): string {
  if (typeof cause === 'object' && cause !== null) {
    const error = cause as { message?: unknown; response?: { data?: { error?: unknown } } }
    const apiError = error.response?.data?.error
    if (typeof apiError === 'string') return apiError
    if (typeof error.message === 'string') return error.message
  }
  return message(fallback, translate)
}

export const useConnectorsStore = defineStore('connectors', () => {
  const agentId = ref('')
  const needs = ref<NeedInfo[]>([])
  const connectors = ref<ConnectorInfo[]>([])
  const targetGroups = ref<Record<string, ConnectorTargetGroupCandidateInfo[]>>({})
  const candidates = ref<Record<string, CandidateInfo[]>>({})
  const loading = ref(false)
  const error = ref('')
  let fetchSequence = 0

  const connectorsById = computed(() => new Map(connectors.value.map((connector) => [connector.id, connector])))

  async function fetchAgent(targetAgentId: string, canAdmin = false, translate?: ConnectorTranslate): Promise<void> {
    const sequence = ++fetchSequence
    if (agentId.value !== targetAgentId) {
      agentId.value = targetAgentId
      needs.value = []
      connectors.value = []
      targetGroups.value = {}
      candidates.value = {}
    }
    loading.value = true
    error.value = ''
    try {
      const [loadedNeeds, loadedConnectors] = await Promise.all([
        listAgentConnectorNeeds(targetAgentId),
        listConnectors(),
      ])
      const loadedNeedData = canAdmin
        ? await Promise.all(loadedNeeds.map(async (need) => [
            need.slug,
            await listConnectorCandidates(targetAgentId, need.slug),
            need.connectorMultiple ? await listConnectorTargetGroupCandidates(targetAgentId, need.slug) : [],
          ] as const))
        : []
      if (sequence !== fetchSequence || agentId.value !== targetAgentId) return
      needs.value = loadedNeeds
      connectors.value = loadedConnectors
      candidates.value = Object.fromEntries(loadedNeedData.map(([slug, loaded]) => [slug, loaded]))
      targetGroups.value = Object.fromEntries(loadedNeedData.map(([slug, , groups]) => [slug, groups]))
    } catch (cause: unknown) {
      if (sequence !== fetchSequence || agentId.value !== targetAgentId) return
      error.value = errorMessage(cause, 'connectors.store.error.loadFailed', translate)
      throw cause
    } finally {
      if (sequence === fetchSequence && agentId.value === targetAgentId) loading.value = false
    }
  }

  function connectorFor(need: NeedInfo): ConnectorInfo | undefined {
    if (need.boundConnectorGroupId) return undefined
    const connectorId = need.boundConnectorId || need.boundResourceId
    return connectorId ? connectorsById.value.get(connectorId) : undefined
  }

  async function fetchConnector(connectorId: string): Promise<ConnectorInfo> {
    const connector = await getConnector(connectorId)
    const index = connectors.value.findIndex((item) => item.id === connector.id)
    if (index === -1) connectors.value.push(connector)
    else connectors.value[index] = connector
    return connector
  }

  async function bind(targetAgentId: string, slug: string, resourceId: string, translate?: ConnectorTranslate): Promise<void> {
    await bindConnector(targetAgentId, slug, resourceId)
    if (agentId.value !== targetAgentId) return
    invalidateAgent()
    await fetchAgent(targetAgentId, true, translate)
  }

  async function unbind(targetAgentId: string, slug: string, translate?: ConnectorTranslate): Promise<void> {
    await unbindConnector(targetAgentId, slug)
    if (agentId.value !== targetAgentId) return
    invalidateAgent()
    await fetchAgent(targetAgentId, true, translate)
  }

  async function bindGroup(targetAgentId: string, slug: string, targetGroupId: string, translate?: ConnectorTranslate): Promise<void> {
    await bindConnectorGroup(targetAgentId, slug, targetGroupId)
    if (agentId.value !== targetAgentId) return
    invalidateAgent()
    await fetchAgent(targetAgentId, true, translate)
  }

  async function createGroup(targetAgentId: string, needSlug: string, name: string, description: string, connectorIds: string[], translate?: ConnectorTranslate): Promise<string> {
    const group = await createConnectorTargetGroup(targetAgentId, needSlug, name, description, connectorIds)
    if (agentId.value === targetAgentId) await fetchAgent(targetAgentId, true, translate)
    return group.id
  }

  function invalidateAgent(): void {
    needs.value = []
    candidates.value = {}
  }

  return {
    agentId,
    needs,
    connectors,
    targetGroups,
    candidates,
    loading,
    error,
    connectorsById,
    fetchAgent,
    connectorFor,
    fetchConnector,
    bind,
    unbind,
    bindGroup,
    createGroup,
    invalidateAgent,
  }
})
