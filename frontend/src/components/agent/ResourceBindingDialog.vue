<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'
import type { CandidateInfo, NeedInfo } from '@/gen/airlock/v1/api_pb'
import { useAgentResources } from '@/composables/useAgentResources'
import {
  bindingDialogCompletion,
  canCreateResourceForNeed,
  candidateAction,
  type BindingDialogCompletion,
} from '@/utils/resources'
import { serializeAPIKeyRequest, serializeOAuthAppRequest } from '@/utils/resourceRequests'

const props = withDefaults(defineProps<{
  agentId: string
  need: NeedInfo | null
  authMode?: string
  setupInstructions?: string
  callbackUrl?: string
}>(), {
  authMode: 'none',
  setupInstructions: '',
  callbackUrl: '',
})
const emit = defineEmits<{
  changed: []
  configure: [need: NeedInfo]
}>()
const visible = defineModel<boolean>('visible', { default: false })
const toast = useToast()
const i18n = useAirlockI18n()
const { t, formatNumber } = i18n
const binding = useAgentResources(props.agentId)

const candidates = ref<CandidateInfo[]>([])
const loading = ref(false)
const loadError = ref('')
const busyId = ref('')
const creating = ref(false)
const displayName = ref('')
const credential = ref('')
const clientId = ref('')
const clientSecret = ref('')

const isOAuth = computed(() => props.authMode === 'oauth' || props.authMode === 'oauth_discovery')
const isManualOAuth = computed(() => props.authMode === 'oauth')
const isCredential = computed(() => props.authMode === 'api_key' || props.authMode === 'token')
const canOfferCreate = computed(() => !!props.need && canCreateResourceForNeed(props.authMode))

function errorMessage(error: any, fallback: string): string {
  return error?.response?.data?.error || error?.message || fallback
}

async function loadCandidates() {
  if (!props.need) return
  loading.value = true
  loadError.value = ''
  try {
    candidates.value = await binding.candidatesFor(props.need)
  } catch (error: any) {
    loadError.value = errorMessage(error, t('resources.errors.loadCompatible'))
  } finally {
    loading.value = false
  }
}

watch(visible, (open) => {
  if (!open) return
  creating.value = false
  displayName.value = ''
  credential.value = ''
  clientId.value = ''
  clientSecret.value = ''
  void loadCandidates()
})

function readinessLabel(readiness: string): string {
  switch (readiness) {
    case 'ready': return t('resources.status.ready')
    case 'authorization_required': return t('resources.status.authorizationRequired')
    case 'scope_upgrade_required': return t('resources.status.moreAccessRequired')
    case 'scope_upgrade_requires_manager': return t('resources.status.managerActionRequired')
    case 'needs_configuration': return t('resources.status.needsLocalConfiguration')
    case 'incompatible_protocol': return t('resources.status.incompatibleProtocol')
    case 'unhealthy': return t('resources.status.unhealthy')
    case 'starting': return t('resources.status.starting')
    case 'offline': return t('resources.status.offline')
    default: return readiness
  }
}

function capabilityLabel(capability: string): string {
  if (capability === 'view') return t('resources.details.capabilityView')
  if (capability === 'bind') return t('resources.details.capabilityBind')
  if (capability === 'manage') return t('resources.details.capabilityManage')
  return capability
}

function action(candidate: CandidateInfo) {
  return candidateAction(candidate, props.authMode, i18n)
}

function readinessSeverity(readiness: string): string {
  if (readiness === 'ready') return 'success'
  if (readiness === 'scope_upgrade_requires_manager' || readiness === 'incompatible_protocol' || readiness === 'unhealthy') return 'danger'
  if (readiness === 'offline') return 'secondary'
  return 'warn'
}

function emitCompletion(completion: BindingDialogCompletion, need: NeedInfo) {
  if (completion === 'configure') emit('configure', need)
  else emit('changed')
}

async function useCandidate(candidate: CandidateInfo) {
  if (!props.need) return
  const selectedAction = action(candidate)
  if (selectedAction.kind === 'disabled') return
  busyId.value = candidate.resourceId
  try {
    if (selectedAction.kind === 'authorize') {
      await binding.startAuthorization(props.need, {
        resourceId: candidate.resourceId,
        displayName: '',
        createNew: false,
      })
      return
    }
    await binding.bind(props.need, candidate.resourceId)
    visible.value = false
    const completion = bindingDialogCompletion(selectedAction.kind)
    emitCompletion(completion, props.need)
    if (completion === 'changed') toast.add({ severity: 'success', summary: t('resources.binding.connected'), life: 3000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.resourceSetupFailed')), life: 6000 })
  } finally {
    busyId.value = ''
  }
}

async function createNew() {
  const need = props.need
  const name = displayName.value.trim()
  if (!need || !name || !canCreateResourceForNeed(props.authMode)) return
  busyId.value = 'new'
  try {
    if (isManualOAuth.value) {
      const path = need.type === 'connection'
        ? `/api/v1/agents/${props.agentId}/credentials/${encodeURIComponent(need.slug)}/oauth-app`
        : `/api/v1/agents/${props.agentId}/mcp-servers/${encodeURIComponent(need.slug)}/credentials/oauth-app`
      await api.put(path, serializeOAuthAppRequest(clientId.value, clientSecret.value, name, true))
      await binding.startAuthorization(need, { resourceId: '', displayName: name, createNew: true })
      return
    }
    if (props.authMode === 'oauth_discovery') {
      await binding.startAuthorization(need, { resourceId: '', displayName: name, createNew: true })
      return
    }
    if (isCredential.value) {
      const path = need.type === 'connection'
        ? `/api/v1/agents/${props.agentId}/credentials/${encodeURIComponent(need.slug)}`
        : `/api/v1/agents/${props.agentId}/mcp-servers/${encodeURIComponent(need.slug)}/credentials`
      await api.post(path, serializeAPIKeyRequest(credential.value, name, true))
      await binding.refresh()
    } else {
      await binding.createForNeed(need, name)
    }
    visible.value = false
    const completion = bindingDialogCompletion('create')
    emitCompletion(completion, need)
    if (completion === 'changed') toast.add({ severity: 'success', summary: t('resources.binding.createdAndConnected'), life: 3000 })
  } catch (error: any) {
    toast.add({ severity: 'error', summary: errorMessage(error, t('resources.errors.createResourceFailed')), life: 6000 })
  } finally {
    busyId.value = ''
  }
}

const canCreate = computed(() => {
  if (!displayName.value.trim()) return false
  if (isManualOAuth.value) return !!clientId.value.trim() && !!clientSecret.value
  if (isCredential.value) return !!credential.value
  return true
})
</script>

<template>
  <Dialog
    v-model:visible="visible"
    :header="t('resources.binding.title', { name: need?.slug || t('resources.binding.resourceFallback') })"
    modal
    class="resource-binding-dialog"
    :style="{ width: 'min(46rem, calc(100vw - 2rem))' }"
  >
    <div v-if="need" class="binding-body">
      <div>
        <strong>{{ need.description || need.slug }}</strong>
        <div class="need-slug">{{ t('resources.connections.appHandle', { slug: need.slug }) }}</div>
      </div>

      <template v-if="!creating">
        <Message severity="info" :closable="false">
          {{ canOfferCreate ? t('resources.binding.reuseOrCreate') : t('resources.binding.reuseOnly') }}
        </Message>
        <div v-if="loading" class="candidate-list">
          <Skeleton v-for="i in 2" :key="i" height="6rem" />
        </div>
        <Message v-else-if="loadError" severity="error" :closable="false">
          <div class="load-error">
            <span>{{ loadError }}</span>
            <Button :label="t('resources.actions.retry')" icon="pi pi-refresh" size="small" outlined @click="loadCandidates" />
          </div>
        </Message>
        <div v-else-if="candidates.length" class="candidate-list">
          <div v-for="candidate in candidates" :key="candidate.resourceId" class="candidate-card">
            <div class="candidate-main">
              <div class="candidate-title">{{ candidate.displayName || candidate.name }}</div>
              <div class="candidate-meta">
                <Tag :value="readinessLabel(candidate.readiness)" :severity="readinessSeverity(candidate.readiness)" />
                <span>{{ t('resources.inventory.appCount', { count: candidate.agentCount, formattedCount: formatNumber(candidate.agentCount) }) }}</span>
                <span>{{ t('resources.binding.access', { capabilities: candidate.capabilities.map(capabilityLabel).join(', ') || t('resources.binding.none') }) }}</span>
              </div>
              <div v-if="candidate.requiredScopes.length" class="scope-line">
                {{ t('resources.binding.requiredScopes', { scopes: candidate.requiredScopes.join(', ') }) }}
              </div>
              <div v-if="candidate.missingScopes.length" class="scope-line missing">
                {{ t('resources.binding.missingScopes', { scopes: candidate.missingScopes.join(', ') }) }}
              </div>
              <small v-if="action(candidate).reason" class="action-reason">
                {{ action(candidate).reason }}
              </small>
            </div>
            <Button
              :label="action(candidate).label"
              size="small"
              :disabled="action(candidate).kind === 'disabled'"
              :loading="busyId === candidate.resourceId"
              @click="useCandidate(candidate)"
            />
          </div>
        </div>
        <div v-else class="empty-candidates">{{ t('resources.binding.empty') }}</div>
        <template v-if="canOfferCreate">
          <Divider />
          <Button :label="t('resources.actions.createNew')" icon="pi pi-plus" outlined @click="creating = true" />
        </template>
      </template>

      <template v-else>
        <Button :label="t('resources.actions.backToReusable')" icon="pi pi-arrow-left" text class="back-button" @click="creating = false" />
        <div class="field">
          <label for="resource-display-name">{{ t('resources.binding.displayName') }}</label>
          <InputText id="resource-display-name" v-model="displayName" autofocus :placeholder="t('resources.binding.displayNamePlaceholder')" />
          <small>{{ t('resources.binding.displayNameHelp') }}</small>
        </div>
        <p v-if="setupInstructions" class="instructions">{{ setupInstructions }}</p>
        <div v-if="callbackUrl && isManualOAuth" class="callback-line">
          {{ t('resources.auth.redirectUri', { uri: callbackUrl }) }}
        </div>
        <div v-if="isManualOAuth" class="field">
          <label for="resource-client-id">{{ t('resources.auth.clientId') }}</label>
          <InputText id="resource-client-id" v-model="clientId" />
        </div>
        <div v-if="isManualOAuth" class="field">
          <label for="resource-client-secret">{{ t('resources.auth.clientSecret') }}</label>
          <Password id="resource-client-secret" v-model="clientSecret" :feedback="false" toggle-mask fluid />
        </div>
        <div v-if="isCredential" class="field">
          <label for="resource-credential">{{ authMode === 'token' ? t('resources.auth.token') : t('resources.auth.apiKey') }}</label>
          <Password id="resource-credential" v-model="credential" :feedback="false" toggle-mask fluid />
        </div>
        <Message v-if="authMode === 'none'" severity="info" :closable="false">
          {{ t('resources.auth.noCredentialsRequired') }}
        </Message>
        <div class="dialog-actions">
          <Button :label="t('resources.actions.cancel')" severity="secondary" text @click="visible = false" />
          <Button
            :label="isOAuth ? t('resources.actions.createAndAuthorize') : t('resources.actions.createResource')"
            :loading="busyId === 'new'"
            :disabled="!canCreate"
            @click="createNew"
          />
        </div>
      </template>
    </div>
  </Dialog>
</template>

<style scoped>
.binding-body, .candidate-list, .field { display: flex; flex-direction: column; }
.binding-body { gap: 1rem; }
.candidate-list { gap: 0.75rem; }
.candidate-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem;
  border: 1px solid var(--p-content-border-color);
  border-radius: 0.65rem;
}
.candidate-main { min-width: 0; }
.candidate-title { font-weight: 600; }
.candidate-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.4rem; color: var(--p-text-muted-color); font-size: 0.8rem; }
.scope-line, .action-reason, .need-slug, .instructions, .callback-line, .field small { color: var(--p-text-muted-color); font-size: 0.8rem; }
.scope-line { margin-top: 0.4rem; word-break: break-word; }
.scope-line.missing { color: var(--p-orange-500); }
.action-reason { display: block; margin-top: 0.45rem; }
.empty-candidates { padding: 1.5rem; text-align: center; color: var(--p-text-muted-color); border: 1px dashed var(--p-content-border-color); border-radius: 0.65rem; }
.field { gap: 0.35rem; }
.field label { font-size: 0.85rem; font-weight: 500; }
.callback-line code { word-break: break-all; }
.back-button { align-self: flex-start; padding-left: 0; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
@media (max-width: 40rem) {
  .candidate-card { align-items: stretch; flex-direction: column; }
  .candidate-card :deep(.p-button) { width: 100%; }
}
</style>
