<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { create } from '@bufbuild/protobuf'
import { useToast } from 'primevue/usetoast'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'
import { ProviderModelSchema, type Provider, type ProviderModel } from '@/gen/airlock/v1/types_pb'
import {
  isCurrentProviderRequest,
  nextProviderRequestSession,
  type ProviderRequestSession,
} from '@/utils/providers'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ provider: Provider | null }>()
const visible = defineModel<boolean>('visible', { required: true })
const { t, formatNumber } = useAirlockI18n()

type ModelDraft = {
  modelId: string
  displayName: string
  contextLimit: number
  outputLimit: number
  toolCall: boolean
  reasoning: boolean
  vision: boolean
  structuredOutputs: boolean
  includeUsage: boolean
  selected: boolean
  persisted: boolean
}

type ProviderModelBooleanField = {
  [K in keyof ProviderModel]-?: ProviderModel[K] extends boolean ? K : never
}[keyof ProviderModel]

// This exhaustive map makes generated model flags compile-fail until load,
// discovery, editing, and save support are added for each field.
const capabilityLabels = computed(() => ({
  toolCall: t('administration.providerModels.capability.toolCalls'),
  reasoning: t('administration.providerModels.capability.reasoning'),
  vision: t('administration.providerModels.capability.vision'),
  structuredOutputs: t('administration.providerModels.capability.structuredOutputs'),
  includeUsage: t('administration.providerModels.capability.includeUsage'),
}) satisfies Record<ProviderModelBooleanField, string>)

const DEFAULT_CONTEXT_LIMIT = 8192
const DEFAULT_OUTPUT_LIMIT = 2048

const providers = useProvidersStore()
const catalog = useCatalogStore()
const toast = useToast()
const models = ref<ModelDraft[]>([])
const loading = ref(false)
const discovering = ref(false)
const saving = ref(false)
const error = ref('')
const loaded = ref(false)
let session: ProviderRequestSession = { generation: 0, providerId: '' }

const selectedCount = computed(() => models.value.filter((model) => model.selected).length)
const saveDisabled = computed(() =>
  loading.value ||
  !loaded.value ||
  discovering.value ||
  saving.value ||
  models.value.some((model) =>
    model.selected && (
      !model.modelId.trim() ||
      !model.displayName.trim() ||
      !Number.isInteger(model.contextLimit) ||
      model.contextLimit <= 0 ||
      !Number.isInteger(model.outputLimit) ||
      model.outputLimit <= 0
    ),
  ),
)

function errorMessage(cause: any, fallback: string): string {
  return cause?.response?.data?.error || cause?.message || fallback
}

function resetDrafts() {
  models.value = []
  loaded.value = false
  error.value = ''
}

function beginSession(providerId: string): ProviderRequestSession {
  session = nextProviderRequestSession(session, providerId)
  return session
}

function requestIsCurrent(request: ProviderRequestSession): boolean {
  return visible.value && isCurrentProviderRequest(session, request)
}

async function loadModels(request: ProviderRequestSession) {
  loading.value = true
  try {
    const confirmed = await providers.fetchProviderModels(request.providerId)
    if (!requestIsCurrent(request)) return
    models.value = confirmed.map((model) => ({
      modelId: model.modelId,
      displayName: model.displayName,
      contextLimit: model.contextLimit,
      outputLimit: model.outputLimit,
      toolCall: model.toolCall,
      reasoning: model.reasoning,
      vision: model.vision,
      structuredOutputs: model.structuredOutputs,
      includeUsage: model.includeUsage,
      selected: true,
      persisted: true,
    }))
    loaded.value = true
  } catch (cause: any) {
    if (!requestIsCurrent(request)) return
    models.value = []
    loaded.value = false
    error.value = errorMessage(cause, t('administration.providerModels.loadFailed'))
  } finally {
    if (requestIsCurrent(request)) loading.value = false
  }
}

watch([visible, () => props.provider?.id], ([isVisible, providerId]) => {
  resetDrafts()
  loading.value = false
  discovering.value = false
  saving.value = false
  const request = beginSession(isVisible ? providerId ?? '' : '')
  if (isVisible && providerId) void loadModels(request)
}, { immediate: true, flush: 'sync' })

async function discoverModels() {
  if (!props.provider) return
  const request = session
  discovering.value = true
  error.value = ''
  try {
    const candidates = await providers.discoverProviderModels(request.providerId)
    if (!requestIsCurrent(request)) return
    const existing = new Set(models.value.map((model) => model.modelId))
    let added = 0
    for (const candidate of candidates) {
      if (existing.has(candidate.modelId)) continue
      models.value.push({
        modelId: candidate.modelId,
        displayName: candidate.modelId,
        contextLimit: DEFAULT_CONTEXT_LIMIT,
        outputLimit: DEFAULT_OUTPUT_LIMIT,
        toolCall: false,
        reasoning: false,
        vision: false,
        structuredOutputs: false,
        includeUsage: false,
        selected: false,
        persisted: false,
      })
      existing.add(candidate.modelId)
      added++
    }
    models.value.sort((a, b) => a.modelId.localeCompare(b.modelId))
    toast.add({
      severity: 'info',
      summary: t('administration.providerModels.discoveryComplete'),
      detail: added
        ? t('administration.providerModels.newModels', { count: added, formattedCount: formatNumber(added) })
        : t('administration.providerModels.noNewModels'),
      life: 4000,
    })
  } catch (cause: any) {
    if (!requestIsCurrent(request)) return
    error.value = errorMessage(cause, t('administration.providerModels.discoveryFailedFallback'))
    toast.add({ severity: 'error', summary: t('administration.providerModels.discoveryFailed'), detail: error.value, life: 5000 })
  } finally {
    if (requestIsCurrent(request)) discovering.value = false
  }
}

function removeModel(index: number) {
  models.value.splice(index, 1)
}

async function saveModels() {
  if (!props.provider || saveDisabled.value) return
  const request = session
  error.value = ''
  saving.value = true
  try {
    const confirmed = models.value
      .filter((model) => model.selected)
      .map((model) => create(ProviderModelSchema, {
        modelId: model.modelId.trim(),
        displayName: model.displayName.trim(),
        contextLimit: model.contextLimit,
        outputLimit: model.outputLimit,
        toolCall: model.toolCall,
        reasoning: model.reasoning,
        vision: model.vision,
        structuredOutputs: model.structuredOutputs,
        includeUsage: model.includeUsage,
      }))
    await providers.replaceProviderModels(request.providerId, confirmed)
    if (!requestIsCurrent(request)) return
    await catalog.fetchConfiguredModels()
    if (!requestIsCurrent(request)) return
    toast.add({ severity: 'success', summary: t('administration.providerModels.savedToast'), life: 3000 })
    visible.value = false
  } catch (cause: any) {
    if (!requestIsCurrent(request)) return
    error.value = errorMessage(cause, t('administration.providerModels.saveFailedFallback'))
    toast.add({ severity: 'error', summary: t('administration.providerModels.saveFailed'), detail: error.value, life: 5000 })
  } finally {
    if (requestIsCurrent(request)) saving.value = false
  }
}
</script>

<template>
  <Dialog
    v-model:visible="visible"
    modal
    :header="provider ? t('administration.providerModels.modelsFor', { provider: provider.displayName || provider.slug }) : t('administration.providerModels.models')"
    style="width: 58rem; max-width: 96vw"
    :breakpoints="{ '700px': '96vw' }"
  >
    <div class="dialog-content">
      <div v-if="provider" class="provider-context">
        <div>
          <strong>{{ provider.displayName || provider.providerId }}</strong>
          <div class="provider-key">{{ provider.providerId }}/{{ provider.slug }}</div>
        </div>
        <Button
          :label="t('administration.providerModels.discover')"
          icon="pi pi-refresh"
          severity="secondary"
          :loading="discovering"
          :disabled="loading || !loaded || saving"
          @click="discoverModels"
        />
      </div>

      <Message severity="info" :closable="false">
        {{ t('administration.providerModels.discoveryHelp') }}
      </Message>
      <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

      <div v-if="loading" class="model-list">
        <Skeleton v-for="i in 3" :key="i" height="9rem" />
      </div>
      <div v-else-if="models.length" class="model-list">
        <section
          v-for="(model, index) in models"
          :key="model.modelId"
          class="model-card"
          :class="{ muted: !model.selected }"
        >
          <div class="model-heading">
            <div class="confirm-control">
              <Checkbox v-model="model.selected" :input-id="`confirm-model-${index}`" binary />
              <label :for="`confirm-model-${index}`">{{ t('administration.providerModels.confirm') }}</label>
              <Tag v-if="model.persisted" :value="t('administration.providerModels.saved')" severity="success" />
              <Tag v-else :value="t('administration.providerModels.discovered')" severity="info" />
            </div>
            <Button
              icon="pi pi-trash"
              :aria-label="t('administration.providerModels.removeAria')"
              severity="danger"
              text
              rounded
              @click="removeModel(index)"
            />
          </div>

          <div class="model-id">{{ model.modelId }}</div>
          <div class="model-fields">
            <FloatLabel variant="on" class="display-field">
              <InputText
                :id="`model-name-${index}`"
                v-model="model.displayName"
                :disabled="!model.selected"
                style="width: 100%"
              />
              <label :for="`model-name-${index}`">{{ t('administration.providerModels.displayName') }}</label>
            </FloatLabel>
            <FloatLabel variant="on">
              <InputNumber
                :id="`model-context-${index}`"
                v-model="model.contextLimit"
                :disabled="!model.selected"
                :min="1"
                :max="2147483647"
                :use-grouping="false"
                fluid
              />
              <label :for="`model-context-${index}`">{{ t('administration.providerModels.contextLimit') }}</label>
            </FloatLabel>
            <FloatLabel variant="on">
              <InputNumber
                :id="`model-output-${index}`"
                v-model="model.outputLimit"
                :disabled="!model.selected"
                :min="1"
                :max="2147483647"
                :use-grouping="false"
                fluid
              />
              <label :for="`model-output-${index}`">{{ t('administration.providerModels.outputLimit') }}</label>
            </FloatLabel>
          </div>

          <div class="capability-toggles">
            <label v-for="(label, field) in capabilityLabels" :key="field">
              <ToggleSwitch v-model="model[field]" :disabled="!model.selected" /> {{ label }}
            </label>
          </div>
        </section>
      </div>
      <Message v-else severity="secondary" :closable="false">
        {{ t('administration.providerModels.empty') }}
      </Message>
    </div>

    <template #footer>
      <div class="dialog-footer">
        <span>{{ t('administration.providerModels.selectedCount', { count: selectedCount, formattedCount: formatNumber(selectedCount) }) }}</span>
        <div class="footer-actions">
          <Button :label="t('administration.action.cancel')" severity="secondary" text @click="visible = false" />
          <Button :label="t('administration.providerModels.save')" icon="pi pi-check" :loading="saving" :disabled="saveDisabled" @click="saveModels" />
        </div>
      </div>
    </template>
  </Dialog>
</template>

<style scoped>
.dialog-content,
.model-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.provider-context,
.model-heading,
.dialog-footer,
.footer-actions,
.confirm-control {
  display: flex;
  align-items: center;
}
.provider-context,
.model-heading,
.dialog-footer {
  justify-content: space-between;
  gap: 1rem;
}
.provider-key,
.model-id,
.dialog-footer > span {
  color: var(--p-text-muted-color);
  font-size: 0.8rem;
}
.model-card {
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  padding: 1rem;
  transition: opacity 0.15s ease;
}
.model-card.muted {
  opacity: 0.68;
}
.confirm-control,
.footer-actions {
  gap: 0.5rem;
}
.model-id {
  margin: -0.25rem 0 1rem;
  overflow-wrap: anywhere;
}
.model-fields {
  display: grid;
  grid-template-columns: minmax(12rem, 1fr) 9rem 9rem;
  gap: 0.75rem;
}
.capability-toggles {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem 1.25rem;
  margin-top: 1rem;
}
.capability-toggles label {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.85rem;
}
@media (max-width: 700px) {
  .provider-context,
  .dialog-footer {
    align-items: stretch;
    flex-direction: column;
  }
  .model-fields {
    grid-template-columns: 1fr;
  }
  .footer-actions {
    justify-content: flex-end;
  }
}
</style>
