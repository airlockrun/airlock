<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { create } from '@bufbuild/protobuf'
import { useToast } from 'primevue/usetoast'
import { useAgentsStore } from '@/stores/agents'
import { useCatalogStore } from '@/stores/catalog'
import {
  useModelCapabilities,
  isLanguage,
  isEmbedding,
  isImageGen,
  isSpeech,
  isTranscription,
  hasCap,
  packModelValue,
  splitModelValue,
  type CatalogModel,
} from '@/composables/useModelCapabilities'
import { useProvidersStore } from '@/stores/providers'
import { useModelsAllowedStore } from '@/stores/modelsAllowed'
import { useAuthStore } from '@/stores/auth'
import type { AgentModelConfig, ModelSlotInfo } from '@/gen/airlock/v1/api_pb'
import { AgentModelConfigSchema, ModelSlotInfoSchema } from '@/gen/airlock/v1/api_pb'

// yourAccess is the caller's per-agent access ("admin"/"user"/"public"), passed
// down from AgentDetailView. Editing models needs both agent-admin (to save) and
// the manager+ provider list (to pick from); otherwise the tab is read-only.
const props = defineProps<{ agentId: string; yourAccess?: string }>()
const emit = defineEmits<{ populated: [count: number] }>()

const agents = useAgentsStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const modelsAllowed = useModelsAllowedStore()
const auth = useAuthStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities({ restrictToAllowed: true })

// Editing requires the provider list (manager+, TenantProviderView) AND
// agent-admin. A plain member / users-group caller sees the current models
// read-only and we never query providers for them.
const canEdit = computed(() => auth.can('tenant.provider.view') && props.yourAccess === 'admin')

const loading = ref(true)
const saving = ref(false)
const config = ref<AgentModelConfig>(create(AgentModelConfigSchema))
// Models is "populated" once the config loads — every LLM-powered agent
// needs at least the chat model wired, so hiding it on the empty initial
// state would be misleading and re-show would jitter after a fast fetch.
watch(loading, (v) => emit('populated', v ? 0 : 1), { immediate: true })

// pickerValues holds the packed "rowUUID|modelName" strings that the
// dropdowns v-model against. Kept parallel to `config` so picker writes
// don't smear the underlying proto. We reload from `config` after every
// fetch and serialize back into the proto on save.
const pickerValues = ref<Record<string, string>>({})
const slotPickerValues = ref<Record<string, string>>({})

const slotProviderField: Record<string, keyof AgentModelConfig> = {
  buildModel:     'buildProviderId',
  execModel:      'execProviderId',
  sttModel:       'sttProviderId',
  visionModel:    'visionProviderId',
  ttsModel:       'ttsProviderId',
  imageGenModel:  'imageGenProviderId',
  embeddingModel: 'embeddingProviderId',
  searchModel:    'searchProviderId',
}

function refreshPickerValues() {
  for (const [modelKey, providerKey] of Object.entries(slotProviderField)) {
    const modelName = (config.value as any)[modelKey] || ''
    const providerRowID = (config.value as any)[providerKey] || ''
    pickerValues.value[modelKey] = providerRowID || modelName
      ? packModelValue(providerRowID, modelName)
      : ''
  }
  slotPickerValues.value = {}
  for (const slot of config.value.slots) {
    slotPickerValues.value[slot.slug] = slot.assignedProviderId || slot.assignedModel
      ? packModelValue(slot.assignedProviderId, slot.assignedModel)
      : ''
  }
}

onMounted(async () => {
  try {
    // Picker data (catalog + providers + allowed set) is only needed — and only
    // permitted (providers is manager+) — when the caller can edit.
    if (canEdit.value) {
      await Promise.all([
        catalog.fetchConfiguredModels(),
        catalog.fetchCapabilities(),
        providers.fetchProviders(),
        modelsAllowed.fetchAllowed(),
      ])
    }
    config.value = await agents.fetchModelConfig(props.agentId)
    refreshPickerValues()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to load model config', life: 5000 })
  } finally {
    loading.value = false
  }
})

// Read-only display metadata (label + icon) for the eight capability slots,
// keyed by the AgentModelConfig field. Used when canEdit is false to show the
// current assignment without the catalog-backed picker.
const readonlyRows: { key: keyof AgentModelConfig; label: string; icon: string }[] = [
  { key: 'buildModel', label: 'Build Model', icon: 'pi pi-hammer' },
  { key: 'execModel', label: 'Execution Model (Text)', icon: 'pi pi-align-left' },
  { key: 'visionModel', label: 'Vision', icon: 'pi pi-image' },
  { key: 'sttModel', label: 'STT', icon: 'pi pi-microphone' },
  { key: 'ttsModel', label: 'TTS', icon: 'pi pi-volume-up' },
  { key: 'imageGenModel', label: 'Image Gen', icon: 'pi pi-palette' },
  { key: 'embeddingModel', label: 'Embedding', icon: 'pi pi-database' },
  { key: 'searchModel', label: 'Web Search', icon: 'pi pi-search' },
]
function currentModel(key: keyof AgentModelConfig): string {
  const set = (config.value as any)[key]
  if (set) return set
  const def = config.value.systemDefaults?.[key as string]
  return def ? `Inherits default · ${def}` : 'Inherits system default'
}

// --- Rows. Each binds to a capability-override field on `config`.
interface ConfigRow {
  key: keyof AgentModelConfig
  label: string
  icon: string
  help: string
  options: { label: string; items: { label: string; value: string }[] }[] | { label: string; value: string }[]
  grouped: boolean
}

const overrideRows = computed<ConfigRow[]>(() => [
  {
    key: 'buildModel',
    label: 'Build Model',
    icon: 'pi pi-hammer',
    help: 'Override the system default build model for this agent.',
    options: groupModels(isLanguage),
    grouped: true,
  },
  {
    key: 'execModel',
    label: 'Execution Model (Text)',
    icon: 'pi pi-align-left',
    help: 'Runtime default when the agent makes text LLM calls without a specific slug.',
    options: groupModels(isLanguage),
    grouped: true,
  },
  {
    key: 'visionModel',
    label: 'Vision',
    icon: 'pi pi-image',
    help: 'Image → text tasks (VM attachToContext on images, explicit vision capability LLM calls).',
    options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')),
    grouped: true,
  },
  {
    key: 'sttModel',
    label: 'STT',
    icon: 'pi pi-microphone',
    help: 'Speech-to-text — used by agent.TranscriptionModel and the VM transcribeAudio built-in.',
    options: groupModels(isTranscription),
    grouped: true,
  },
  {
    key: 'ttsModel',
    label: 'TTS',
    icon: 'pi pi-volume-up',
    help: 'Text-to-speech — used by agent.SpeechModel and the VM generateSpeech built-in.',
    options: groupModels(isSpeech),
    grouped: true,
  },
  {
    key: 'imageGenModel',
    label: 'Image Gen',
    icon: 'pi pi-palette',
    help: 'Text-to-image — used by agent.ImageModel and the VM generateImage built-in.',
    options: groupModels(isImageGen),
    grouped: true,
  },
  {
    key: 'embeddingModel',
    label: 'Embedding',
    icon: 'pi pi-database',
    help: 'Text embeddings — used by agent.EmbeddingModel and the VM embed built-in.',
    options: groupModels(isEmbedding),
    grouped: true,
  },
  {
    key: 'searchModel',
    label: 'Web Search',
    icon: 'pi pi-search',
    help: 'Web search backend + model. Pick "Provider default" to let the backend choose its model.',
    options: searchModelOptions.value,
    grouped: true,
  },
])

function optionsForCapability(capability: string) {
  switch (capability) {
    case 'text': return groupModels(isLanguage)
    case 'vision': return groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision'))
    case 'image': return groupModels(isImageGen)
    case 'speech': return groupModels(isSpeech)
    case 'transcription': return groupModels(isTranscription)
    case 'embedding': return groupModels(isEmbedding)
    // Search slots bind a search-capable provider (+ optional model). Reuses the
    // same source as the capability-default picker: filters to providers whose
    // catalog capabilities include "search" and offers a provider-only entry.
    case 'search': return searchModelOptions.value
  }
  return []
}

function capabilitySeverity(capability: string): string {
  switch (capability) {
    case 'text': return 'info'
    case 'vision': return 'secondary'
    case 'image': return 'warn'
    case 'speech':
    case 'transcription': return 'success'
    case 'embedding': return 'contrast'
    case 'search': return 'help'
  }
  return 'info'
}

async function save() {
  saving.value = true
  try {
    // Picker values are packed "rowUUID|modelName" — split each into the
    // (provider FK, bare model name) pair the proto expects. Empty-empty
    // ⇄ inherit; both halves move together.
    const split = (k: string) => splitModelValue(pickerValues.value[k] || '')
    const build = split('buildModel')
    const exec = split('execModel')
    const stt = split('sttModel')
    const vision = split('visionModel')
    const tts = split('ttsModel')
    const imageGen = split('imageGenModel')
    const embedding = split('embeddingModel')
    const search = split('searchModel')
    const next = create(AgentModelConfigSchema, {
      buildModel:          build.modelName,
      buildProviderId:     build.providerRowID,
      execModel:           exec.modelName,
      execProviderId:      exec.providerRowID,
      sttModel:            stt.modelName,
      sttProviderId:       stt.providerRowID,
      visionModel:         vision.modelName,
      visionProviderId:    vision.providerRowID,
      ttsModel:            tts.modelName,
      ttsProviderId:       tts.providerRowID,
      imageGenModel:       imageGen.modelName,
      imageGenProviderId:  imageGen.providerRowID,
      embeddingModel:      embedding.modelName,
      embeddingProviderId: embedding.providerRowID,
      searchModel:         search.modelName,
      searchProviderId:    search.providerRowID,
      slots: config.value.slots.map((s: ModelSlotInfo) => {
        const slotSplit = splitModelValue(slotPickerValues.value[s.slug] || '')
        return create(ModelSlotInfoSchema, {
          slug:               s.slug,
          capability:         s.capability,
          description:        s.description,
          assignedModel:      slotSplit.modelName,
          assignedProviderId: slotSplit.providerRowID,
        })
      }),
    })
    config.value = await agents.updateModelConfig(props.agentId, next)
    refreshPickerValues()
    toast.add({ severity: 'success', summary: 'Models saved', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Save failed', life: 5000 })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div v-if="loading" style="padding: 1rem">
    <Skeleton height="2rem" style="margin-bottom: 1rem" />
    <Skeleton height="12rem" />
  </div>
  <div v-else style="display: flex; flex-direction: column; gap: 1.75rem">
    <template v-if="canEdit">
    <!-- Per-agent capability overrides -->
    <div>
      <h3 class="models-subhead">Capability overrides</h3>
      <p class="models-sub">
        Override system defaults for this agent. Leave empty to inherit the system default for that capability.
      </p>
      <div style="display: flex; flex-direction: column; gap: 1.25rem">
        <div
          v-for="row in overrideRows"
          :key="row.key as string"
          style="display: flex; flex-direction: column; gap: 0.5rem"
        >
          <label :for="`override-${row.key as string}`" style="font-weight: 500; display: flex; align-items: center; gap: 0.5rem">
            <i :class="row.icon" />
            <span>{{ row.label }}</span>
          </label>
          <Select
            v-if="row.grouped"
            :id="`override-${row.key as string}`"
            v-model="pickerValues[row.key as string]"
            :options="row.options"
            optionLabel="label"
            optionValue="value"
            optionGroupLabel="label"
            optionGroupChildren="items"
            filter
            autoFilterFocus
            showClear
            placeholder="Inherit system default"
            :loading="catalog.loading"
            style="width: 100%"
          />
          <Select
            v-else
            :id="`override-${row.key as string}`"
            v-model="pickerValues[row.key as string]"
            :options="row.options"
            optionLabel="label"
            optionValue="value"
            filter
            autoFilterFocus
            showClear
            placeholder="Inherit system default"
            :loading="catalog.loading"
            style="width: 100%"
          />
          <small v-if="!pickerValues[row.key as string] && config.systemDefaults?.[row.key as string]" style="color: var(--p-text-muted-color)">
            Inherits default: <strong>{{ config.systemDefaults[row.key as string] }}</strong>
          </small>
          <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
        </div>
      </div>
    </div>

    <!-- Declared slots — only renders when the agent declared any -->
    <div v-if="config.slots.length > 0">
      <h3 class="models-subhead">Model slots</h3>
      <p class="models-sub">
        Named slots the agent declared via <code>RegisterModel</code>. Assigning a model binds the slot directly; empty falls through to the capability override above, then the system default.
      </p>
      <div style="display: flex; flex-direction: column; gap: 1rem">
        <div
          v-for="slot in config.slots"
          :key="slot.slug"
          style="display: flex; flex-direction: column; gap: 0.5rem; padding: 0.75rem; border: 1px solid var(--p-content-border-color); border-radius: var(--p-border-radius)"
        >
          <div style="display: flex; align-items: center; gap: 0.5rem">
            <span style="font-family: var(--p-font-family-monospace, monospace); font-weight: 600">{{ slot.slug }}</span>
            <Tag :value="slot.capability" :severity="capabilitySeverity(slot.capability)" />
          </div>
          <small v-if="slot.description" style="color: var(--p-text-muted-color)">{{ slot.description }}</small>
          <Select
            v-model="slotPickerValues[slot.slug]"
            :options="optionsForCapability(slot.capability)"
            optionLabel="label"
            optionValue="value"
            optionGroupLabel="label"
            optionGroupChildren="items"
            filter
            autoFilterFocus
            showClear
            placeholder="Inherit capability default"
            :loading="catalog.loading"
            style="width: 100%"
          />
          <small v-if="!slotPickerValues[slot.slug] && slot.resolvedModel" style="color: var(--p-text-muted-color)">
            Inherits default: <strong>{{ slot.resolvedModel }}</strong>
          </small>
        </div>
      </div>
    </div>

    <div>
      <Button label="Save" :loading="saving" @click="save" />
    </div>
    </template>

    <!-- Read-only view: non-admin members / users-group can't edit models and
         we never query providers for them. Show the current assignments. -->
    <template v-else>
      <div>
        <h3 class="models-subhead">Models</h3>
        <p class="models-sub">
          Models configured for this agent. Editing requires manager access and agent-admin.
        </p>
        <div style="display: flex; flex-direction: column; gap: 0.75rem">
          <div
            v-for="row in readonlyRows"
            :key="row.key as string"
            style="display: flex; align-items: center; gap: 0.5rem"
          >
            <i :class="row.icon" style="width: 1.25rem; color: var(--p-text-muted-color)" />
            <span style="font-weight: 500; min-width: 11rem">{{ row.label }}</span>
            <span style="color: var(--p-text-muted-color)">{{ currentModel(row.key) }}</span>
          </div>
        </div>
      </div>
      <div v-if="config.slots.length > 0">
        <h3 class="models-subhead">Model slots</h3>
        <div style="display: flex; flex-direction: column; gap: 0.5rem">
          <div
            v-for="slot in config.slots"
            :key="slot.slug"
            style="display: flex; align-items: center; gap: 0.5rem"
          >
            <span style="font-family: var(--p-font-family-monospace, monospace); font-weight: 600; min-width: 11rem">{{ slot.slug }}</span>
            <span style="color: var(--p-text-muted-color)">{{ slot.assignedModel || (slot.resolvedModel ? `Inherits default · ${slot.resolvedModel}` : 'Inherits capability default') }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.models-subhead {
  margin: 0 0 0.35rem;
  font-size: 1rem;
  font-weight: 500;
}
.models-sub {
  margin: 0 0 1rem;
  color: var(--p-text-muted-color);
  font-size: 0.85rem;
}
</style>
