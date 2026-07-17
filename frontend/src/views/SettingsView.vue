<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { fromJson, toJson } from '@bufbuild/protobuf'
import { useAuthStore } from '@/stores/auth'
import { useCatalogStore } from '@/stores/catalog'
import { useToast } from 'primevue/usetoast'
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
import api from '@/api/client'
import {
  GetSystemSettingsResponseSchema,
  UpdateSystemSettingsRequestSchema,
  UpdateSystemSettingsResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import type { SystemSettingsInfo } from '@/gen/airlock/v1/types_pb'

const auth = useAuthStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities()

// Default models (admin only). Keyed by the SystemSettingsInfo field key
// (camelCase) so assignment back to the proto payload is trivial.
const defaults = ref<Record<keyof SystemSettingsInfo & string, string>>({
  defaultBuildModel: '',
  defaultExecModel: '',
  defaultSttModel: '',
  defaultVisionModel: '',
  defaultTtsModel: '',
  defaultImageGenModel: '',
  defaultEmbeddingModel: '',
  defaultSearchModel: '',
} as Record<keyof SystemSettingsInfo & string, string>)
const defaultsLoading = ref(false)

// Pairs each picker key with its companion *_provider_id field on the
// SystemSettingsInfo proto. Read/write paths use this to pack/unpack the
// (rowUUID, modelName) tuple the picker stores in `defaults`.
const slotProviderField: Record<keyof typeof defaults.value, keyof SystemSettingsInfo> = {
  defaultBuildModel:     'defaultBuildProviderId',
  defaultExecModel:      'defaultExecProviderId',
  defaultSttModel:       'defaultSttProviderId',
  defaultVisionModel:    'defaultVisionProviderId',
  defaultTtsModel:       'defaultTtsProviderId',
  defaultImageGenModel:  'defaultImageGenProviderId',
  defaultEmbeddingModel: 'defaultEmbeddingProviderId',
  defaultSearchModel:    'defaultSearchProviderId',
}

function applySettings(info: SystemSettingsInfo) {
  for (const k of Object.keys(defaults.value) as (keyof typeof defaults.value)[]) {
    const modelName = (info as any)[k] || ''
    const providerKey = slotProviderField[k]
    const providerRowID = (info as any)[providerKey] || ''
    defaults.value[k] = providerRowID || modelName
      ? packModelValue(providerRowID, modelName)
      : ''
  }
}

onMounted(async () => {
  if (auth.can('tenant.settings.update')) {
    // Pickers depend on configured providers — fetch first so the
    // applySettings packed values match an option in the dropdown.
    await providers.fetchProviders()
    try {
      const { data } = await api.get('/api/v1/settings')
      const resp = fromJson(GetSystemSettingsResponseSchema, data)
      if (resp.settings) applySettings(resp.settings)
    } catch { /* ignore */ }
    catalog.fetchConfiguredModels()
    catalog.fetchCapabilities()
  }
})

// Declarative row definitions — each row drives a dropdown. Build + Exec are
// agent roles (kept from before) and the remaining six mirror the capability
// matrix on the Providers page.
interface DefaultRow {
  key: string               // matches `defaults` key / system_settings column suffix
  label: string
  icon: string
  help: string
  options: { label: string; value: string }[] | { label: string; items: { label: string; value: string }[] }[]
  placeholder: string
}

const defaultRows = computed<DefaultRow[]>(() => [
  {
    key: 'defaultBuildModel',
    label: 'Build Model',
    icon: 'pi pi-hammer',
    help: 'Used by Sol for app code generation and upgrades.',
    options: groupModels(isLanguage),
    placeholder: 'Select default build model',
  },
  {
    key: 'defaultExecModel',
    label: 'Execution Model (Text)',
    icon: 'pi pi-align-left',
    help: 'Runtime default when apps make language-model calls.',
    options: groupModels(isLanguage),
    placeholder: 'Select default execution model',
  },
  {
    key: 'defaultVisionModel',
    label: 'Vision',
    icon: 'pi pi-image',
    help: 'Default model for image → text tasks.',
    options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')),
    placeholder: 'Select vision model',
  },
  {
    key: 'defaultSttModel',
    label: 'STT',
    icon: 'pi pi-microphone',
    help: 'Telegram voice notes are auto-transcribed with this model before being sent to apps. Leave empty to disable.',
    options: groupModels(isTranscription),
    placeholder: 'Select speech-to-text model',
  },
  {
    key: 'defaultTtsModel',
    label: 'TTS',
    icon: 'pi pi-volume-up',
    help: 'Default model for text → speech synthesis.',
    options: groupModels(isSpeech),
    placeholder: 'Select text-to-speech model',
  },
  {
    key: 'defaultImageGenModel',
    label: 'Image Gen',
    icon: 'pi pi-palette',
    help: 'Default model for text → image generation.',
    options: groupModels(isImageGen),
    placeholder: 'Select image-generation model',
  },
  {
    key: 'defaultEmbeddingModel',
    label: 'Embedding',
    icon: 'pi pi-database',
    help: 'Default model for text → vector embeddings (e.g. OpenAI text-embedding-3-small).',
    options: groupModels(isEmbedding),
    placeholder: 'Select embedding model',
  },
  {
    key: 'defaultSearchModel',
    label: 'Web Search',
    icon: 'pi pi-search',
    help: 'Default web search backend + model. Only tool-capable text models are listed (the backend runs search by calling the model with a search tool). Pick "Provider default" to let the backend choose its model.',
    options: searchModelOptions.value,
    placeholder: 'Select search backend',
  },
])

// A flat options list is a plain array without `items`; a grouped one has
// `items` per group. The <Select> component needs different props for each
// shape, so we detect which one we're dealing with.
function isGrouped(opts: DefaultRow['options']): boolean {
  return opts.length > 0 && typeof (opts[0] as any).items !== 'undefined'
}

async function saveDefaults() {
  defaultsLoading.value = true
  try {
    const split = (k: keyof typeof defaults.value) => splitModelValue(defaults.value[k])
    const build = split('defaultBuildModel')
    const exec = split('defaultExecModel')
    const stt = split('defaultSttModel')
    const vision = split('defaultVisionModel')
    const tts = split('defaultTtsModel')
    const imageGen = split('defaultImageGenModel')
    const embedding = split('defaultEmbeddingModel')
    const search = split('defaultSearchModel')
    const info: SystemSettingsInfo = {
      $typeName: 'airlock.v1.SystemSettingsInfo',
      defaultBuildModel:          build.modelName,
      defaultBuildProviderId:     build.providerRowID,
      defaultExecModel:           exec.modelName,
      defaultExecProviderId:      exec.providerRowID,
      defaultSttModel:            stt.modelName,
      defaultSttProviderId:       stt.providerRowID,
      defaultVisionModel:         vision.modelName,
      defaultVisionProviderId:    vision.providerRowID,
      defaultTtsModel:            tts.modelName,
      defaultTtsProviderId:       tts.providerRowID,
      defaultImageGenModel:       imageGen.modelName,
      defaultImageGenProviderId:  imageGen.providerRowID,
      defaultEmbeddingModel:      embedding.modelName,
      defaultEmbeddingProviderId: embedding.providerRowID,
      defaultSearchModel:         search.modelName,
      defaultSearchProviderId:    search.providerRowID,
    }
    const req = toJson(UpdateSystemSettingsRequestSchema, {
      $typeName: 'airlock.v1.UpdateSystemSettingsRequest',
      settings: info,
    })
    const { data } = await api.put('/api/v1/settings', req)
    const resp = fromJson(UpdateSystemSettingsResponseSchema, data)
    if (resp.settings) applySettings(resp.settings)
    toast.add({ severity: 'success', summary: 'Defaults saved', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed', life: 5000 })
  } finally {
    defaultsLoading.value = false
  }
}

</script>

<template>
  <div style="max-width: 36rem">
    <h1 style="margin: 0 0 1.5rem; font-size: 1.5rem">System defaults</h1>

    <!-- Default Models (admin only) -->
    <Card v-if="auth.can('tenant.settings.update')" style="margin-bottom: 1.5rem">
      <template #title>Default Models</template>
      <template #subtitle>
        Per-capability defaults. Used wherever the system needs a model for a capability and no app-specific override is set.
      </template>
      <template #content>
        <div style="display: flex; flex-direction: column; gap: 1.25rem">
          <div
            v-for="row in defaultRows"
            :key="row.key"
            style="display: flex; flex-direction: column; gap: 0.5rem"
          >
            <label :for="`default-${row.key}`" style="font-weight: 500; display: flex; align-items: center; gap: 0.5rem">
              <i :class="row.icon" />
              <span>{{ row.label }}</span>
            </label>
            <Select
              v-if="isGrouped(row.options)"
              :id="`default-${row.key}`"
              v-model="defaults[row.key]"
              :options="row.options"
              optionLabel="label"
              optionValue="value"
              optionGroupLabel="label"
              optionGroupChildren="items"
              filter
              autoFilterFocus
              showClear
              :placeholder="row.placeholder"
              :loading="catalog.loading"
              style="width: 100%"
            />
            <Select
              v-else
              :id="`default-${row.key}`"
              v-model="defaults[row.key]"
              :options="row.options"
              optionLabel="label"
              optionValue="value"
              filter
              autoFilterFocus
              showClear
              :placeholder="row.placeholder"
              :loading="catalog.loading"
              style="width: 100%"
            />
            <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
          </div>
          <Button label="Save" :loading="defaultsLoading" @click="saveDefaults" style="align-self: flex-start" />
        </div>
      </template>
    </Card>
  </div>
</template>
