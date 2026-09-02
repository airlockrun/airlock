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
import { useAirlockI18n } from '@/i18n'

const auth = useAuthStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities()
const { t, locale, availableLocales, setLocale } = useAirlockI18n()
const uiLocale = computed({
  get: () => locale.value,
  set: (value: string) => setLocale(value),
})
const localeOptions = computed(() => availableLocales.map(value => ({
  label: value === 'en'
    ? t('administration.locale.english')
    : value === 'ru'
      ? t('administration.locale.russian')
      : value,
  value,
})))

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
  if (availableLocales.includes(info.uiLocale)) setLocale(info.uiLocale)
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
    let info: SystemSettingsInfo | undefined
    try {
      const { data } = await api.get('/api/v1/settings')
      const resp = fromJson(GetSystemSettingsResponseSchema, data)
      info = resp.settings
    } catch { /* ignore */ }
    if (info) applySettings(info)
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
    label: t('administration.settings.buildLabel'),
    icon: 'pi pi-hammer',
    help: t('administration.settings.buildHelp'),
    options: groupModels(isLanguage),
    placeholder: t('administration.settings.buildPlaceholder'),
  },
  {
    key: 'defaultExecModel',
    label: t('administration.settings.executionLabel'),
    icon: 'pi pi-align-left',
    help: t('administration.settings.executionHelp'),
    options: groupModels(isLanguage),
    placeholder: t('administration.settings.executionPlaceholder'),
  },
  {
    key: 'defaultVisionModel',
    label: t('administration.capability.vision'),
    icon: 'pi pi-image',
    help: t('administration.settings.visionHelp'),
    options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')),
    placeholder: t('administration.settings.visionPlaceholder'),
  },
  {
    key: 'defaultSttModel',
    label: t('administration.settings.transcriptionLabel'),
    icon: 'pi pi-microphone',
    help: t('administration.settings.transcriptionHelp'),
    options: groupModels(isTranscription),
    placeholder: t('administration.settings.transcriptionPlaceholder'),
  },
  {
    key: 'defaultTtsModel',
    label: t('administration.settings.speechLabel'),
    icon: 'pi pi-volume-up',
    help: t('administration.settings.speechHelp'),
    options: groupModels(isSpeech),
    placeholder: t('administration.settings.speechPlaceholder'),
  },
  {
    key: 'defaultImageGenModel',
    label: t('administration.settings.imageGenerationLabel'),
    icon: 'pi pi-palette',
    help: t('administration.settings.imageGenerationHelp'),
    options: groupModels(isImageGen),
    placeholder: t('administration.settings.imageGenerationPlaceholder'),
  },
  {
    key: 'defaultEmbeddingModel',
    label: t('administration.capability.embedding'),
    icon: 'pi pi-database',
    help: t('administration.settings.embeddingHelp'),
    options: groupModels(isEmbedding),
    placeholder: t('administration.settings.embeddingPlaceholder'),
  },
  {
    key: 'defaultSearchModel',
    label: t('administration.settings.searchLabel'),
    icon: 'pi pi-search',
    help: t('administration.settings.searchHelp'),
    options: searchModelOptions.value,
    placeholder: t('administration.settings.searchPlaceholder'),
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
  let savedSettings: SystemSettingsInfo | undefined
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
      uiLocale:                   uiLocale.value,
    }
    const req = toJson(UpdateSystemSettingsRequestSchema, {
      $typeName: 'airlock.v1.UpdateSystemSettingsRequest',
      settings: info,
    })
    const { data } = await api.put('/api/v1/settings', req)
    const resp = fromJson(UpdateSystemSettingsResponseSchema, data)
    savedSettings = resp.settings
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.settings.failed'), life: 5000 })
    return
  } finally {
    defaultsLoading.value = false
  }
  if (savedSettings) applySettings(savedSettings)
  toast.add({ severity: 'success', summary: t('administration.settings.saved'), life: 3000 })
}

</script>

<template>
  <div style="max-width: 36rem">
    <h1 style="margin: 0 0 1.5rem; font-size: 1.5rem">{{ t('administration.settings.title') }}</h1>

    <!-- Default Models (admin only) -->
    <Card v-if="auth.can('tenant.settings.update')" style="margin-bottom: 1.5rem">
      <template #title>{{ t('administration.settings.systemSettings') }}</template>
      <template #subtitle>
        {{ t('administration.settings.subtitle') }}
      </template>
      <template #content>
        <div style="display: flex; flex-direction: column; gap: 1.25rem">
          <div style="display: flex; flex-direction: column; gap: 0.5rem">
            <label for="system-ui-locale" style="font-weight: 500">{{ t('administration.settings.interfaceLanguage') }}</label>
            <Select
              id="system-ui-locale"
              v-model="uiLocale"
              :options="localeOptions"
              optionLabel="label"
              optionValue="value"
              style="width: 100%"
            />
            <small style="color: var(--p-text-muted-color)">{{ t('administration.settings.interfaceLanguageHelp') }}</small>
          </div>
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
          <Button :label="t('administration.action.save')" :loading="defaultsLoading" @click="saveDefaults" style="align-self: flex-start" />
        </div>
      </template>
    </Card>
  </div>
</template>
