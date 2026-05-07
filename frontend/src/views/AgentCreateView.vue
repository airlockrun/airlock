<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { create, fromJson } from '@bufbuild/protobuf'
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
  splitModelValue,
  type CatalogModel,
} from '@/composables/useModelCapabilities'
import { useProvidersStore } from '@/stores/providers'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { ws } from '@/api/ws'
import {
  GetAgentDetailResponseSchema,
  GetSystemSettingsResponseSchema,
  AgentModelConfigSchema,
} from '@/gen/airlock/v1/api_pb'
import BuildLogPanel from '@/components/agent/BuildLogPanel.vue'

const router = useRouter()
const store = useAgentsStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const toast = useToast()
const { groupModels, searchProviderOptions } = useModelCapabilities()

const name = ref('')
const slug = ref('')
const slugManual = ref(false)
const instructions = ref('')
const loading = ref(false)
const building = ref(false)
const buildError = ref('')
const buildAgentId = ref('')
const activeBuildId = ref<string | undefined>(undefined)

// All 8 capability override slots — empty = live inherit from system default.
// Mirrors the AgentModelConfig proto field names so this object can be
// shovelled straight into `create(AgentModelConfigSchema, ...)`.
interface ModelOverrides {
  buildModel: string
  execModel: string
  visionModel: string
  sttModel: string
  ttsModel: string
  imageGenModel: string
  embeddingModel: string
  searchModel: string
}
const emptyOverrides = (): ModelOverrides => ({
  buildModel: '', execModel: '', visionModel: '', sttModel: '',
  ttsModel: '', imageGenModel: '', embeddingModel: '', searchModel: '',
})
const overrides = ref<ModelOverrides>(emptyOverrides())
// System defaults shown inside placeholders so users see what "inherit" resolves to.
const systemDefaults = ref<ModelOverrides>(emptyOverrides())

let pollTimer: ReturnType<typeof setInterval> | null = null

onMounted(async () => {
  catalog.fetchConfiguredModels()
  catalog.fetchCapabilities()
  // Pickers fan out per (catalog provider × configured row), so we need
  // the providers list before the model dropdowns render.
  providers.fetchProviders()
  try {
    const { data } = await api.get('/api/v1/settings')
    const resp = fromJson(GetSystemSettingsResponseSchema, data)
    const s = resp.settings
    if (s) {
      systemDefaults.value = {
        buildModel:     s.defaultBuildModel || '',
        execModel:      s.defaultExecModel || '',
        visionModel:    s.defaultVisionModel || '',
        sttModel:       s.defaultSttModel || '',
        ttsModel:       s.defaultTtsModel || '',
        imageGenModel:  s.defaultImageGenModel || '',
        embeddingModel: s.defaultEmbeddingModel || '',
        searchModel:    s.defaultSearchModel || '',
      }
    }
  } catch { /* non-admin can't read settings — placeholders stay generic */ }
})

interface OverrideRow {
  key: keyof ModelOverrides
  label: string
  icon: string
  help: string
  options: any
  grouped: boolean
}

const coreRows = computed<OverrideRow[]>(() => [
  {
    key: 'buildModel',
    label: 'Build Model',
    icon: 'pi pi-hammer',
    help: 'Used by Sol to generate this agent\'s code. Leave empty to inherit the system default.',
    options: groupModels(isLanguage),
    grouped: true,
  },
  {
    key: 'execModel',
    label: 'Execution Model',
    icon: 'pi pi-align-left',
    help: 'Runtime default for LLM calls. Leave empty to inherit the system default.',
    options: groupModels(isLanguage),
    grouped: true,
  },
])

const advancedRows = computed<OverrideRow[]>(() => [
  {
    key: 'visionModel',
    label: 'Vision',
    icon: 'pi pi-image',
    help: 'Image → text tasks.',
    options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')),
    grouped: true,
  },
  {
    key: 'sttModel',
    label: 'STT',
    icon: 'pi pi-microphone',
    help: 'Speech-to-text transcription.',
    options: groupModels(isTranscription),
    grouped: true,
  },
  {
    key: 'ttsModel',
    label: 'TTS',
    icon: 'pi pi-volume-up',
    help: 'Text-to-speech synthesis.',
    options: groupModels(isSpeech),
    grouped: true,
  },
  {
    key: 'imageGenModel',
    label: 'Image Gen',
    icon: 'pi pi-palette',
    help: 'Text-to-image generation.',
    options: groupModels(isImageGen),
    grouped: true,
  },
  {
    key: 'embeddingModel',
    label: 'Embedding',
    icon: 'pi pi-database',
    help: 'Text → vector embeddings.',
    options: groupModels(isEmbedding),
    grouped: true,
  },
  {
    key: 'searchModel',
    label: 'Web Search',
    icon: 'pi pi-search',
    help: 'Search provider (provider ID, not a model).',
    options: searchProviderOptions.value,
    grouped: false,
  },
])

function placeholderFor(key: keyof ModelOverrides): string {
  const def = systemDefaults.value[key]
  return def ? `Inherit from system (${def})` : 'Inherit from system default'
}

watch(name, (v) => {
  if (!slugManual.value) {
    slug.value = v
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '')
  }
})

function onSlugInput() {
  slugManual.value = true
}

const canSubmit = computed(() => !!name.value && !!slug.value)

// Build+Exec ride on the CreateAgent proto; the other six have to be pushed
// via PUT /agents/{id}/models right after create because the create proto
// doesn't carry them yet.
const hasAdvancedOverrides = computed(() =>
  !!overrides.value.visionModel ||
  !!overrides.value.sttModel ||
  !!overrides.value.ttsModel ||
  !!overrides.value.imageGenModel ||
  !!overrides.value.embeddingModel ||
  !!overrides.value.searchModel
)

function onBuildDone(agentId: string) {
  stopPolling()
  toast.add({ severity: 'success', summary: 'Agent built successfully', life: 3000 })
  router.push(`/agents/${agentId}`)
}

function onBuildFailed(error: string) {
  stopPolling()
  buildError.value = error || 'Build failed.'
  building.value = false
}

async function onCancelBuild() {
  if (!buildAgentId.value) return
  try {
    await api.post(`/api/v1/agents/${buildAgentId.value}/builds/cancel`)
    toast.add({ severity: 'info', summary: 'Build cancelled', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Cancel failed', life: 5000 })
  }
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

function startPolling(agentId: string) {
  pollTimer = setInterval(async () => {
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}`)
      const agent = fromJson(GetAgentDetailResponseSchema, data).agent
      if (!agent) return
      if (agent.status === 'active') {
        onBuildDone(agentId)
      } else if (agent.status === 'failed') {
        onBuildFailed(agent.errorMessage)
      }
    } catch { /* ignore polling errors */ }
  }, 2000)
}

async function onSubmit() {
  buildError.value = ''
  if (!canSubmit.value) {
    toast.add({ severity: 'error', summary: 'Name and slug are required', life: 3000 })
    return
  }

  loading.value = true
  try {
    // Picker values are packed "rowUUID|modelName" tuples — split into the
    // (provider FK, bare model name) pair the backend expects per slot.
    const build = splitModelValue(overrides.value.buildModel)
    const exec = splitModelValue(overrides.value.execModel)
    const stt = splitModelValue(overrides.value.sttModel)
    const vision = splitModelValue(overrides.value.visionModel)
    const tts = splitModelValue(overrides.value.ttsModel)
    const imageGen = splitModelValue(overrides.value.imageGenModel)
    const embedding = splitModelValue(overrides.value.embeddingModel)
    const search = splitModelValue(overrides.value.searchModel)

    const agent = await store.createAgent(
      name.value,
      slug.value,
      build.modelName,
      build.providerRowID,
      exec.modelName,
      exec.providerRowID,
      instructions.value,
    )

    if (hasAdvancedOverrides.value) {
      const cfg = create(AgentModelConfigSchema, {
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
        slots:               [],
      })
      try {
        await store.updateModelConfig(agent.id, cfg)
      } catch (err: any) {
        // Non-fatal: the agent build is already running with the build+exec
        // pair that did go through. Tell the user the rest didn't stick.
        toast.add({
          severity: 'warn',
          summary: 'Agent created — advanced model overrides not saved',
          detail: err.response?.data?.error || String(err),
          life: 6000,
        })
      }
    }

    buildAgentId.value = agent.id
    building.value = true
    loading.value = false

    ws.reconnect()
    ws.onMessage('agent.build', (payload: any) => {
      if (payload?.agentId !== agent.id) return
      if (payload.buildId) activeBuildId.value = payload.buildId
      if (payload.status === 'complete' || payload.status === 'active' || payload.status === 'done') {
        onBuildDone(agent.id)
      } else if (payload.status === 'failed' || payload.status === 'error') {
        onBuildFailed(payload.error)
      }
    })
    startPolling(agent.id)
  } catch (err: any) {
    loading.value = false
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to create agent', life: 5000 })
  }
}

onUnmounted(() => { stopPolling() })
</script>

<template>
  <div style="max-width: 36rem">
    <h1 style="font-size: 1.5rem; margin-bottom: 1.5rem">Create Agent</h1>

    <form @submit.prevent="onSubmit" style="display: flex; flex-direction: column; gap: 1.25rem">
      <FloatLabel>
        <InputText id="agent-name" v-model="name" style="width: 100%" :disabled="building" />
        <label for="agent-name">Agent Name</label>
      </FloatLabel>

      <div>
        <FloatLabel>
          <InputText id="agent-slug" v-model="slug" style="width: 100%" :disabled="building" @input="onSlugInput" />
          <label for="agent-slug">Slug</label>
        </FloatLabel>
        <small style="color: var(--p-text-muted-color)">URL-safe identifier, auto-generated from name.</small>
      </div>

      <!-- Core models: Build + Exec, both optional -->
      <div
        v-for="row in coreRows"
        :key="row.key"
        style="display: flex; flex-direction: column; gap: 0.5rem"
      >
        <label :for="`override-${row.key}`" style="font-weight: 500; display: flex; align-items: center; gap: 0.5rem">
          <i :class="row.icon" />
          <span>{{ row.label }}</span>
        </label>
        <Select
          :id="`override-${row.key}`"
          v-model="overrides[row.key]"
          :options="row.options"
          optionLabel="label"
          optionValue="value"
          optionGroupLabel="label"
          optionGroupChildren="items"
          filter
          autoFilterFocus
          showClear
          :placeholder="placeholderFor(row.key)"
          :loading="catalog.loading"
          :disabled="building"
          style="width: 100%"
        />
        <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
      </div>

      <!-- Advanced capability overrides — collapsed by default -->
      <Fieldset legend="Other capability overrides" :toggleable="true" :collapsed="true">
        <div style="display: flex; flex-direction: column; gap: 1rem">
          <div
            v-for="row in advancedRows"
            :key="row.key"
            style="display: flex; flex-direction: column; gap: 0.5rem"
          >
            <label :for="`override-${row.key}`" style="font-weight: 500; display: flex; align-items: center; gap: 0.5rem">
              <i :class="row.icon" />
              <span>{{ row.label }}</span>
            </label>
            <Select
              v-if="row.grouped"
              :id="`override-${row.key}`"
              v-model="overrides[row.key]"
              :options="row.options"
              optionLabel="label"
              optionValue="value"
              optionGroupLabel="label"
              optionGroupChildren="items"
              filter
              autoFilterFocus
              showClear
              :placeholder="placeholderFor(row.key)"
              :loading="catalog.loading"
              :disabled="building"
              style="width: 100%"
            />
            <Select
              v-else
              :id="`override-${row.key}`"
              v-model="overrides[row.key]"
              :options="row.options"
              optionLabel="label"
              optionValue="value"
              filter
              autoFilterFocus
              showClear
              :placeholder="placeholderFor(row.key)"
              :loading="catalog.loading"
              :disabled="building"
              style="width: 100%"
            />
            <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
          </div>
        </div>
      </Fieldset>

      <div>
        <label for="instructions" style="display: block; margin-bottom: 0.5rem; font-weight: 500">Instructions</label>
        <Textarea
          id="instructions"
          v-model="instructions"
          :auto-resize="true"
          rows="3"
          placeholder="Describe what this agent should do and what tools it needs, e.g. &quot;Connect to Gmail and summarize my daily emails&quot;. Leave empty for a default agent."
          :disabled="building"
          style="width: 100%"
        />
      </div>

      <Button
        v-if="!building"
        type="submit"
        label="Create"
        icon="pi pi-plus"
        :loading="loading"
        :disabled="!canSubmit"
        style="align-self: flex-end"
      />
    </form>

    <!-- Build progress -->
    <div v-if="building" style="margin-top: 1.5rem">
      <p style="margin-bottom: 0.75rem; font-weight: 600">Building {{ name }}...</p>
      <ProgressBar mode="indeterminate" style="height: 0.375rem; margin-bottom: 0.75rem" />
      <BuildLogPanel :agent-id="buildAgentId" :build-id="activeBuildId" :active="building" @cancel="onCancelBuild" />
    </div>

    <Message v-if="buildError" severity="error" :closable="false" style="margin-top: 1rem">
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 20rem; overflow-y: auto">{{ buildError }}</pre>
    </Message>
  </div>
</template>
