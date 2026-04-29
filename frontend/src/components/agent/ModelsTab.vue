<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
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
  type CatalogModel,
} from '@/composables/useModelCapabilities'
import type { AgentModelConfig, ModelSlotInfo } from '@/gen/airlock/v1/api_pb'
import { AgentModelConfigSchema, ModelSlotInfoSchema } from '@/gen/airlock/v1/api_pb'

const props = defineProps<{ agentId: string }>()

const agents = useAgentsStore()
const catalog = useCatalogStore()
const toast = useToast()
const { groupModels, searchProviderOptions } = useModelCapabilities()

const loading = ref(true)
const saving = ref(false)
const config = ref<AgentModelConfig>(create(AgentModelConfigSchema))

onMounted(async () => {
  try {
    await Promise.all([
      catalog.fetchConfiguredModels(),
      catalog.fetchCapabilities(),
    ])
    config.value = await agents.fetchModelConfig(props.agentId)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to load model config', life: 5000 })
  } finally {
    loading.value = false
  }
})

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
    help: 'Search provider override (provider ID, not a model).',
    options: searchProviderOptions.value,
    grouped: false,
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
  }
  return 'info'
}

async function save() {
  saving.value = true
  try {
    // create() gives us the typed proto with all required fields; we then
    // copy current config values onto it to keep the $typeName discriminator.
    const next = create(AgentModelConfigSchema, {
      buildModel: config.value.buildModel,
      execModel: config.value.execModel,
      sttModel: config.value.sttModel,
      visionModel: config.value.visionModel,
      ttsModel: config.value.ttsModel,
      imageGenModel: config.value.imageGenModel,
      embeddingModel: config.value.embeddingModel,
      searchModel: config.value.searchModel,
      slots: config.value.slots.map((s: ModelSlotInfo) =>
        create(ModelSlotInfoSchema, {
          slug: s.slug,
          capability: s.capability,
          description: s.description,
          assignedModel: s.assignedModel,
        }),
      ),
    })
    config.value = await agents.updateModelConfig(props.agentId, next)
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
  <div v-else style="display: flex; flex-direction: column; gap: 1.5rem">
    <!-- Per-agent capability overrides -->
    <Card>
      <template #title>Capability Overrides</template>
      <template #subtitle>
        Override system defaults for this agent. Leave empty to inherit the system default for that capability.
      </template>
      <template #content>
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
              v-model="(config as any)[row.key]"
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
              v-model="(config as any)[row.key]"
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
            <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
          </div>
        </div>
      </template>
    </Card>

    <!-- Declared slots -->
    <Card>
      <template #title>Model Slots</template>
      <template #subtitle>
        Named slots the agent declared via <code>RegisterModel</code>. Assigning a model binds the slot directly; empty falls through to the capability override above, then the system default.
      </template>
      <template #content>
        <div v-if="config.slots.length === 0" style="color: var(--p-text-muted-color); padding: 0.5rem 0">
          This agent hasn't declared any model slots. Add
          <code>agent.RegisterModel(slug, agentsdk.ModelSlotOpts{...})</code> in the agent code to expose a slot here.
        </div>
        <div v-else style="display: flex; flex-direction: column; gap: 1rem">
          <div
            v-for="slot in config.slots"
            :key="slot.slug"
            style="display: flex; flex-direction: column; gap: 0.5rem; padding: 0.75rem; border: 1px solid var(--p-surface-border); border-radius: var(--p-border-radius)"
          >
            <div style="display: flex; align-items: center; gap: 0.5rem">
              <span style="font-family: var(--p-font-family-monospace, monospace); font-weight: 600">{{ slot.slug }}</span>
              <Tag :value="slot.capability" :severity="capabilitySeverity(slot.capability)" />
            </div>
            <small v-if="slot.description" style="color: var(--p-text-muted-color)">{{ slot.description }}</small>
            <Select
              v-model="slot.assignedModel"
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
          </div>
        </div>
      </template>
    </Card>

    <div>
      <Button label="Save" :loading="saving" @click="save" />
    </div>
  </div>
</template>
