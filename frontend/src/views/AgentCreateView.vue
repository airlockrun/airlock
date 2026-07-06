<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { create, fromJson } from '@bufbuild/protobuf'
import { useAgentsStore } from '@/stores/agents'
import { useBuildsStore } from '@/stores/builds'
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
import { useModelsAllowedStore } from '@/stores/modelsAllowed'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { ws } from '@/api/ws'
import {
  GetAgentDetailResponseSchema,
  GetSystemSettingsResponseSchema,
  GetAgentSDKInfoResponseSchema,
  AgentModelConfigSchema,
} from '@/gen/airlock/v1/api_pb'

const router = useRouter()
const store = useAgentsStore()
const buildsStore = useBuildsStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const modelsAllowed = useModelsAllowedStore()
const gitCredsStore = useGitCredentialsStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities({ restrictToAllowed: true })

const name = ref('')
const slug = ref('')
const slugManual = ref(false)
const instructions = ref('')
const mode = ref<'generate' | 'git' | 'local'>('generate')
const modifyAfterImport = ref(false)

// Optional external git remote attached on create. When gitRemoteUrl
// is non-empty, gitCredentialId must also be set.
const gitRemoteUrl = ref('')
const gitCredentialId = ref('')
const gitDefaultBranch = ref('main')
const keepGitBound = ref(true)
const loading = ref(false)
const building = ref(false)
const buildError = ref('')
const buildAgentId = ref('')
const sdkVersion = ref('')
const sdkCommandImport = ref('github.com/airlockrun/agentsdk/cmd/air')

// All 8 capability override slots — empty = live system Default.
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
// System defaults shown inside placeholders so users see what Default resolves to.
const systemDefaults = ref<ModelOverrides>(emptyOverrides())

let pollTimer: ReturnType<typeof setInterval> | null = null
// Unsubscribe handle for the agent.build listener registered when this
// view kicks off a new build. Cleaned up in onUnmounted — otherwise the
// listener (closing over the just-created agent's id) lingers for the
// rest of the session and re-fires router.push every time that agent
// later completes any build/upgrade, including from unrelated views.
let unsubBuild: (() => void) | null = null

onMounted(async () => {
  catalog.fetchConfiguredModels()
  catalog.fetchCapabilities()
  // Pickers fan out per (catalog provider × configured row), so we need
  // the providers list before the model dropdowns render.
  providers.fetchProviders()
  modelsAllowed.fetchAllowed()
  gitCredsStore.fetchCredentials()
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
  try {
    const { data } = await api.get('/api/v1/agent-sdk')
    const info = fromJson(GetAgentSDKInfoResponseSchema, data)
    sdkVersion.value = info.version || ''
    sdkCommandImport.value = info.commandImport || sdkCommandImport.value
  } catch { /* command block falls back to the unversioned module path */ }
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
    help: 'Used by Sol to generate this agent\'s code. Leave empty for Default.',
    options: groupModels(isLanguage),
    grouped: true,
  },
  {
    key: 'execModel',
    label: 'Execution Model',
    icon: 'pi pi-align-left',
    help: 'Runtime default for LLM calls. Leave empty for Default.',
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
    help: 'Web search backend + model. Pick "Provider default" to let the backend choose its model.',
    options: searchModelOptions.value,
    grouped: true,
  },
])

function placeholderFor(key: keyof ModelOverrides): string {
  const def = systemDefaults.value[key]
  return def ? `Default (${def})` : 'Default'
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

const canSubmit = computed(() => {
  if (mode.value === 'local') return false
  if (!name.value || !slug.value) return false
  if (mode.value === 'git') {
    if (!gitRemoteUrl.value.trim() || !gitCredentialId.value) return false
    if (modifyAfterImport.value && !instructions.value.trim()) return false
  }
  return true
})

const localDir = computed(() => slug.value || 'my-agent')
const airlockURL = computed(() => window.location.origin)
const versionedAirCommand = computed(() => {
  const suffix = sdkVersion.value ? `@v${sdkVersion.value}` : ''
  return `${sdkCommandImport.value}${suffix}`
})
const localCreateCommands = computed(() => [
  `go run ${versionedAirCommand.value} init ${localDir.value} --airlock ${airlockURL.value}`,
  `cd ${localDir.value}`,
  'go mod tidy',
  `go tool air login ${airlockURL.value}`,
  'go tool air toolchain install',
  `go tool air deploy --create --name ${JSON.stringify(name.value || localDir.value)}`,
].join('\n'))
const localDeployCommand = computed(() => 'go tool air deploy')

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

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

function startPolling(agentId: string) {
  pollTimer = setInterval(async () => {
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}`)
      const agent = fromJson(GetAgentDetailResponseSchema, data).agent
      if (!agent) return
      // Build already finished before we got a chance to hand off — go to the
      // agent page / surface the error.
      if (agent.status === 'active') {
        onBuildDone(agentId)
        return
      }
      if (agent.status === 'failed') {
        onBuildFailed(agent.errorMessage)
        return
      }
      // Still building: navigate to the build view as soon as the build row
      // exists. This is the reliable hand-off; the WS 'agent.build' event is
      // just the faster path when the subscription is already live (it can be
      // missed in the race right after create).
      await buildsStore.fetchBuilds(agentId)
      const latest = buildsStore.builds[0]
      if (latest?.id) {
        unsubBuild?.()
        unsubBuild = null
        stopPolling()
        router.push({ name: 'build-detail', params: { id: agentId, buildId: latest.id } })
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
      mode.value === 'git' && !modifyAfterImport.value ? '' : instructions.value,
      mode.value === 'git' && gitRemoteUrl.value.trim()
        ? {
            remoteUrl: gitRemoteUrl.value.trim(),
            credentialId: gitCredentialId.value,
            defaultBranch: gitDefaultBranch.value.trim() || 'main',
            oneTimeImport: !keepGitBound.value,
          }
        : undefined,
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
          summary: 'Agent created - advanced model overrides not saved',
          detail: err.response?.data?.error || String(err),
          life: 6000,
        })
      }
    }

    buildAgentId.value = agent.id
    building.value = true
    loading.value = false

    ws.reconnect()
    unsubBuild?.()
    unsubBuild = ws.onMessage('agent.build', (payload: any) => {
      if (payload?.agentId !== agent.id) return
      // As soon as the build row exists, hand off to the dedicated Build page
      // (task checklist + codegen/docker logs stream there).
      if (payload.buildId) {
        const buildId = payload.buildId
        unsubBuild?.()
        unsubBuild = null
        stopPolling()
        router.push({ name: 'build-detail', params: { id: agent.id, buildId } })
      }
    })
    startPolling(agent.id)
  } catch (err: any) {
    loading.value = false
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to create agent', life: 5000 })
  }
}

onUnmounted(() => {
  stopPolling()
  unsubBuild?.()
  unsubBuild = null
})
</script>

<template>
  <div class="create-page">
    <div class="create-header">
      <div>
        <h1>Create Agent</h1>
        <p>Start from instructions, import an existing Git repo, or initialize source locally and deploy from your machine.</p>
      </div>
    </div>

    <div class="mode-grid">
      <button type="button" class="mode-card" :class="{ active: mode === 'generate' }" @click="mode = 'generate'">
        <i class="pi pi-wand" />
        <strong>Generate From Instructions</strong>
        <span>Describe what you need. Airlock scaffolds the source and builds the first version.</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'git' }" @click="mode = 'git'">
        <i class="pi pi-github" />
        <strong>Import From Git</strong>
        <span>Clone an existing repo, build it as-is, and optionally keep it connected for future sync.</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'local' }" @click="mode = 'local'">
        <i class="pi pi-desktop" />
        <strong>Deploy From Local</strong>
        <span>Initialize an agent repo on your machine and deploy it with the Airlock CLI.</span>
      </button>
    </div>

    <Message v-if="mode === 'local'" severity="info" :closable="false">
      This option does not create an agent yet. The first deploy command creates the agent and writes a stable local binding.
    </Message>

    <section v-if="mode === 'local'" class="local-panel">
      <div class="local-copy">
        <h2>Deploy from local source</h2>
        <p>Run these commands from the directory where you keep source code.</p>
        <pre><code>{{ localCreateCommands }}</code></pre>
      </div>
      <div class="local-copy">
        <h2>Future deploys</h2>
        <p>After `.airlock/agent.toml` contains the Airlock URL and agent ID, deploy with no arguments.</p>
        <pre><code>{{ localDeployCommand }}</code></pre>
      </div>
    </section>

    <form v-else @submit.prevent="onSubmit" class="create-form">
      <FloatLabel variant="on">
        <InputText id="agent-name" v-model="name" style="width: 100%" :disabled="building" />
        <label for="agent-name">Agent Name</label>
      </FloatLabel>

      <div>
        <FloatLabel variant="on">
          <InputText id="agent-slug" v-model="slug" style="width: 100%" :disabled="building" @input="onSlugInput" />
          <label for="agent-slug">Slug</label>
        </FloatLabel>
        <small style="color: var(--p-text-muted-color)">URL-safe identifier, auto-generated from name.</small>
      </div>

      <Message v-if="mode === 'generate'" severity="secondary" :closable="false">
        Airlock creates a new repo from your instructions, then opens the build page while it generates and compiles the first version.
      </Message>

      <Message v-if="mode === 'git'" severity="secondary" :closable="false">
        Airlock imports the selected branch and builds it as-is. Keep the repository connected to enable future push/pull and webhook sync, or import once and let Airlock own the internal source after creation.
      </Message>

      <div v-if="mode === 'git'" class="git-fields">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Repo URL</label>
          <InputText
            v-model="gitRemoteUrl"
            placeholder="https://github.com/you/your-agent.git"
            :disabled="building"
            autocomplete="off"
            style="width: 100%"
          />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Credential</label>
          <Select
            v-model="gitCredentialId"
            :options="gitCredsStore.credentials"
            option-label="name"
            option-value="id"
            placeholder="Choose a PAT"
            :disabled="building"
            style="width: 100%"
          />
          <small v-if="gitCredsStore.credentials.length === 0" style="color: var(--p-text-muted-color)">
            No credentials yet - <router-link to="/settings/git-credentials">add a PAT in Settings</router-link>.
          </small>
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Default branch</label>
          <InputText v-model="gitDefaultBranch" :disabled="building" style="width: 100%" />
        </div>
        <label class="check-row">
          <Checkbox v-model="keepGitBound" binary :disabled="building" />
          <span>Keep this Git repo connected after import</span>
        </label>
        <label class="check-row">
          <Checkbox v-model="modifyAfterImport" binary :disabled="building" />
          <span>Ask Airlock to modify the code after import</span>
        </label>
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

      <div v-if="mode === 'generate' || (mode === 'git' && modifyAfterImport)">
        <label for="instructions" style="display: block; margin-bottom: 0.5rem; font-weight: 500">
          {{ mode === 'git' ? 'Change request' : 'Instructions' }}
        </label>
        <Textarea
          id="instructions"
          v-model="instructions"
          :auto-resize="true"
          rows="3"
          :placeholder="mode === 'git' ? 'Example: Add a dashboard page for weekly presentation analytics.' : 'Describe what this agent should do and what tools it needs, e.g. &quot;Connect to Gmail and summarize my daily emails&quot;. Leave empty for a default agent.'"
          :disabled="building"
          style="width: 100%"
        />
        <small v-if="mode === 'git'" style="color: var(--p-text-muted-color)">
          Airlock imports the repo first, then applies this request during the build.
        </small>
      </div>

      <Button
        v-if="!building"
        type="submit"
        :label="mode === 'git' ? 'Import Agent' : 'Generate Agent'"
        icon="pi pi-plus"
        :loading="loading"
        :disabled="!canSubmit"
        style="align-self: flex-end"
      />
    </form>

    <!-- Build kicked off — we hand off to the dedicated Build page as soon as
         the build row exists; this is the brief interim state. -->
    <div v-if="building" style="margin-top: 1.5rem">
      <p style="margin-bottom: 0.75rem; font-weight: 600">Building {{ name }}…</p>
      <ProgressBar mode="indeterminate" style="height: 0.375rem; margin-bottom: 0.75rem" />
      <p style="color: var(--p-text-muted-color); font-size: 0.85rem">Opening the build view…</p>
    </div>

    <Message v-if="buildError" severity="error" :closable="false" style="margin-top: 1rem">
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 20rem; overflow-y: auto">{{ buildError }}</pre>
    </Message>
  </div>
</template>

<style scoped>
.create-page {
  max-width: 54rem;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.create-header h1 {
  margin: 0 0 0.35rem;
  font-size: 1.65rem;
}

.create-header p {
  margin: 0;
  color: var(--p-text-muted-color);
  max-width: 48rem;
}

.mode-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1rem;
}

.mode-card {
  border: 1px solid var(--p-content-border-color);
  border-radius: 1rem;
  background: var(--p-content-background);
  color: var(--p-text-color);
  padding: 1rem;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
  cursor: pointer;
}

.mode-card i {
  font-size: 1.25rem;
  color: var(--p-primary-color);
}

.mode-card span {
  color: var(--p-text-muted-color);
  line-height: 1.35;
}

.mode-card.active {
  border-color: var(--p-primary-color);
  box-shadow: 0 0 0 1px var(--p-primary-color);
}

.create-form {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.git-fields,
.local-panel {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.check-row {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.local-copy {
  border: 1px solid var(--p-content-border-color);
  border-radius: 1rem;
  padding: 1rem;
  background: var(--p-content-background);
}

.local-copy h2 {
  margin: 0 0 0.35rem;
  font-size: 1rem;
}

.local-copy p {
  margin: 0 0 0.75rem;
  color: var(--p-text-muted-color);
}

pre {
  margin: 0;
  padding: 1rem;
  overflow-x: auto;
  border-radius: 0.75rem;
  background: color-mix(in srgb, var(--p-surface-900) 88%, black);
  color: var(--p-surface-0);
}

@media (max-width: 760px) {
  .mode-grid {
    grid-template-columns: 1fr;
  }
}
</style>
