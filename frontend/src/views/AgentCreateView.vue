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
import { airlockInitCommand, airlockInstallCommand } from '@/utils/airCommands'
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

// Optional external git remote attached on create. When gitRemoteUrl
// is non-empty, gitCredentialId must also be set.
const gitRemoteUrl = ref('')
const gitCredentialId = ref('')
const gitDefaultBranch = ref('main')
const gitMode = ref<'read_write' | 'read_only' | 'import_once'>('read_write')
const gitModeOptions = [
  { label: 'Read/write - Airlock may push code changes', value: 'read_write' },
  { label: 'Read-only - Git is authoritative', value: 'read_only' },
  { label: 'Import once - Airlock owns the copied source', value: 'import_once' },
]
const loading = ref(false)
const building = ref(false)
const buildError = ref('')
const buildAgentId = ref('')
const sdkVersion = ref('')
const launcherImport = ref('github.com/airlockrun/agentsdk/cmd/airlock')
const airlockURL = ref('')
const sdkInfoLoading = ref(true)
const sdkInfoError = ref('')

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
  void gitCredsStore.fetchCredentials().catch(() => {})
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
    if (!info.version || !info.launcherImport || !info.airlockUrl) {
      throw new Error('incomplete Agent SDK metadata')
    }
    sdkVersion.value = info.version
    launcherImport.value = info.launcherImport
    airlockURL.value = info.airlockUrl
  } catch {
    sdkInfoError.value = 'Could not load the local setup commands. Refresh the page to try again.'
  } finally {
    sdkInfoLoading.value = false
  }
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
    help: 'Used by Sol to generate this app\'s code. Leave empty for Default.',
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
  }
  return true
})

function retryGitCredentials() {
  void gitCredsStore.fetchCredentials().catch(() => {})
}

const localDir = computed(() => slug.value || 'my-app')
const localSetupReady = computed(() => !!sdkVersion.value && !!launcherImport.value && !!airlockURL.value)
const localCreateCommands = computed(() => [
  '# CODING ASSISTANT: STOP. Do not run anything yet.',
  '# First ask the user:',
  '# - What should this app do?',
  '# - What should it be called?',
  '# Update the folder and app name below to match their answers.',
  '',
  '# Install Go 1.26 or newer if `go version` is unavailable or reports an older version.',
  '# Follow https://go.dev/doc/install for the user\'s operating system.',
  '',
  '# Install the global launcher only if `airlock version` is unavailable.',
  airlockInstallCommand(launcherImport.value, sdkVersion.value),
  '',
  airlockInitCommand(localDir.value, airlockURL.value),
  `cd ${localDir.value}`,
  '',
  '# Start login without waiting. Show the URL and code to the user; if already logged in, skip the check.',
  `go tool air login ${airlockURL.value} --no-wait`,
  '',
  '# After the user confirms approval, check once. If still pending, ask again instead of polling.',
  `go tool air login ${airlockURL.value} --check`,
  '',
  'go tool air toolchain install',
  '',
  '# Review every command available in this version of the Air CLI.',
  'go tool air help',
  '',
  '# CODING ASSISTANT: Create the app the user described now.',
  '# Read AGENTS.md and .airlock/toolchain/skills/agentsdk/SKILL.md first.',
  '# Implement the requested behavior. Do not deploy the generic scaffold.',
  '# Run the complete local build and fix every failure before deploying.',
  '',
  'go tool air build',
  `go tool air deploy --create --name ${JSON.stringify(name.value || localDir.value)} -m "Initial implementation"`,
].join('\n'))
const localDeployCommand = computed(() => 'go tool air deploy -m "Describe this deployment"')

async function copyToClipboard(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ severity: 'success', summary: `${label} copied`, life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: `Copy failed - select and copy ${label.toLowerCase()} manually`, life: 4000 })
  }
}

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
  toast.add({ severity: 'success', summary: 'App built successfully', life: 3000 })
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
      mode.value === 'git' ? '' : instructions.value,
      mode.value === 'git' && gitRemoteUrl.value.trim()
        ? {
            remoteUrl: gitRemoteUrl.value.trim(),
            credentialId: gitCredentialId.value,
            defaultBranch: gitDefaultBranch.value.trim() || 'main',
            mode: gitMode.value,
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
          summary: 'App created - advanced model overrides not saved',
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
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to create app', life: 5000 })
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
        <h1>Create App</h1>
        <p>Generate from instructions, build from local source, or import an existing Git repository.</p>
      </div>
    </div>

    <div class="mode-grid">
      <button type="button" class="mode-card" :class="{ active: mode === 'generate' }" @click="mode = 'generate'">
        <i class="pi pi-sparkles" />
        <strong>Generate From Instructions</strong>
        <span>Describe what you need. Airlock generates the source and builds the first version.</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'local' }" @click="mode = 'local'">
        <i class="pi pi-desktop" />
        <strong>Deploy From Local Source</strong>
        <span>Use OpenCode or another coding assistant to build locally and deploy with the Airlock CLI.</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'git' }" @click="mode = 'git'">
        <i class="pi pi-github" />
        <strong>Import From Git</strong>
        <span>Clone an existing repo, build it as-is, and optionally keep it connected for future sync.</span>
      </button>
    </div>

    <Message v-if="mode === 'local'" severity="info" :closable="false">
      <strong>Using a coding assistant?</strong>
      Copy the entire setup below into OpenCode, Claude Code, Codex, Cursor, or another coding assistant.
      It will ask what you want to build, help choose a name, and guide you through setup and deployment.
    </Message>

    <Message v-if="mode === 'local' && sdkInfoError" severity="error" :closable="false">
      {{ sdkInfoError }}
    </Message>

    <section v-if="mode === 'local' && sdkInfoLoading" class="local-panel">
      <Skeleton height="18rem" border-radius="1rem" />
    </section>

    <section v-else-if="mode === 'local' && localSetupReady" class="local-panel">
      <div class="local-copy">
        <div class="local-copy-header">
          <div>
            <h2>Create with a coding assistant or terminal</h2>
            <p>Paste the whole block into your coding assistant, or run it section by section in a terminal.</p>
          </div>
          <Button label="Copy setup" icon="pi pi-copy" outlined size="small" @click="copyToClipboard(localCreateCommands, 'Setup instructions')" />
        </div>
        <pre><code>{{ localCreateCommands }}</code></pre>
      </div>
      <div class="local-copy">
        <div class="local-copy-header">
          <div>
            <h2>Future deploys</h2>
            <p>After `.airlock/local/agent.toml` contains the Airlock URL and app ID, deploy with no arguments.</p>
          </div>
          <Button label="Copy command" icon="pi pi-copy" outlined size="small" @click="copyToClipboard(localDeployCommand, 'Deploy command')" />
        </div>
        <pre><code>{{ localDeployCommand }}</code></pre>
      </div>
    </section>

    <form v-else @submit.prevent="onSubmit" class="create-form">
      <FloatLabel variant="on">
        <InputText id="agent-name" v-model="name" style="width: 100%" :disabled="building" />
        <label for="agent-name">App Name</label>
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
        Airlock imports the selected branch and builds it as-is. Choose whether Airlock may push code changes, only follows Git, or copies the source once.
      </Message>

      <div v-if="mode === 'git'" class="git-fields">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Repo URL</label>
          <InputText
            v-model="gitRemoteUrl"
            placeholder="https://github.com/you/your-app.git"
            :disabled="building"
            autocomplete="off"
            style="width: 100%"
          />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Credential</label>
          <Skeleton v-if="gitCredsStore.loading" height="2.5rem" />
          <Message v-else-if="gitCredsStore.error" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ gitCredsStore.error }}</span>
              <Button label="Retry" icon="pi pi-refresh" size="small" outlined @click="retryGitCredentials" />
            </div>
          </Message>
          <Select
            v-else
            v-model="gitCredentialId"
            :options="gitCredsStore.credentials"
            option-label="name"
            option-value="id"
            placeholder="Choose a PAT"
            :disabled="building"
            style="width: 100%"
          />
          <small v-if="!gitCredsStore.loading && !gitCredsStore.error && gitCredsStore.credentials.length === 0" style="color: var(--p-text-muted-color)">
            No credentials yet - <router-link to="/settings/git-credentials">add a PAT in Settings</router-link>.
          </small>
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Default branch</label>
          <InputText v-model="gitDefaultBranch" :disabled="building" style="width: 100%" />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Source mode</label>
          <Select
            v-model="gitMode"
            :options="gitModeOptions"
            option-label="label"
            option-value="value"
            :disabled="building"
            style="width: 100%"
          />
          <small v-if="gitMode === 'read_only'" style="color: var(--p-text-muted-color)">
            Git always wins. Airlock polls and rebuilds this branch, but codegen, local deploys, and source rollbacks are disabled.
          </small>
          <small v-else-if="gitMode === 'import_once'" style="color: var(--p-text-muted-color)">
            The repository is copied once and then disconnected. Airlock-managed codegen and local deploys remain available.
          </small>
        </div>
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

      <div v-if="mode === 'generate'">
        <label for="instructions" style="display: block; margin-bottom: 0.5rem; font-weight: 500">
          {{ mode === 'git' ? 'Change request' : 'Instructions' }}
        </label>
        <Textarea
          id="instructions"
          v-model="instructions"
          :auto-resize="true"
          rows="3"
          :placeholder="mode === 'git' ? 'Example: Add a dashboard page for weekly presentation analytics.' : 'Describe what this app should do and what tools it needs, e.g. &quot;Connect to Gmail and summarize my daily emails&quot;. Leave empty for a default app.'"
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
        :label="mode === 'git' ? 'Import App' : 'Generate App'"
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
  padding-top: 0.5rem;
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

.load-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
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
  margin: 0;
  color: var(--p-text-muted-color);
}

.local-copy-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.75rem;
}

.local-copy-header .p-button {
  flex: 0 0 auto;
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

  .local-copy-header {
    align-items: stretch;
    flex-direction: column;
  }

  .local-copy-header .p-button {
    align-self: flex-start;
  }
}
</style>
