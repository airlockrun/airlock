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
import { useAirlockI18n } from '@/i18n'

const router = useRouter()
const store = useAgentsStore()
const buildsStore = useBuildsStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const modelsAllowed = useModelsAllowedStore()
const gitCredsStore = useGitCredentialsStore()
const toast = useToast()
const { t, locale } = useAirlockI18n()
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
const gitModeOptions = computed(() => [
  { label: t('agents.source.mode.readWriteDescription'), value: 'read_write' },
  { label: t('agents.source.mode.readOnlyDescription'), value: 'read_only' },
  { label: t('agents.create.gitMode.importOnce'), value: 'import_once' },
])
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
    sdkInfoError.value = t('agents.create.localSetupLoadFailed')
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
    label: t('agents.create.model.build'),
    icon: 'pi pi-hammer',
    help: t('agents.create.model.buildHelp'),
    options: groupModels(isLanguage),
    grouped: true,
  },
  {
    key: 'execModel',
    label: t('agents.create.model.execution'),
    icon: 'pi pi-align-left',
    help: t('agents.create.model.executionHelp'),
    options: groupModels(isLanguage),
    grouped: true,
  },
])

const advancedRows = computed<OverrideRow[]>(() => [
  {
    key: 'visionModel',
    label: t('agents.create.model.vision'),
    icon: 'pi pi-image',
    help: t('agents.create.model.visionHelp'),
    options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')),
    grouped: true,
  },
  {
    key: 'sttModel',
    label: t('agents.create.model.stt'),
    icon: 'pi pi-microphone',
    help: t('agents.create.model.sttHelp'),
    options: groupModels(isTranscription),
    grouped: true,
  },
  {
    key: 'ttsModel',
    label: t('agents.create.model.tts'),
    icon: 'pi pi-volume-up',
    help: t('agents.create.model.ttsHelp'),
    options: groupModels(isSpeech),
    grouped: true,
  },
  {
    key: 'imageGenModel',
    label: t('agents.create.model.imageGen'),
    icon: 'pi pi-palette',
    help: t('agents.create.model.imageGenHelp'),
    options: groupModels(isImageGen),
    grouped: true,
  },
  {
    key: 'embeddingModel',
    label: t('agents.create.model.embedding'),
    icon: 'pi pi-database',
    help: t('agents.create.model.embeddingHelp'),
    options: groupModels(isEmbedding),
    grouped: true,
  },
  {
    key: 'searchModel',
    label: t('agents.create.model.webSearch'),
    icon: 'pi pi-search',
    help: t('agents.create.model.webSearchHelp'),
    options: searchModelOptions.value,
    grouped: true,
  },
])

function placeholderFor(key: keyof ModelOverrides): string {
  const def = systemDefaults.value[key]
  return def ? t('agents.create.model.defaultValue', { model: def }) : t('agents.create.model.default')
}

watch(name, (v) => {
  if (!slugManual.value) {
    slug.value = v
      .toLocaleLowerCase(locale.value)
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
    toast.add({ severity: 'success', summary: t('agents.copy.copied', { label }), life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: t('agents.copy.failedLowercase', { label: label.toLocaleLowerCase(locale.value) }), life: 4000 })
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
  toast.add({ severity: 'success', summary: t('agents.create.builtSuccessfully'), life: 3000 })
  router.push(`/agents/${agentId}`)
}

function onBuildFailed(error: string) {
  stopPolling()
  buildError.value = error || t('agents.create.buildFailedSentence')
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
    toast.add({ severity: 'error', summary: t('agents.create.nameAndSlugRequired'), life: 3000 })
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
          summary: t('agents.create.advancedOverridesNotSaved'),
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
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.create.failed'), life: 5000 })
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
        <h1>{{ t('agents.create.title') }}</h1>
        <p>{{ t('agents.create.description') }}</p>
      </div>
    </div>

    <div class="mode-grid">
      <button type="button" class="mode-card" :class="{ active: mode === 'generate' }" @click="mode = 'generate'">
        <i class="pi pi-sparkles" />
        <strong>{{ t('agents.create.mode.generateTitle') }}</strong>
        <span>{{ t('agents.create.mode.generateDescription') }}</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'local' }" @click="mode = 'local'">
        <i class="pi pi-desktop" />
        <strong>{{ t('agents.create.mode.localTitle') }}</strong>
        <span>{{ t('agents.create.mode.localDescription') }}</span>
      </button>
      <button type="button" class="mode-card" :class="{ active: mode === 'git' }" @click="mode = 'git'">
        <i class="pi pi-github" />
        <strong>{{ t('agents.create.mode.gitTitle') }}</strong>
        <span>{{ t('agents.create.mode.gitDescription') }}</span>
      </button>
    </div>

    <Message v-if="mode === 'local'" severity="info" :closable="false">
      <strong>{{ t('agents.create.localAssistantQuestion') }}</strong>
      {{ t('agents.create.localAssistantDescription') }}
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
            <h2>{{ t('agents.create.localTitle') }}</h2>
            <p>{{ t('agents.create.localDescription') }}</p>
          </div>
          <Button :label="t('agents.create.copySetup')" icon="pi pi-copy" outlined size="small" @click="copyToClipboard(localCreateCommands, t('agents.create.setupInstructions'))" />
        </div>
        <pre><code>{{ localCreateCommands }}</code></pre>
      </div>
      <div class="local-copy">
        <div class="local-copy-header">
          <div>
            <h2>{{ t('agents.create.futureDeploys') }}</h2>
            <p>{{ t('agents.create.futureDeploysDescription') }}</p>
          </div>
          <Button :label="t('agents.create.copyCommand')" icon="pi pi-copy" outlined size="small" @click="copyToClipboard(localDeployCommand, t('agents.source.deployCommand'))" />
        </div>
        <pre><code>{{ localDeployCommand }}</code></pre>
      </div>
    </section>

    <form v-else @submit.prevent="onSubmit" class="create-form">
      <FloatLabel variant="on">
        <InputText id="agent-name" v-model="name" style="width: 100%" :disabled="building" />
        <label for="agent-name">{{ t('agents.create.appName') }}</label>
      </FloatLabel>

      <div>
        <FloatLabel variant="on">
          <InputText id="agent-slug" v-model="slug" style="width: 100%" :disabled="building" @input="onSlugInput" />
          <label for="agent-slug">{{ t('agents.create.slug') }}</label>
        </FloatLabel>
        <small style="color: var(--p-text-muted-color)">{{ t('agents.create.slugHelp') }}</small>
      </div>

      <Message v-if="mode === 'generate'" severity="secondary" :closable="false">
        {{ t('agents.create.generateNotice') }}
      </Message>

      <Message v-if="mode === 'git'" severity="secondary" :closable="false">
        {{ t('agents.create.gitNotice') }}
      </Message>

      <div v-if="mode === 'git'" class="git-fields">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.create.repoUrl') }}</label>
          <InputText
            v-model="gitRemoteUrl"
            :placeholder="t('agents.create.repoUrlPlaceholder')"
            :disabled="building"
            autocomplete="off"
            style="width: 100%"
          />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.source.credential') }}</label>
          <Skeleton v-if="gitCredsStore.loading" height="2.5rem" />
          <Message v-else-if="gitCredsStore.error" severity="error" :closable="false">
            <div class="load-error">
              <span>{{ gitCredsStore.error }}</span>
              <Button :label="t('agents.action.retry')" icon="pi pi-refresh" size="small" outlined @click="retryGitCredentials" />
            </div>
          </Message>
          <Select
            v-else
            v-model="gitCredentialId"
            :options="gitCredsStore.credentials"
            option-label="name"
            option-value="id"
            :placeholder="t('agents.create.choosePat')"
            :disabled="building"
            style="width: 100%"
          />
          <small v-if="!gitCredsStore.loading && !gitCredsStore.error && gitCredsStore.credentials.length === 0" style="color: var(--p-text-muted-color)">
            {{ t('agents.create.noCredentialsBeforeLink') }} <router-link to="/settings/git-credentials">{{ t('agents.create.addPatLink') }}</router-link>.
          </small>
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.source.defaultBranch') }}</label>
          <InputText v-model="gitDefaultBranch" :disabled="building" style="width: 100%" />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.source.sourceMode') }}</label>
          <Select
            v-model="gitMode"
            :options="gitModeOptions"
            option-label="label"
            option-value="value"
            :disabled="building"
            style="width: 100%"
          />
          <small v-if="gitMode === 'read_only'" style="color: var(--p-text-muted-color)">
            {{ t('agents.create.readOnlyHelp') }}
          </small>
          <small v-else-if="gitMode === 'import_once'" style="color: var(--p-text-muted-color)">
            {{ t('agents.create.importOnceHelp') }}
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
      <Fieldset :legend="t('agents.create.otherCapabilityOverrides')" :toggleable="true" :collapsed="true">
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
          {{ mode === 'git' ? t('agents.create.changeRequest') : t('agents.create.instructions') }}
        </label>
        <Textarea
          id="instructions"
          v-model="instructions"
          :auto-resize="true"
          rows="3"
          :placeholder="mode === 'git' ? t('agents.create.changeRequestPlaceholder') : t('agents.create.instructionsPlaceholder')"
          :disabled="building"
          style="width: 100%"
        />
        <small v-if="mode === 'git'" style="color: var(--p-text-muted-color)">
          {{ t('agents.create.changeRequestHelp') }}
        </small>
      </div>

      <Button
        v-if="!building"
        type="submit"
        :label="mode === 'git' ? t('agents.create.importAction') : t('agents.create.generateAction')"
        icon="pi pi-plus"
        :loading="loading"
        :disabled="!canSubmit"
        style="align-self: flex-end"
      />
    </form>

    <!-- Build kicked off — we hand off to the dedicated Build page as soon as
         the build row exists; this is the brief interim state. -->
    <div v-if="building" style="margin-top: 1.5rem">
      <p style="margin-bottom: 0.75rem; font-weight: 600">{{ t('agents.create.buildingName', { name }) }}</p>
      <ProgressBar mode="indeterminate" style="height: 0.375rem; margin-bottom: 0.75rem" />
      <p style="color: var(--p-text-muted-color); font-size: 0.85rem">{{ t('agents.create.openingBuild') }}</p>
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
