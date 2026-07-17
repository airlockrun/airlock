<script setup lang="ts">
import { ref, computed, onMounted, nextTick, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { fromJson, toJson } from '@bufbuild/protobuf'
import { useAuthStore } from '@/stores/auth'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'
import { useBridgesStore } from '@/stores/bridges'
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
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { registerPasskey } from '@/api/passkeys'
import { usePasskeysStore } from '@/stores/passkeys'
import { scorePassword } from '@/composables/usePasswordStrength'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import {
  GetSystemSettingsResponseSchema,
  UpdateSystemSettingsRequestSchema,
} from '@/gen/airlock/v1/api_pb'
import type { SystemSettingsInfo } from '@/gen/airlock/v1/types_pb'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const passkeys = usePasskeysStore()
const catalog = useCatalogStore()
const providersStore = useProvidersStore()
const bridgesStore = useBridgesStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities()

const activeStep = ref(0)
const stepperEl = ref<HTMLElement | null>(null)

// Keep the active step visible when the header is wider than the card (narrow
// screens): scroll it to center within the scrollbar-hidden step list. Indexing
// .p-step by the step value avoids depending on PrimeVue's active-class name.
watch(activeStep, async (step) => {
  // Reflect the step in the URL so a mid-wizard refresh resumes where the
  // operator left off (the account already exists + the session is live).
  router.replace({ query: { ...route.query, step: step ? String(step) : undefined } })
  await nextTick()
  const root = stepperEl.value
  if (!root) return
  const list = root.querySelector<HTMLElement>('.p-steplist')
  const steps = root.querySelectorAll<HTMLElement>('.p-step')
  const active = steps[step]
  if (!list || !active) return
  const target = active.offsetLeft - (list.clientWidth - active.clientWidth) / 2
  list.scrollTo({ left: Math.max(0, target), behavior: 'smooth' })
})
const alreadyActivated = ref(false)
const activationCodeRequired = ref(false)
const loading = ref(false)
const error = ref('')

onMounted(async () => {
  catalog.fetchCatalogProviders()
  // Resume a step from the URL (a refresh mid-wizard).
  const wanted = Number(route.query.step)
  const resumeStep = Number.isInteger(wanted) && wanted >= 1 && wanted <= 3 ? wanted : 0
  try {
    const { data } = await api.get('/auth/status')
    if (data.activation_code_required) activationCodeRequired.value = true
    if (data.activated) {
      // Already activated. A mid-wizard refresh (an authenticated admin landing
      // with a ?step) resumes the post-account setup; a bare visit or a
      // non-admin is genuinely done and gets the "already activated" notice.
      if (resumeStep >= 1 && auth.isAuthenticated && auth.isAdmin) {
        accountCreated.value = true
        credentialSet.value = true
        await resumeSetup(resumeStep)
      } else {
        alreadyActivated.value = true
      }
    }
  } catch { /* show the form anyway */ }
})

// resumeSetup loads the data the post-account steps need (normally fetched as
// the operator advances) and jumps to the requested step after a refresh.
async function resumeSetup(step: number) {
  await catalog.fetchCapabilities()
  if (step >= 2) {
    await Promise.all([
      catalog.fetchConfiguredModels(),
      providersStore.fetchProviders(),
      loadExistingDefaults(),
    ])
  }
  if (step >= 3) {
    await bridgesStore.fetchBridges().catch(() => {})
  }
  activeStep.value = step
}

// --- Step 1: Admin account
const activationCode = ref('')
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const displayName = ref('')
// Passkey is the default (checkbox ticked); unticking opts into a password
// instead. usePasskey === false is the "password" mode used throughout.
const usePasskey = ref(true)
// Tracks that the account+tenant already exist so a retry (e.g. after a
// cancelled passkey prompt) doesn't re-run activation and 409.
const accountCreated = ref(false)
// Tracks that the account has a usable credential (password or enrolled
// passkey). Gates advancing past step 1: a cancelled passkey ceremony on a
// fresh passkey-only account must not move on with no way to sign back in.
const credentialSet = ref(false)

function isCeremonyAbort(err: any): boolean {
  const name = err?.name
  return name === 'NotAllowedError' || name === 'AbortError'
}

async function nextStep() {
  error.value = ''
  if (activationCodeRequired.value && !activationCode.value) {
    error.value = 'Activation code is required.'
    return
  }
  if (!email.value) {
    error.value = 'Email is required.'
    return
  }
  if (!usePasskey.value) {
    if (!password.value || !confirmPassword.value) {
      error.value = 'Enter and confirm a password.'
      return
    }
    if (password.value !== confirmPassword.value) {
      error.value = 'Passwords do not match.'
      return
    }
    if (!scorePassword(password.value, [email.value]).ok) {
      error.value = 'Password is too weak - choose a longer or less predictable one.'
      return
    }
  }

  loading.value = true
  try {
    if (!accountCreated.value) {
      // Creates the account AND authenticates the session; a passkey-only
      // account is created with an empty password.
      await auth.activate(email.value, usePasskey.value ? '' : password.value, displayName.value || email.value, activationCode.value)
      accountCreated.value = true
      credentialSet.value = !usePasskey.value
    } else if (!usePasskey.value && !credentialSet.value) {
      // Account already exists (e.g. passkey-only after a cancelled ceremony)
      // and the session is authenticated, so set the password via the
      // self-service endpoint — activate is a one-time create and won't re-run.
      await passkeys.setPassword(password.value)
      credentialSet.value = true
    }
    // A passkey-only admin must enroll a passkey now — it's the account's only
    // credential. With a password set, a passkey is optional (add later under
    // Security). Gate on credentialSet so a cancelled ceremony can't advance
    // with no usable credential.
    if (!credentialSet.value) {
      await registerPasskey('Passkey')
      credentialSet.value = true
    }
    catalog.fetchCapabilities()
    activeStep.value = 1
  } catch (err: any) {
    if (err.response?.status === 409) {
      alreadyActivated.value = true
    } else if (isCeremonyAbort(err)) {
      error.value = 'Passkey setup was cancelled. Try again, or uncheck "Use a passkey" to set a password instead.'
    } else {
      error.value = err.response?.data?.error || 'Activation failed.'
    }
  } finally {
    loading.value = false
  }
}

// --- Step 2: LLM Providers
type Capability = 'text' | 'vision' | 'transcription' | 'speech' | 'image_gen' | 'embedding' | 'search'

const capabilityOrder: Capability[] = ['text', 'vision', 'transcription', 'speech', 'image_gen', 'embedding', 'search']
const capabilityMeta: Record<Capability, { label: string; icon: string }> = {
  text:          { label: 'Text',          icon: 'pi pi-align-left' },
  vision:        { label: 'Vision',        icon: 'pi pi-image' },
  transcription: { label: 'Transcription', icon: 'pi pi-microphone' },
  speech:        { label: 'Speech',        icon: 'pi pi-volume-up' },
  image_gen:     { label: 'Image gen',     icon: 'pi pi-palette' },
  embedding:     { label: 'Embedding',     icon: 'pi pi-database' },
  search:        { label: 'Web search',    icon: 'pi pi-search' },
}

const providerID = ref('')
const providerName = ref('')
const providerSlug = ref('')
// Mirrors ProvidersView: slug auto-tracks displayName until the user types
// into the slug field manually. Same kebab-case rules as agent slugs.
const slugManual = ref(false)
const baseURL = ref('')
const apiKey = ref('')

function toSlug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
}

const providerCandidates = computed(() =>
  catalog.capabilities
    .filter(p => !p.configured)
    .map(p => ({
      id: p.providerId,
      name: p.displayName || p.providerId,
      capabilities: p.capabilities,
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
)

const selectedProviderCaps = computed<string[]>(() => {
  const match = providerCandidates.value.find(c => c.id === providerID.value)
  return match?.capabilities ?? []
})

const coverageByCapability = computed<Record<Capability, string[]>>(() => {
  const out: Record<string, string[]> = {}
  for (const cap of capabilityOrder) out[cap] = []
  for (const p of catalog.capabilities) {
    if (!p.configured) continue
    const display = p.displayName || p.providerId
    for (const c of p.capabilities) {
      if (out[c]) out[c].push(display)
    }
  }
  return out as Record<Capability, string[]>
})

const anyProviderConfigured = computed(() =>
  catalog.capabilities.some(p => p.configured)
)

function onProviderSelect(id: string) {
  const p = providerCandidates.value.find(c => c.id === id)
  if (p) {
    providerName.value = p.name
    if (!slugManual.value) providerSlug.value = toSlug(p.name)
  }
}

function onProviderNameInput() {
  if (!slugManual.value) providerSlug.value = toSlug(providerName.value)
}

function onSlugInput() {
  slugManual.value = true
}

function resetProviderForm() {
  providerID.value = ''
  providerName.value = ''
  providerSlug.value = ''
  slugManual.value = false
  baseURL.value = ''
  apiKey.value = ''
}

async function addProvider() {
  error.value = ''
  if (!providerID.value || !apiKey.value) {
    error.value = 'Provider and API key are required.'
    return
  }
  if (!providerSlug.value) {
    error.value = 'Slug is required.'
    return
  }

  loading.value = true
  try {
    await providersStore.createProvider({
      providerId: providerID.value,
      slug: providerSlug.value,
      displayName: providerName.value || providerID.value,
      baseUrl: baseURL.value,
      apiKey: apiKey.value,
    })
    toast.add({ severity: 'success', summary: `Added ${providerName.value || providerID.value}`, life: 3000 })
    resetProviderForm()
    await catalog.fetchCapabilities()
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to create provider.'
  } finally {
    loading.value = false
  }
}

async function goToDefaults() {
  error.value = ''
  // Pull configured models, any previously-saved settings, AND the
  // providers list — the model picker fans out across configured rows
  // (multi-key support), so groupModels needs the providers store
  // populated before the dropdowns render.
  loading.value = true
  try {
    await Promise.all([
      catalog.fetchConfiguredModels(),
      providersStore.fetchProviders(),
      loadExistingDefaults(),
    ])
    activeStep.value = 2
  } finally {
    loading.value = false
  }
}

function skipToDashboard() {
  toast.add({ severity: 'info', summary: 'Setup skipped', detail: 'You can configure providers, defaults, and Telegram later in Settings and Bridges.', life: 5000 })
  router.push('/')
}

// --- Step 3: Default models
interface Defaults {
  defaultBuildModel: string
  defaultExecModel: string
  defaultVisionModel: string
  defaultSttModel: string
  defaultTtsModel: string
  defaultImageGenModel: string
  defaultEmbeddingModel: string
  defaultSearchModel: string
}
const defaults = ref<Defaults>({
  defaultBuildModel: '', defaultExecModel: '', defaultVisionModel: '',
  defaultSttModel: '', defaultTtsModel: '', defaultImageGenModel: '',
  defaultEmbeddingModel: '', defaultSearchModel: '',
})

async function loadExistingDefaults() {
  try {
    const { data } = await api.get('/api/v1/settings')
    const resp = fromJson(GetSystemSettingsResponseSchema, data)
    if (resp.settings) {
      // Pack each (row UUID, model name) pair into the picker-shaped
      // string so the dropdowns pre-select the right entry. Empty pair
      // ⇒ empty string, picker shows the placeholder.
      const pack = (modelKey: keyof SystemSettingsInfo, fkKey: keyof SystemSettingsInfo) => {
        const modelName = (resp.settings as any)[modelKey] || ''
        const providerRowID = (resp.settings as any)[fkKey] || ''
        return providerRowID || modelName ? packModelValue(providerRowID, modelName) : ''
      }
      defaults.value.defaultBuildModel     = pack('defaultBuildModel', 'defaultBuildProviderId')
      defaults.value.defaultExecModel      = pack('defaultExecModel', 'defaultExecProviderId')
      defaults.value.defaultVisionModel    = pack('defaultVisionModel', 'defaultVisionProviderId')
      defaults.value.defaultSttModel       = pack('defaultSttModel', 'defaultSttProviderId')
      defaults.value.defaultTtsModel       = pack('defaultTtsModel', 'defaultTtsProviderId')
      defaults.value.defaultImageGenModel  = pack('defaultImageGenModel', 'defaultImageGenProviderId')
      defaults.value.defaultEmbeddingModel = pack('defaultEmbeddingModel', 'defaultEmbeddingProviderId')
      defaults.value.defaultSearchModel    = pack('defaultSearchModel', 'defaultSearchProviderId')
    }
  } catch { /* best-effort */ }
}

interface DefaultRow {
  key: keyof Defaults
  label: string
  icon: string
  help: string
  options: any
  grouped: boolean
}

const defaultRows = computed<DefaultRow[]>(() => [
  { key: 'defaultBuildModel',     label: 'Build Model',      icon: 'pi pi-hammer',     help: 'Used by Sol to generate app code.', options: groupModels(isLanguage),                                            grouped: true },
  { key: 'defaultExecModel',      label: 'Execution (Text)', icon: 'pi pi-align-left', help: 'Runtime default for LLM calls.',      options: groupModels(isLanguage),                                            grouped: true },
  { key: 'defaultVisionModel',    label: 'Vision',           icon: 'pi pi-image',      help: 'Image → text.',                       options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')), grouped: true },
  { key: 'defaultSttModel',       label: 'STT',              icon: 'pi pi-microphone', help: 'Speech-to-text.',                     options: groupModels(isTranscription),                                       grouped: true },
  { key: 'defaultTtsModel',       label: 'TTS',              icon: 'pi pi-volume-up',  help: 'Text-to-speech.',                     options: groupModels(isSpeech),                                              grouped: true },
  { key: 'defaultImageGenModel',  label: 'Image Gen',        icon: 'pi pi-palette',    help: 'Text-to-image generation.',           options: groupModels(isImageGen),                                            grouped: true },
  { key: 'defaultEmbeddingModel', label: 'Embedding',        icon: 'pi pi-database',   help: 'Text → vector embeddings.',           options: groupModels(isEmbedding),                                           grouped: true },
  { key: 'defaultSearchModel',    label: 'Web Search',       icon: 'pi pi-search',     help: 'Web search backend + model.',          options: searchModelOptions.value,                                        grouped: true },
])

// Don't bother showing a capability row the tenant can't satisfy with any
// configured provider — zero options means a dead dropdown.
const visibleDefaultRows = computed(() =>
  defaultRows.value.filter(row => {
    if (row.grouped) {
      return (row.options as { items: any[] }[]).some(g => g.items.length > 0)
    }
    return (row.options as any[]).length > 0
  })
)

// saveDefaults persists the capability defaults. Returns true on success; on
// error it sets `error` and returns false so the caller stays on the step.
async function saveDefaults(): Promise<boolean> {
  error.value = ''
  loading.value = true
  try {
    const split = (k: keyof Defaults) => splitModelValue(defaults.value[k])
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
    await api.put('/api/v1/settings', req)
    return true
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to save defaults.'
    return false
  } finally {
    loading.value = false
  }
}

async function saveDefaultsAndContinue() {
  if (!(await saveDefaults())) return
  await bridgesStore.fetchBridges().catch(() => {})
  activeStep.value = 3
}

// --- Step 4: Telegram manager bot
const managerBotToken = ref('')
const managerBot = computed(() =>
  bridgesStore.bridges.find(b => b.type === 'telegram' && b.isManager),
)
const managerBotConfigured = computed(() => !!managerBot.value)

async function addManagerBot() {
  error.value = ''
  if (!managerBotToken.value) {
    error.value = 'Paste the Telegram bot token first.'
    return
  }

  loading.value = true
  try {
    await bridgesStore.createBridge({
      type: 'telegram',
      token: managerBotToken.value,
      isManager: true,
    })
    managerBotToken.value = ''
    toast.add({ severity: 'success', summary: 'Telegram manager bot added', life: 3000 })
    await bridgesStore.fetchBridges()
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to add Telegram manager bot.'
  } finally {
    loading.value = false
  }
}

function finishActivation() {
  toast.add({ severity: 'success', summary: 'Airlock activated', life: 3000 })
  router.push('/')
}
</script>

<template>
  <Card v-if="alreadyActivated" style="width: 30rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Already Activated</div>
    </template>
    <template #content>
      <p style="text-align: center; color: var(--p-text-muted-color)">Airlock has already been set up. Please sign in.</p>
      <div style="display: flex; justify-content: center; margin-top: 1rem">
        <Button label="Go to Login" @click="router.push('/login')" />
      </div>
    </template>
  </Card>

  <Card v-else style="width: 40rem; max-width: 95vw">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Airlock Setup</div>
    </template>
    <template #content>
      <div ref="stepperEl">
      <Stepper v-model:value="activeStep" linear>
        <StepList>
          <Step :value="0">Account</Step>
          <Step :value="1">Providers</Step>
          <Step :value="2">Defaults</Step>
          <Step :value="3">Telegram</Step>
        </StepList>
        <StepPanels>
          <!-- Step 1: Admin Account -->
          <StepPanel :value="0">
            <form @submit.prevent="nextStep" style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <FloatLabel variant="on" v-if="activationCodeRequired">
                <InputText id="act-code" v-model="activationCode" autocomplete="one-time-code" style="width: 100%" />
                <label for="act-code">Activation Code</label>
              </FloatLabel>
              <FloatLabel variant="on">
                <InputText id="act-email" v-model="email" type="email" autocomplete="username" style="width: 100%" />
                <label for="act-email">Email</label>
              </FloatLabel>
              <FloatLabel variant="on">
                <InputText id="act-name" v-model="displayName" autocomplete="name" style="width: 100%" />
                <label for="act-name">Display Name</label>
              </FloatLabel>
              <div style="display: flex; align-items: center; gap: 0.5rem">
                <Checkbox v-model="usePasskey" :binary="true" inputId="use-passkey" />
                <label for="use-passkey" style="font-size: 0.9rem; color: var(--p-text-muted-color)">
                  Use a passkey (uncheck to set a password instead)
                </label>
              </div>
              <template v-if="!usePasskey">
                <FloatLabel variant="on">
                  <Password id="act-pass" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="act-pass">Password</label>
                </FloatLabel>
                <PasswordStrengthMeter :password="password" :user-inputs="[email]" />
                <FloatLabel variant="on">
                  <Password id="act-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="act-confirm">Confirm Password</label>
                </FloatLabel>
              </template>
              <div style="display: flex; justify-content: flex-end">
                <Button type="submit" :label="usePasskey ? 'Create account & passkey' : 'Create account'" :icon="usePasskey ? 'pi pi-key' : 'pi pi-check'" icon-pos="right" :loading="loading" />
              </div>
            </form>
          </StepPanel>

          <!-- Step 2: LLM Providers -->
          <StepPanel :value="1">
            <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

              <!-- Capability coverage -->
              <div class="cap-matrix">
                <div class="cap-matrix-title">Capabilities</div>
                <div v-for="cap in capabilityOrder" :key="cap" class="cap-row">
                  <div class="cap-label">
                    <i :class="capabilityMeta[cap].icon" />
                    <span>{{ capabilityMeta[cap].label }}</span>
                  </div>
                  <div class="cap-coverage">
                    <template v-if="coverageByCapability[cap].length > 0">
                      <Tag
                        v-for="name in coverageByCapability[cap]"
                        :key="name"
                        :value="name"
                        severity="success"
                        style="font-size: 0.7rem"
                      />
                    </template>
                    <span v-else class="cap-missing">Not yet configured</span>
                  </div>
                </div>
              </div>

              <!-- Add provider form. autocomplete="off" on the form + each
                   field stops the browser password manager from offering to
                   save "Display Name + API Key" as a credential pair. -->
              <form @submit.prevent="addProvider" autocomplete="off" style="display: flex; flex-direction: column; gap: 1rem">
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <Select
                      id="prov-id"
                      v-model="providerID"
                      :options="providerCandidates"
                      optionLabel="name"
                      optionValue="id"
                      :disabled="providerCandidates.length === 0"
                      filter
                      autoFilterFocus
                      showClear
                      resetFilterOnHide
                      style="width: 100%"
                      @update:modelValue="onProviderSelect"
                    />
                    <label for="prov-id">Provider</label>
                  </FloatLabel>
                  <!-- Preview what this provider will cover -->
                  <div v-if="selectedProviderCaps.length" class="cap-preview">
                    Provides:
                    <Tag
                      v-for="c in selectedProviderCaps"
                      :key="c"
                      :value="capabilityMeta[c as Capability]?.label ?? c"
                      severity="info"
                      style="font-size: 0.7rem"
                    />
                  </div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <InputText id="prov-name" v-model="providerName" autocomplete="off" style="width: 100%" @input="onProviderNameInput" />
                    <label for="prov-name">Display Name</label>
                  </FloatLabel>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <InputText id="prov-slug" v-model="providerSlug" autocomplete="off" style="width: 100%" @input="onSlugInput" />
                    <label for="prov-slug">Slug</label>
                  </FloatLabel>
                  <small style="color: var(--p-text-muted-color)">
                    Disambiguates rows for the same provider (multi-key support).
                  </small>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <InputText id="prov-url" v-model="baseURL" autocomplete="off" style="width: 100%" />
                    <label for="prov-url">Base URL (optional)</label>
                  </FloatLabel>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <!-- type="text" + -webkit-text-security keeps the visual
                       masking but avoids the password manager entirely —
                       Chrome's built-in manager fixates on type="password"
                       and ignores autocomplete tokens. -->
                  <FloatLabel variant="on">
                    <InputText
                      id="prov-key"
                      v-model="apiKey"
                      type="text"
                      autocomplete="off"
                      name="prov-api-key"
                      data-1p-ignore="true"
                      data-lpignore="true"
                      data-bwignore="true"
                      style="width: 100%; -webkit-text-security: disc;"
                    />
                    <label for="prov-key">API Key</label>
                  </FloatLabel>
                </div>
                <div style="display: flex; justify-content: flex-end">
                  <Button
                    type="submit"
                    label="Add provider"
                    icon="pi pi-plus"
                    :loading="loading"
                    :disabled="!providerID || !apiKey || !providerSlug"
                    severity="secondary"
                  />
                </div>
              </form>

              <!-- Navigation -->
              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button label="Skip setup" severity="secondary" text @click="skipToDashboard" />
                <Button
                  label="Next"
                  icon="pi pi-arrow-right"
                  icon-pos="right"
                  :disabled="!anyProviderConfigured"
                  @click="goToDefaults"
                />
              </div>
            </div>
          </StepPanel>

          <!-- Step 3: Default Models -->
          <StepPanel :value="2">
            <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <p style="color: var(--p-text-muted-color); margin: 0">
                Pick a default model for each capability. Apps inherit these unless they override. You can change them anytime under Settings.
              </p>

              <div
                v-for="row in visibleDefaultRows"
                :key="row.key"
                style="display: flex; flex-direction: column; gap: 0.5rem"
              >
                <FloatLabel variant="on">
                  <Select
                    v-if="row.grouped"
                    :id="`def-${row.key}`"
                    v-model="defaults[row.key]"
                    :options="row.options"
                    optionLabel="label"
                    optionValue="value"
                    optionGroupLabel="label"
                    optionGroupChildren="items"
                    filter
                    autoFilterFocus
                    showClear
                    :loading="catalog.loading"
                    style="width: 100%"
                  />
                  <Select
                    v-else
                    :id="`def-${row.key}`"
                    v-model="defaults[row.key]"
                    :options="row.options"
                    optionLabel="label"
                    optionValue="value"
                    filter
                    autoFilterFocus
                    showClear
                    :loading="catalog.loading"
                    style="width: 100%"
                  />
                  <label :for="`def-${row.key}`" style="display: flex; align-items: center; gap: 0.4rem">
                    <i :class="row.icon" />
                    <span>{{ row.label }}</span>
                  </label>
                </FloatLabel>
                <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
              </div>

              <p v-if="!visibleDefaultRows.length" style="color: var(--p-text-muted-color); margin: 0">
                No models yet. Go back and add a provider that offers at least one capability.
              </p>

              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button label="Back" severity="secondary" text icon="pi pi-arrow-left" @click="activeStep = 1" />
                <Button label="Next" icon="pi pi-arrow-right" icon-pos="right" :loading="loading" @click="saveDefaultsAndContinue" />
              </div>
            </div>
          </StepPanel>

          <!-- Step 4: Telegram manager bot -->
          <StepPanel :value="3">
            <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <div class="manager-setup-intro">
                <div class="manager-setup-icon"><i class="pi pi-send" /></div>
                <div style="display: flex; flex-direction: column; gap: 0.35rem">
                  <h3 style="margin: 0">Add a Telegram manager bot</h3>
                  <p style="color: var(--p-text-muted-color); margin: 0">
                    The manager bot lets Airlock create new Telegram bots for apps through Telegram's managed-bots flow. It must be a Telegram bot with bot-management permission enabled.
                  </p>
                </div>
              </div>

              <Message v-if="managerBotConfigured" severity="success" :closable="false">
                Manager bot configured: <b>{{ managerBot?.botUsername || managerBot?.name }}</b>
                <span v-if="managerBot?.managerError"> - {{ managerBot.managerError }}</span>
              </Message>

              <div class="manager-guide">
                <div class="manager-guide-title">Telegram setup checklist</div>
                <ol>
                  <li>Open <b>@BotFather</b> in Telegram and create a new bot, or choose an existing bot that should manage bot creation.</li>
                  <li>Open that bot's settings in BotFather and enable the management permission for creating/managing bots. Telegram exposes this as <code>can_manage_bots</code>.</li>
                  <li>Copy the bot token from BotFather and paste it below.</li>
                  <li>Airlock verifies the token and refuses setup if Telegram has not granted <code>can_manage_bots</code>.</li>
                </ol>
              </div>

              <div v-if="!managerBotConfigured" style="display: flex; flex-direction: column; gap: 0.75rem">
                <FloatLabel variant="on">
                  <Password id="manager-bot-token" v-model="managerBotToken" :feedback="false" toggleMask style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="manager-bot-token">Telegram bot token</label>
                </FloatLabel>
                <small style="color: var(--p-text-muted-color)">
                  The bot is saved as an unbound manager bridge. App bots can be created later from Bridges without pasting tokens manually.
                </small>
                <div style="display: flex; justify-content: flex-end">
                  <Button label="Add manager bot" icon="pi pi-plus" :loading="loading" :disabled="!managerBotToken" @click="addManagerBot" />
                </div>
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button label="Back" severity="secondary" text icon="pi pi-arrow-left" @click="activeStep = 2" />
                <div style="display: flex; gap: 0.5rem">
                  <Button v-if="!managerBotConfigured" label="Skip for now" severity="secondary" text @click="finishActivation" />
                  <Button label="Finish" icon="pi pi-check" :disabled="!managerBotConfigured" @click="finishActivation" />
                </div>
              </div>
            </div>
          </StepPanel>
        </StepPanels>
      </Stepper>
      </div>
    </template>
    <template #footer>
      <div style="text-align: center">
        <router-link to="/login" style="color: var(--p-primary-color); text-decoration: none; font-size: 0.875rem">
          Already activated? Sign in
        </router-link>
      </div>
    </template>
  </Card>
</template>

<style scoped>
.cap-matrix {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
}
.cap-matrix-title {
  font-weight: 600;
  font-size: 0.875rem;
  color: var(--p-text-color);
  margin-bottom: 0.25rem;
}
.cap-row {
  display: grid;
  grid-template-columns: 7rem 1fr;
  gap: 0.75rem;
  align-items: center;
}
.cap-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
}
.cap-coverage {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  align-items: center;
  min-height: 1.25rem;
}
.cap-missing {
  color: var(--p-text-muted-color);
  font-style: italic;
  font-size: 0.8rem;
}
.cap-preview {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  align-items: center;
  margin-top: 0.375rem;
  font-size: 0.75rem;
  color: var(--p-text-muted-color);
}
/* The step header may be wider than the card on narrow screens. Let it scroll
   horizontally but hide the scrollbar — the active step is auto-scrolled into
   view in script, so the bar is never needed or seen. */
:deep(.p-steplist) {
  max-width: 100%;
  overflow-x: auto;
  scrollbar-width: none; /* Firefox */
  -ms-overflow-style: none; /* legacy Edge */
}
:deep(.p-steplist)::-webkit-scrollbar {
  display: none; /* WebKit */
}
.manager-setup-intro {
  display: flex;
  gap: 0.85rem;
  align-items: flex-start;
  padding: 1rem;
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  background: color-mix(in srgb, var(--p-primary-color) 8%, transparent);
}
.manager-setup-icon {
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 999px;
  display: grid;
  place-items: center;
  background: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
  flex: 0 0 auto;
}
.manager-guide {
  border: 1px solid var(--p-surface-border);
  border-radius: var(--p-border-radius);
  padding: 0.85rem 1rem;
}
.manager-guide-title {
  font-weight: 600;
  margin-bottom: 0.5rem;
}
.manager-guide ol {
  margin: 0;
  padding-left: 1.2rem;
  color: var(--p-text-muted-color);
}
.manager-guide li + li {
  margin-top: 0.45rem;
}
</style>
