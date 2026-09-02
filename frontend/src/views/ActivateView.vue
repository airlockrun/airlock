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
import { useAirlockI18n, type AuthLocaleStatus } from '@/i18n'
import {
  GetSystemSettingsResponseSchema,
  UpdateSystemSettingsRequestSchema,
} from '@/gen/airlock/v1/api_pb'
import type { SystemSettingsInfo } from '@/gen/airlock/v1/types_pb'
import {
  OPENAI_COMPATIBLE_PROVIDER_ID,
  isValidProviderSlug,
  isValidProviderURL,
  uniqueProviderSlug,
} from '@/utils/providers'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const passkeys = usePasskeysStore()
const catalog = useCatalogStore()
const providersStore = useProvidersStore()
const bridgesStore = useBridgesStore()
const toast = useToast()
const { groupModels, searchModelOptions } = useModelCapabilities()
const { locale, availableLocales, setLocale, t } = useAirlockI18n()
const uiLocale = computed({
  get: () => locale.value,
  set: (value: string) => setLocale(value),
})
const localeOptions = computed(() => availableLocales.map(value => ({
  label: value === 'en'
    ? t('auth.locale.english')
    : value === 'ru' ? t('auth.locale.russian') : value,
  value,
})))

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
const providerSetupError = ref('')

onMounted(async () => {
  catalog.fetchCatalogProviders()
  // Resume a step from the URL (a refresh mid-wizard).
  const wanted = Number(route.query.step)
  const resumeStep = Number.isInteger(wanted) && wanted >= 1 && wanted <= 3 ? wanted : 0
  let status: (AuthLocaleStatus & { activation_code_required?: boolean }) | undefined
  try {
    const response = await api.get('/auth/status')
    status = response.data
  } catch {
    return
  }
  if (status.activation_code_required) activationCodeRequired.value = true
  if (status.activated) {
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
})

// resumeSetup loads the data the post-account steps need (normally fetched as
// the operator advances) and jumps to the requested step after a refresh.
async function resumeSetup(step: number) {
  activeStep.value = step
  if (!(await refreshProviderSetup())) return
  if (step >= 2) {
    try {
      await Promise.all([
        catalog.fetchConfiguredModels(),
        loadExistingDefaults(),
      ])
    } catch (err: any) {
      error.value = err.response?.data?.error || t('auth.activation.setupDataFailed')
      return
    }
  }
  if (step >= 3) {
    await bridgesStore.fetchBridges().catch(() => {})
  }
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
    error.value = t('auth.activation.codeRequired')
    return
  }
  if (!email.value) {
    error.value = t('auth.activation.emailRequired')
    return
  }
  if (!usePasskey.value) {
    if (!password.value || !confirmPassword.value) {
      error.value = t('auth.activation.enterPassword')
      return
    }
    if (password.value !== confirmPassword.value) {
      error.value = t('auth.activation.passwordsMismatch')
      return
    }
    if (!scorePassword(password.value, [email.value]).ok) {
      error.value = t('auth.activation.passwordWeak')
      return
    }
  }

  loading.value = true
  let credentialReady = false
  try {
    if (!accountCreated.value) {
      // Creates the account AND authenticates the session; a passkey-only
      // account is created with an empty password.
      await auth.activate(
        email.value,
        usePasskey.value ? '' : password.value,
        displayName.value || email.value,
        uiLocale.value,
        activationCode.value,
      )
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
      await registerPasskey(t('auth.passkey.defaultName'))
      credentialSet.value = true
    }
    credentialReady = true
  } catch (err: any) {
    if (err.response?.status === 409) {
      alreadyActivated.value = true
    } else if (isCeremonyAbort(err)) {
      error.value = t('auth.activation.passkeyCancelled')
    } else {
      error.value = err.response?.data?.error || t('auth.activation.failed')
    }
  } finally {
    loading.value = false
  }
  if (!credentialReady) return

  // Account activation is complete before provider inventory is loaded. A
  // transient inventory failure therefore remains a retryable setup error.
  activeStep.value = 1
  await refreshProviderSetup()
}

// --- Step 2: LLM Providers
type Capability = 'text' | 'vision' | 'transcription' | 'speech' | 'image_gen' | 'embedding' | 'search'

const capabilityOrder: Capability[] = ['text', 'vision', 'transcription', 'speech', 'image_gen', 'embedding', 'search']
const capabilityMeta = computed<Record<Capability, { label: string; icon: string }>>(() => ({
  text:          { label: t('auth.activation.capability.text'),          icon: 'pi pi-align-left' },
  vision:        { label: t('auth.activation.capability.vision'),        icon: 'pi pi-image' },
  transcription: { label: t('auth.activation.capability.transcription'), icon: 'pi pi-microphone' },
  speech:        { label: t('auth.activation.capability.speech'),        icon: 'pi pi-volume-up' },
  image_gen:     { label: t('auth.activation.capability.imageGen'),      icon: 'pi pi-palette' },
  embedding:     { label: t('auth.activation.capability.embedding'),     icon: 'pi pi-database' },
  search:        { label: t('auth.activation.capability.webSearch'),     icon: 'pi pi-search' },
}))

const providerID = ref('')
const providerName = ref('')
const providerSlug = ref('')
const slugManual = ref(false)
const baseURL = ref('')
const apiKey = ref('')

const providerCandidates = computed(() =>
  catalog.capabilities
    .filter(p => p.providerId !== OPENAI_COMPATIBLE_PROVIDER_ID)
    .map(p => ({
      id: p.providerId,
      name: p.displayName || p.providerId,
      capabilities: p.capabilities,
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
)

const providerFormValid = computed(() =>
  !!providerID.value &&
  !!providerName.value.trim() &&
  isValidProviderSlug(providerSlug.value) &&
  isValidProviderURL(baseURL.value, false) &&
  !!apiKey.value.trim(),
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
    if (!slugManual.value) {
      providerSlug.value = uniqueProviderSlug(id, id, providersStore.providers)
    }
  }
}

function onProviderNameInput() {
  if (!slugManual.value && providerID.value) {
    providerSlug.value = uniqueProviderSlug(providerID.value, providerName.value, providersStore.providers)
  }
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

async function refreshProviderSetup(): Promise<boolean> {
  providerSetupError.value = ''
  loading.value = true
  try {
    const [capabilitiesLoaded] = await Promise.all([catalog.fetchCapabilities(), providersStore.fetchProviders()])
    if (!capabilitiesLoaded) throw new Error(t('auth.activation.providerCatalogFailed'))
    return true
  } catch (err: any) {
    providerSetupError.value = err.response?.data?.error || err.message || t('auth.activation.providerOptionsFailed')
    return false
  } finally {
    loading.value = false
  }
}

async function addProvider() {
  error.value = ''
  if (!providerFormValid.value) {
    error.value = t('auth.activation.providerFormInvalid')
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
    toast.add({ severity: 'success', summary: t('auth.activation.providerAdded', { provider: providerName.value || providerID.value }), life: 3000 })
    resetProviderForm()
    if (!(await catalog.fetchCapabilities())) {
      providerSetupError.value = t('auth.activation.providerCatalogRefreshFailed')
    }
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.activation.createProviderFailed')
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
  } catch (err: any) {
    error.value = err.response?.data?.error || err.message || t('auth.activation.modelsDefaultsFailed')
  } finally {
    loading.value = false
  }
}

function skipToDashboard() {
  toast.add({ severity: 'info', summary: t('auth.activation.setupSkipped'), detail: t('auth.activation.setupSkippedDetail'), life: 5000 })
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
  let info: SystemSettingsInfo | undefined
  try {
    const { data } = await api.get('/api/v1/settings')
    const resp = fromJson(GetSystemSettingsResponseSchema, data)
    info = resp.settings
  } catch { /* best-effort */ }
  if (info) {
    if (availableLocales.includes(info.uiLocale)) setLocale(info.uiLocale)
    // Pack each (row UUID, model name) pair into the picker-shaped
    // string so the dropdowns pre-select the right entry. Empty pair
    // ⇒ empty string, picker shows the placeholder.
    const pack = (modelKey: keyof SystemSettingsInfo, fkKey: keyof SystemSettingsInfo) => {
      const modelName = (info as any)[modelKey] || ''
      const providerRowID = (info as any)[fkKey] || ''
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
  { key: 'defaultBuildModel',     label: t('auth.activation.default.buildModel'),     icon: 'pi pi-hammer',     help: t('auth.activation.default.buildModelHelp'),     options: groupModels(isLanguage),                                              grouped: true },
  { key: 'defaultExecModel',      label: t('auth.activation.default.executionText'),  icon: 'pi pi-align-left', help: t('auth.activation.default.executionTextHelp'),  options: groupModels(isLanguage),                                              grouped: true },
  { key: 'defaultVisionModel',    label: t('auth.activation.default.vision'),         icon: 'pi pi-image',      help: t('auth.activation.default.visionHelp'),         options: groupModels((m: CatalogModel) => isLanguage(m) && hasCap(m, 'vision')), grouped: true },
  { key: 'defaultSttModel',       label: t('auth.activation.default.stt'),            icon: 'pi pi-microphone', help: t('auth.activation.default.sttHelp'),            options: groupModels(isTranscription),                                         grouped: true },
  { key: 'defaultTtsModel',       label: t('auth.activation.default.tts'),            icon: 'pi pi-volume-up',  help: t('auth.activation.default.ttsHelp'),            options: groupModels(isSpeech),                                                grouped: true },
  { key: 'defaultImageGenModel',  label: t('auth.activation.default.imageGen'),       icon: 'pi pi-palette',    help: t('auth.activation.default.imageGenHelp'),       options: groupModels(isImageGen),                                              grouped: true },
  { key: 'defaultEmbeddingModel', label: t('auth.activation.default.embedding'),      icon: 'pi pi-database',   help: t('auth.activation.default.embeddingHelp'),      options: groupModels(isEmbedding),                                             grouped: true },
  { key: 'defaultSearchModel',    label: t('auth.activation.default.webSearch'),      icon: 'pi pi-search',     help: t('auth.activation.default.webSearchHelp'),      options: searchModelOptions.value,                                             grouped: true },
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
      uiLocale:                   uiLocale.value,
    }
    const req = toJson(UpdateSystemSettingsRequestSchema, {
      $typeName: 'airlock.v1.UpdateSystemSettingsRequest',
      settings: info,
    })
    await api.put('/api/v1/settings', req)
    return true
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.activation.saveDefaultsFailed')
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
    error.value = t('auth.activation.telegramTokenRequired')
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
    toast.add({ severity: 'success', summary: t('auth.activation.telegramBotAdded'), life: 3000 })
    await bridgesStore.fetchBridges()
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.activation.telegramBotFailed')
  } finally {
    loading.value = false
  }
}

function finishActivation() {
  toast.add({ severity: 'success', summary: t('auth.activation.activated'), life: 3000 })
  router.push('/')
}
</script>

<template>
  <Card v-if="alreadyActivated" style="width: 30rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">{{ t('auth.activation.alreadyActivated') }}</div>
    </template>
    <template #content>
      <p style="text-align: center; color: var(--p-text-muted-color)">{{ t('auth.activation.alreadyActivatedDetail') }}</p>
      <div style="display: flex; justify-content: center; margin-top: 1rem">
        <Button :label="t('auth.activation.goToLogin')" @click="router.push('/login')" />
      </div>
    </template>
  </Card>

  <Card v-else style="width: 40rem; max-width: 95vw">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">{{ t('auth.activation.setupTitle') }}</div>
    </template>
    <template #content>
      <div ref="stepperEl">
      <Stepper v-model:value="activeStep" linear>
        <StepList>
          <Step :value="0">{{ t('auth.activation.step.account') }}</Step>
          <Step :value="1">{{ t('auth.activation.step.providers') }}</Step>
          <Step :value="2">{{ t('auth.activation.step.defaults') }}</Step>
          <Step :value="3">{{ t('auth.activation.step.telegram') }}</Step>
        </StepList>
        <StepPanels>
          <!-- Step 1: Admin Account -->
          <StepPanel :value="0">
            <form @submit.prevent="nextStep" style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <FloatLabel variant="on" v-if="activationCodeRequired">
                <InputText id="act-code" v-model="activationCode" autocomplete="one-time-code" style="width: 100%" />
                <label for="act-code">{{ t('auth.activation.activationCode') }}</label>
              </FloatLabel>
              <FloatLabel variant="on">
                <InputText id="act-email" v-model="email" type="email" autocomplete="username" style="width: 100%" />
                <label for="act-email">{{ t('auth.login.email') }}</label>
              </FloatLabel>
              <FloatLabel variant="on">
                <InputText id="act-name" v-model="displayName" autocomplete="name" style="width: 100%" />
                <label for="act-name">{{ t('auth.activation.displayName') }}</label>
              </FloatLabel>
              <FloatLabel variant="on">
                <Select
                  id="act-locale"
                  v-model="uiLocale"
                  :options="localeOptions"
                  optionLabel="label"
                  optionValue="value"
                  style="width: 100%"
                />
                <label for="act-locale">{{ t('auth.activation.language') }}</label>
              </FloatLabel>
              <div style="display: flex; align-items: center; gap: 0.5rem">
                <Checkbox v-model="usePasskey" :binary="true" inputId="use-passkey" />
                <label for="use-passkey" style="font-size: 0.9rem; color: var(--p-text-muted-color)">
                  {{ t('auth.activation.usePasskey') }}
                </label>
              </div>
              <template v-if="!usePasskey">
                <FloatLabel variant="on">
                  <Password id="act-pass" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="act-pass">{{ t('auth.login.password') }}</label>
                </FloatLabel>
                <PasswordStrengthMeter :password="password" :user-inputs="[email]" />
                <FloatLabel variant="on">
                  <Password id="act-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="act-confirm">{{ t('auth.activation.confirmPassword') }}</label>
                </FloatLabel>
              </template>
              <div style="display: flex; justify-content: flex-end">
                <Button type="submit" :label="usePasskey ? t('auth.activation.createAccountPasskey') : t('auth.activation.createAccount')" :icon="usePasskey ? 'pi pi-key' : 'pi pi-check'" icon-pos="right" :loading="loading" />
              </div>
            </form>
          </StepPanel>

          <!-- Step 2: LLM Providers -->
          <StepPanel :value="1">
            <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <Message v-if="providerSetupError" severity="error" :closable="false">
                <div class="retry-message">
                  <span>{{ t('auth.activation.providerLoadContext', { error: providerSetupError }) }}</span>
                  <Button :label="t('auth.action.retry')" icon="pi pi-refresh" size="small" severity="secondary" :loading="loading" @click="refreshProviderSetup" />
                </div>
              </Message>
              <Message severity="info" :closable="false">
                {{ t('auth.activation.localProviderNotice') }}
              </Message>

              <!-- Capability coverage -->
              <div class="cap-matrix">
                <div class="cap-matrix-title">{{ t('auth.activation.capabilities') }}</div>
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
                    <span v-else class="cap-missing">{{ t('auth.activation.notConfigured') }}</span>
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
                    <label for="prov-id">{{ t('auth.activation.provider') }}</label>
                  </FloatLabel>
                  <!-- Preview what this provider will cover -->
                  <div v-if="selectedProviderCaps.length" class="cap-preview">
                    {{ t('auth.activation.provides') }}
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
                    <label for="prov-name">{{ t('auth.activation.displayName') }}</label>
                  </FloatLabel>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <InputText id="prov-slug" v-model="providerSlug" autocomplete="off" style="width: 100%" @input="onSlugInput" />
                    <label for="prov-slug">{{ t('auth.activation.slug') }}</label>
                  </FloatLabel>
                  <small style="color: var(--p-text-muted-color)">
                    {{ t('auth.activation.slugHelp') }}
                  </small>
                  <small v-if="providerSlug && !isValidProviderSlug(providerSlug)" class="field-error">
                    {{ t('auth.activation.slugInvalid') }}
                  </small>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <FloatLabel variant="on">
                    <InputText id="prov-url" v-model="baseURL" autocomplete="off" style="width: 100%" />
                    <label for="prov-url">{{ t('auth.activation.baseUrl') }}</label>
                  </FloatLabel>
                  <small v-if="!isValidProviderURL(baseURL, false)" class="field-error">
                    {{ t('auth.activation.urlInvalid') }}
                  </small>
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
                    <label for="prov-key">{{ t('auth.activation.apiKey') }}</label>
                  </FloatLabel>
                  <small v-if="!apiKey" class="field-error">{{ t('auth.activation.apiKeyRequired') }}</small>
                </div>
                <div style="display: flex; justify-content: flex-end">
                  <Button
                    type="submit"
                    :label="t('auth.activation.addProvider')"
                    icon="pi pi-plus"
                    :loading="loading"
                    :disabled="!providerFormValid"
                    severity="secondary"
                  />
                </div>
              </form>

              <!-- Navigation -->
              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button :label="t('auth.activation.skipSetup')" severity="secondary" text @click="skipToDashboard" />
                <Button
                  :label="t('auth.action.next')"
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
                {{ t('auth.activation.defaultsInstructions') }}
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
                {{ t('auth.activation.noModels') }}
              </p>

              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button :label="t('auth.action.back')" severity="secondary" text icon="pi pi-arrow-left" @click="activeStep = 1" />
                <Button :label="t('auth.action.next')" icon="pi pi-arrow-right" icon-pos="right" :loading="loading" @click="saveDefaultsAndContinue" />
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
                  <h3 style="margin: 0">{{ t('auth.activation.telegramTitle') }}</h3>
                  <p style="color: var(--p-text-muted-color); margin: 0">
                    {{ t('auth.activation.telegramIntro') }}
                  </p>
                </div>
              </div>

              <Message v-if="managerBotConfigured" severity="success" :closable="false">
                {{ managerBot?.managerError
                  ? t('auth.activation.managerConfiguredError', { name: managerBot?.botUsername || managerBot?.name || '', error: managerBot.managerError })
                  : t('auth.activation.managerConfigured', { name: managerBot?.botUsername || managerBot?.name || '' }) }}
              </Message>

              <div class="manager-guide">
                <div class="manager-guide-title">{{ t('auth.activation.telegramChecklist') }}</div>
                <ol>
                  <li>{{ t('auth.activation.telegramChecklistCreate') }}</li>
                  <li>{{ t('auth.activation.telegramChecklistPermission') }}</li>
                  <li>{{ t('auth.activation.telegramChecklistToken') }}</li>
                  <li>{{ t('auth.activation.telegramChecklistVerify') }}</li>
                </ol>
              </div>

              <div v-if="!managerBotConfigured" style="display: flex; flex-direction: column; gap: 0.75rem">
                <FloatLabel variant="on">
                  <Password id="manager-bot-token" v-model="managerBotToken" :feedback="false" toggleMask style="width: 100%" :input-style="{ width: '100%' }" />
                  <label for="manager-bot-token">{{ t('auth.activation.telegramBotToken') }}</label>
                </FloatLabel>
                <small style="color: var(--p-text-muted-color)">
                  {{ t('auth.activation.telegramBridgeHelp') }}
                </small>
                <div style="display: flex; justify-content: flex-end">
                  <Button :label="t('auth.activation.addManagerBot')" icon="pi pi-plus" :loading="loading" :disabled="!managerBotToken" @click="addManagerBot" />
                </div>
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button :label="t('auth.action.back')" severity="secondary" text icon="pi pi-arrow-left" @click="activeStep = 2" />
                <div style="display: flex; gap: 0.5rem">
                  <Button v-if="!managerBotConfigured" :label="t('auth.activation.skipForNow')" severity="secondary" text @click="finishActivation" />
                  <Button :label="t('auth.action.finish')" icon="pi pi-check" :disabled="!managerBotConfigured" @click="finishActivation" />
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
          {{ t('auth.activation.alreadySignIn') }}
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
.field-error {
  color: var(--p-red-500);
  font-size: 0.8rem;
}
.retry-message {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
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
