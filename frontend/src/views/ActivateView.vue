<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { fromJson, toJson } from '@bufbuild/protobuf'
import { useAuthStore } from '@/stores/auth'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'
import {
  useModelCapabilities,
  supportsText,
  supportsVision,
  supportsSTT,
  supportsTTS,
  supportsImageGen,
} from '@/composables/useModelCapabilities'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import {
  GetSystemSettingsResponseSchema,
  UpdateSystemSettingsRequestSchema,
} from '@/gen/airlock/v1/api_pb'
import type { SystemSettingsInfo } from '@/gen/airlock/v1/types_pb'

const router = useRouter()
const auth = useAuthStore()
const catalog = useCatalogStore()
const providersStore = useProvidersStore()
const toast = useToast()
const { groupModels, searchProviderOptions } = useModelCapabilities()

const activeStep = ref(0)
const alreadyActivated = ref(false)
const activationCodeRequired = ref(false)
const loading = ref(false)
const error = ref('')

onMounted(async () => {
  catalog.fetchCatalogProviders()
  try {
    const { data } = await api.get('/auth/status')
    if (data.activated) alreadyActivated.value = true
    if (data.activation_code_required) activationCodeRequired.value = true
  } catch { /* show the form anyway */ }
})

// --- Step 1: Admin account
const activationCode = ref('')
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const displayName = ref('')

async function nextStep() {
  error.value = ''
  if (activationCodeRequired.value && !activationCode.value) {
    error.value = 'Activation code is required.'
    return
  }
  if (!email.value || !password.value || !confirmPassword.value) {
    error.value = 'All fields are required.'
    return
  }
  if (password.value !== confirmPassword.value) {
    error.value = 'Passwords do not match.'
    return
  }
  if (password.value.length < 8) {
    error.value = 'Password must be at least 8 characters.'
    return
  }

  loading.value = true
  try {
    await auth.activate(email.value, password.value, displayName.value || email.value, activationCode.value)
    // After activation we're logged in as admin. Load the data for steps 2-3.
    catalog.fetchCapabilities()
    activeStep.value = 1
  } catch (err: any) {
    if (err.response?.status === 409) {
      alreadyActivated.value = true
    } else {
      error.value = err.response?.data?.error || 'Activation failed.'
    }
  } finally {
    loading.value = false
  }
}

// --- Step 2: LLM Providers
type Capability = 'text' | 'vision' | 'stt' | 'tts' | 'image_gen' | 'search'

const capabilityOrder: Capability[] = ['text', 'vision', 'stt', 'tts', 'image_gen', 'search']
const capabilityMeta: Record<Capability, { label: string; icon: string }> = {
  text:      { label: 'Text',       icon: 'pi pi-align-left' },
  vision:    { label: 'Vision',     icon: 'pi pi-image' },
  stt:       { label: 'STT',        icon: 'pi pi-microphone' },
  tts:       { label: 'TTS',        icon: 'pi pi-volume-up' },
  image_gen: { label: 'Image gen',  icon: 'pi pi-palette' },
  search:    { label: 'Web search', icon: 'pi pi-search' },
}

const providerID = ref('')
const providerName = ref('')
const baseURL = ref('')
const apiKey = ref('')

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
  if (p) providerName.value = p.name
}

function resetProviderForm() {
  providerID.value = ''
  providerName.value = ''
  baseURL.value = ''
  apiKey.value = ''
}

async function addProvider() {
  error.value = ''
  if (!providerID.value || !apiKey.value) {
    error.value = 'Provider and API key are required.'
    return
  }

  loading.value = true
  try {
    await providersStore.createProvider({
      providerId: providerID.value,
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
  // Pull both configured models and any previously-saved settings so the
  // defaults step can render sensible rows.
  loading.value = true
  try {
    await Promise.all([
      catalog.fetchConfiguredModels(),
      loadExistingDefaults(),
    ])
    activeStep.value = 2
  } finally {
    loading.value = false
  }
}

function skipToDashboard() {
  toast.add({ severity: 'info', summary: 'Setup skipped', detail: 'You can configure providers and defaults later in Settings.', life: 5000 })
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
const publicURL = ref('')
const agentDomain = ref('')

async function loadExistingDefaults() {
  try {
    const { data } = await api.get('/api/v1/settings')
    const resp = fromJson(GetSystemSettingsResponseSchema, data)
    if (resp.settings) {
      defaults.value.defaultBuildModel     = resp.settings.defaultBuildModel || ''
      defaults.value.defaultExecModel      = resp.settings.defaultExecModel || ''
      defaults.value.defaultVisionModel    = resp.settings.defaultVisionModel || ''
      defaults.value.defaultSttModel       = resp.settings.defaultSttModel || ''
      defaults.value.defaultTtsModel       = resp.settings.defaultTtsModel || ''
      defaults.value.defaultImageGenModel  = resp.settings.defaultImageGenModel || ''
      defaults.value.defaultEmbeddingModel = resp.settings.defaultEmbeddingModel || ''
      defaults.value.defaultSearchModel    = resp.settings.defaultSearchModel || ''
      publicURL.value  = resp.settings.publicUrl || ''
      agentDomain.value = resp.settings.agentDomain || ''
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
  { key: 'defaultBuildModel',     label: 'Build Model',      icon: 'pi pi-hammer',     help: 'Used by Sol to generate agent code.', options: groupModels(supportsText),     grouped: true },
  { key: 'defaultExecModel',      label: 'Execution (Text)', icon: 'pi pi-align-left', help: 'Runtime default for LLM calls.',      options: groupModels(supportsText),     grouped: true },
  { key: 'defaultVisionModel',    label: 'Vision',           icon: 'pi pi-image',      help: 'Image → text.',                       options: groupModels(supportsVision),   grouped: true },
  { key: 'defaultSttModel',       label: 'STT',              icon: 'pi pi-microphone', help: 'Speech-to-text.',                     options: groupModels(supportsSTT),      grouped: true },
  { key: 'defaultTtsModel',       label: 'TTS',              icon: 'pi pi-volume-up',  help: 'Text-to-speech.',                     options: groupModels(supportsTTS),      grouped: true },
  { key: 'defaultImageGenModel',  label: 'Image Gen',        icon: 'pi pi-palette',    help: 'Text-to-image generation.',           options: groupModels(supportsImageGen), grouped: true },
  { key: 'defaultEmbeddingModel', label: 'Embedding',        icon: 'pi pi-database',   help: 'Text → vector embeddings.',           options: groupModels(supportsText),     grouped: true },
  { key: 'defaultSearchModel',    label: 'Web Search',       icon: 'pi pi-search',     help: 'Search provider (provider ID).',      options: searchProviderOptions.value,    grouped: false },
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

async function finish() {
  error.value = ''
  loading.value = true
  try {
    const info: SystemSettingsInfo = {
      $typeName: 'airlock.v1.SystemSettingsInfo',
      publicUrl: publicURL.value,
      agentDomain: agentDomain.value,
      defaultBuildModel:     defaults.value.defaultBuildModel,
      defaultExecModel:      defaults.value.defaultExecModel,
      defaultSttModel:       defaults.value.defaultSttModel,
      defaultVisionModel:    defaults.value.defaultVisionModel,
      defaultTtsModel:       defaults.value.defaultTtsModel,
      defaultImageGenModel:  defaults.value.defaultImageGenModel,
      defaultEmbeddingModel: defaults.value.defaultEmbeddingModel,
      defaultSearchModel:    defaults.value.defaultSearchModel,
    }
    const req = toJson(UpdateSystemSettingsRequestSchema, {
      $typeName: 'airlock.v1.UpdateSystemSettingsRequest',
      settings: info,
    })
    await api.put('/api/v1/settings', req)
    toast.add({ severity: 'success', summary: 'Airlock activated', life: 3000 })
    router.push('/')
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to save defaults.'
  } finally {
    loading.value = false
  }
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

  <Card v-else style="width: 34rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Airlock Setup</div>
    </template>
    <template #content>
      <Stepper v-model:value="activeStep" linear>
        <StepList>
          <Step :value="0">Admin Account</Step>
          <Step :value="1">LLM Providers</Step>
          <Step :value="2">Default Models</Step>
        </StepList>
        <StepPanels>
          <!-- Step 1: Admin Account -->
          <StepPanel :value="0">
            <form @submit.prevent="nextStep" style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 1rem">
              <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
              <FloatLabel v-if="activationCodeRequired">
                <InputText id="act-code" v-model="activationCode" autocomplete="one-time-code" style="width: 100%" />
                <label for="act-code">Activation Code</label>
              </FloatLabel>
              <FloatLabel>
                <InputText id="act-email" v-model="email" type="email" autocomplete="username" style="width: 100%" />
                <label for="act-email">Email</label>
              </FloatLabel>
              <FloatLabel>
                <Password id="act-pass" v-model="password" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                <label for="act-pass">Password</label>
              </FloatLabel>
              <FloatLabel>
                <Password id="act-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
                <label for="act-confirm">Confirm Password</label>
              </FloatLabel>
              <FloatLabel>
                <InputText id="act-name" v-model="displayName" autocomplete="name" style="width: 100%" />
                <label for="act-name">Display Name</label>
              </FloatLabel>
              <div style="display: flex; justify-content: flex-end">
                <Button type="submit" label="Next" icon="pi pi-arrow-right" icon-pos="right" :loading="loading" />
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
                  <label for="prov-id">Provider</label>
                  <Select
                    id="prov-id"
                    v-model="providerID"
                    :options="providerCandidates"
                    optionLabel="name"
                    optionValue="id"
                    :placeholder="providerCandidates.length ? 'Select a provider' : 'All providers already configured'"
                    :disabled="providerCandidates.length === 0"
                    filter
                    autoFilterFocus
                    showClear
                    style="width: 100%"
                    @update:modelValue="onProviderSelect"
                  />
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
                  <label for="prov-name">Display Name</label>
                  <InputText id="prov-name" v-model="providerName" autocomplete="off" style="width: 100%" />
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <label for="prov-url">Base URL (optional)</label>
                  <InputText id="prov-url" v-model="baseURL" autocomplete="off" style="width: 100%" />
                </div>
                <div style="display: flex; flex-direction: column; gap: 0.25rem">
                  <label for="prov-key">API Key</label>
                  <Password id="prov-key" v-model="apiKey" :feedback="false" toggle-mask :input-props="{ autocomplete: 'off' }" style="width: 100%" :input-style="{ width: '100%' }" />
                </div>
                <div style="display: flex; justify-content: flex-end">
                  <Button
                    type="submit"
                    label="Add provider"
                    icon="pi pi-plus"
                    :loading="loading"
                    :disabled="!providerID || !apiKey"
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
                Pick a default model for each capability. Agents inherit these unless they override. You can change them anytime under Settings.
              </p>

              <div
                v-for="row in visibleDefaultRows"
                :key="row.key"
                style="display: flex; flex-direction: column; gap: 0.5rem"
              >
                <label :for="`def-${row.key}`" style="font-weight: 500; display: flex; align-items: center; gap: 0.5rem">
                  <i :class="row.icon" />
                  <span>{{ row.label }}</span>
                </label>
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
                  placeholder="No default — leave empty"
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
                  placeholder="No default — leave empty"
                  :loading="catalog.loading"
                  style="width: 100%"
                />
                <small style="color: var(--p-text-muted-color)">{{ row.help }}</small>
              </div>

              <p v-if="!visibleDefaultRows.length" style="color: var(--p-text-muted-color); margin: 0">
                No models yet. Go back and add a provider that offers at least one capability.
              </p>

              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--p-surface-border); padding-top: 1rem">
                <Button label="Back" severity="secondary" text icon="pi pi-arrow-left" @click="activeStep = 1" />
                <Button label="Finish" icon="pi pi-check" :loading="loading" @click="finish" />
              </div>
            </div>
          </StepPanel>
        </StepPanels>
      </Stepper>
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
</style>
