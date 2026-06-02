<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { fromJson, toJson } from '@bufbuild/protobuf'
import { useAuthStore } from '@/stores/auth'
import { useCatalogStore } from '@/stores/catalog'
import { useToast } from 'primevue/usetoast'
import { useTheme } from '@/composables/useTheme'
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
import {
  SystemSettingsInfoSchema,
  UpdateTelegramManagerBotResponseSchema,
} from '@/gen/airlock/v1/types_pb'

const auth = useAuthStore()
const catalog = useCatalogStore()
const providers = useProvidersStore()
const toast = useToast()
const { isDark, toggle: toggleTheme } = useTheme()
const { groupModels, searchProviderOptions } = useModelCapabilities()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)

// Connected apps (OAuth grants) — apps the user has authorized to
// reach their agents via the MCP server-side OAuth flow. The list +
// revoke buttons let the user yank consent without an admin doing it.
interface GrantDTO {
  clientId: string
  clientName: string
  agentId: string
  agentSlug: string
  agentName: string
  scope: string
  grantedAt: string
  expiresAt: string
}
const grants = ref<GrantDTO[]>([])
const grantsLoading = ref(false)

async function loadGrants() {
  grantsLoading.value = true
  try {
    const { data } = await api.get('/api/v1/oauth/grants')
    grants.value = data || []
  } catch {
    grants.value = []
  } finally {
    grantsLoading.value = false
  }
}

async function revokeGrant(g: GrantDTO) {
  try {
    await api.delete(`/api/v1/oauth/grants/${encodeURIComponent(g.clientId)}/${encodeURIComponent(g.agentId)}`)
    grants.value = grants.value.filter(x => !(x.clientId === g.clientId && x.agentId === g.agentId))
    toast.add({ severity: 'success', summary: 'Access revoked', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || 'revoke failed', life: 5000 })
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString()
  } catch {
    return iso
  }
}

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
  applyManagerBotStatus(info)
}

onMounted(async () => {
  loadGrants()
  if (auth.isAdmin) {
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
    help: 'Used by Sol for agent code generation and upgrades.',
    options: groupModels(isLanguage),
    placeholder: 'Select default build model',
  },
  {
    key: 'defaultExecModel',
    label: 'Execution Model (Text)',
    icon: 'pi pi-align-left',
    help: 'Runtime default when agents make language-model calls.',
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
    help: 'Telegram voice notes are auto-transcribed with this model before being sent to agents. Leave empty to disable.',
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
    help: 'Default search provider. Stored as a provider ID — search is a provider-level tool.',
    options: searchProviderOptions.value,
    placeholder: 'Select search provider',
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

// Telegram Manager Bot (admin only). Holds the editor state for the
// token input plus the live status the backend reports (resolved
// username from getMe + last validation error). The raw token never
// comes back from the API — only the configured flag.
const managerBotToken = ref('')
const managerBotConfigured = ref(false)
const managerBotUsername = ref('')
const managerBotError = ref('')
const managerBotSaving = ref(false)

function applyManagerBotStatus(info: SystemSettingsInfo) {
  managerBotConfigured.value = !!info.telegramManagerBotConfigured
  managerBotUsername.value = info.telegramManagerBotUsername || ''
  managerBotError.value = info.telegramManagerBotError || ''
}

async function saveManagerBot() {
  managerBotSaving.value = true
  try {
    const { data } = await api.put('/api/v1/settings/telegram-manager-bot', { token: managerBotToken.value })
    const resp = fromJson(UpdateTelegramManagerBotResponseSchema, data)
    managerBotConfigured.value = resp.configured
    managerBotUsername.value = resp.username || ''
    managerBotError.value = resp.error || ''
    managerBotToken.value = ''
    if (resp.configured) {
      toast.add({ severity: 'success', summary: `Connected as @${resp.username}`, life: 3000 })
    } else {
      toast.add({ severity: 'success', summary: 'Manager bot disabled', life: 3000 })
    }
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || 'Save failed', life: 5000 })
  } finally {
    managerBotSaving.value = false
  }
}

async function changePassword() {
  if (!currentPassword.value || !newPassword.value || !confirmPassword.value) {
    toast.add({ severity: 'error', summary: 'All fields are required', life: 3000 })
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    toast.add({ severity: 'error', summary: 'New passwords do not match', life: 3000 })
    return
  }
  loading.value = true
  try {
    await auth.changePassword(currentPassword.value, newPassword.value)
    toast.add({ severity: 'success', summary: 'Password changed', life: 3000 })
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed', life: 5000 })
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div style="max-width: 36rem">
    <h1 style="font-size: 1.5rem; margin-bottom: 1.5rem">Settings</h1>

    <!-- Appearance -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>Appearance</template>
      <template #content>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <span>Dark Mode</span>
          <ToggleSwitch v-model="isDark" @change="toggleTheme" />
        </div>
      </template>
    </Card>

    <!-- Default Models (admin only) -->
    <Card v-if="auth.isAdmin" style="margin-bottom: 1.5rem">
      <template #title>Default Models</template>
      <template #subtitle>
        Per-capability defaults. Used wherever the system needs a model for a capability and no agent-specific override is set.
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

    <!-- Telegram Manager Bot (admin only) -->
    <Card v-if="auth.isAdmin" style="margin-bottom: 1.5rem">
      <template #title>Telegram Manager Bot</template>
      <template #subtitle>
        Used for the "Create new bot via Telegram" flow on the Bridges page. Configure a Telegram bot that has <code>can_manage_bots</code> enabled in BotFather and paste its token here.
      </template>
      <template #content>
        <div style="display: flex; flex-direction: column; gap: 0.75rem">
          <div v-if="managerBotConfigured" style="display: flex; align-items: center; gap: 0.5rem">
            <i class="pi pi-check-circle" style="color: var(--p-green-500)" />
            <span>Connected as <strong>@{{ managerBotUsername || 'unknown' }}</strong></span>
          </div>
          <div v-else-if="managerBotError" style="display: flex; align-items: center; gap: 0.5rem">
            <i class="pi pi-times-circle" style="color: var(--p-red-500)" />
            <span style="color: var(--p-red-500)">{{ managerBotError }}</span>
          </div>
          <div v-else style="color: var(--p-text-muted-color)">
            Not configured.
          </div>
          <label for="managerBotToken">Bot token</label>
          <Password id="managerBotToken" v-model="managerBotToken" :feedback="false" toggleMask placeholder="Paste a new token to replace, or leave empty to disable" />
          <div style="display: flex; gap: 0.5rem; align-items: center">
            <Button label="Save" :loading="managerBotSaving" @click="saveManagerBot" />
            <small style="color: var(--p-text-muted-color)">Empty token disables the feature.</small>
          </div>
        </div>
      </template>
    </Card>

    <!-- Connected apps (OAuth grants) -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>Connected apps</template>
      <template #subtitle>
        External MCP clients (Claude Desktop, VSCode, Codex, …) that you've authorized to talk to your agents.
        Revoking immediately stops future requests; tokens already issued may keep working for up to 15 minutes
        until their access token naturally expires.
      </template>
      <template #content>
        <div v-if="grantsLoading" style="color: var(--p-text-muted-color)">Loading…</div>
        <div v-else-if="grants.length === 0" style="color: var(--p-text-muted-color)">
          No external apps are connected.
        </div>
        <DataTable v-else :value="grants" stripedRows size="small">
          <Column field="clientName" header="App" />
          <Column header="Agent">
            <template #body="{ data }">
              <RouterLink :to="`/agents/${data.agentId}`">{{ data.agentName }}</RouterLink>
              <span style="color: var(--p-text-muted-color); margin-left: 0.5rem">
                ({{ data.agentSlug }})
              </span>
            </template>
          </Column>
          <Column header="Granted">
            <template #body="{ data }">{{ formatDate(data.grantedAt) }}</template>
          </Column>
          <Column header="Expires">
            <template #body="{ data }">{{ formatDate(data.expiresAt) }}</template>
          </Column>
          <Column header="">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                size="small"
                severity="danger"
                text
                @click="revokeGrant(data)"
                v-tooltip.left="'Revoke access'"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Change Password -->
    <Card>
      <template #title>Change Password</template>
      <template #content>
        <form @submit.prevent="changePassword" style="display: flex; flex-direction: column; gap: 1.25rem">
          <FloatLabel>
            <Password id="set-current" v-model="currentPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'current-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="set-current">Current Password</label>
          </FloatLabel>
          <FloatLabel>
            <Password id="set-new" v-model="newPassword" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="set-new">New Password</label>
          </FloatLabel>
          <FloatLabel>
            <Password id="set-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="set-confirm">Confirm New Password</label>
          </FloatLabel>
          <Button type="submit" label="Change Password" :loading="loading" style="align-self: flex-start" />
        </form>
      </template>
    </Card>
  </div>
</template>
