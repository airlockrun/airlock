<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useProvidersStore } from '@/stores/providers'
import { useCatalogStore } from '@/stores/catalog'
import ProviderModelsDialog from '@/components/providers/ProviderModelsDialog.vue'
import type { Provider } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'
import {
  OPENAI_COMPATIBLE_PROVIDER_ID,
  isValidProviderSlug,
  isValidProviderURL,
  setRowPending,
  uniqueProviderSlug,
} from '@/utils/providers'

const store = useProvidersStore()
const catalog = useCatalogStore()
const toast = useToast()
const confirm = useConfirm()
const { t, locale } = useAirlockI18n()

type Capability = 'text' | 'vision' | 'transcription' | 'speech' | 'image_gen' | 'embedding' | 'search'

const capabilityOrder: Capability[] = ['text', 'vision', 'transcription', 'speech', 'image_gen', 'embedding', 'search']
const capabilityMeta = computed<Record<Capability, { label: string; icon: string }>>(() => ({
  text:          { label: t('administration.capability.text'),          icon: 'pi pi-align-left' },
  vision:        { label: t('administration.capability.vision'),        icon: 'pi pi-image' },
  transcription: { label: t('administration.capability.transcription'), icon: 'pi pi-microphone' },
  speech:        { label: t('administration.capability.speech'),        icon: 'pi pi-volume-up' },
  image_gen:     { label: t('administration.capability.imageGeneration'), icon: 'pi pi-palette' },
  embedding:     { label: t('administration.capability.embedding'),     icon: 'pi pi-database' },
  search:        { label: t('administration.capability.search'),        icon: 'pi pi-search' },
}))

const dialogVisible = ref(false)
const editingId = ref<string | null>(null)
const dialogCapabilityFilter = ref<Capability | null>(null)
const form = ref({ providerId: '', slug: '', displayName: '', baseUrl: '', apiKey: '' })
const slugManual = ref(false)
const creationPath = ref<'hosted' | 'local'>('hosted')
const localPreset = ref('ollama')
const togglingIds = ref<Set<string>>(new Set())
const modelsVisible = ref(false)
const modelsProvider = ref<Provider | null>(null)

const creationPaths = computed(() => [
  { label: t('administration.providers.creationHosted'), value: 'hosted', icon: 'pi pi-cloud' },
  { label: t('administration.providers.creationLocal'), value: 'local', icon: 'pi pi-server' },
])
const localPresets = computed(() => [
  { label: 'Ollama', value: 'ollama', url: 'http://host.docker.internal:11434/v1' },
  { label: 'vLLM', value: 'vllm', url: 'http://host.docker.internal:8000/v1' },
  { label: 'llama.cpp', value: 'llama-cpp', url: 'http://host.docker.internal:8080/v1' },
  { label: 'LocalAI', value: 'localai', url: 'http://host.docker.internal:8080/v1' },
  { label: t('administration.providers.customPreset'), value: 'custom', url: '' },
])

onMounted(async () => {
  await Promise.all([store.fetchProviders(), catalog.fetchCapabilities(), catalog.fetchConfiguredModels()])
})

const coverageByCapability = computed<Record<Capability, Provider[]>>(() => {
  const out: Record<string, Provider[]> = {}
  for (const cap of capabilityOrder) out[cap] = []
  for (const provider of store.providers) {
    if (!provider.isEnabled) continue
    const capabilities = provider.providerId === OPENAI_COMPATIBLE_PROVIDER_ID
      ? [...new Set(catalog.models
          .filter((model) => model.providerConfigId === provider.id)
          .flatMap((model) => model.caps))]
      : catalog.capabilities.find((item) => item.providerId === provider.providerId)?.capabilities ?? []
    for (const capability of capabilities) {
      if (out[capability]) out[capability].push(provider)
    }
  }
  return out as Record<Capability, Provider[]>
})

// For the Add Provider dialog: candidates = the full known provider catalog.
// Multi-key support: don't filter out already-configured providers — admins
// can register a second OpenAI row for a different account/billing.
const dialogCandidates = computed(() => {
  const filter = dialogCapabilityFilter.value
  return catalog.capabilities
    .filter(p => p.providerId !== OPENAI_COMPATIBLE_PROVIDER_ID)
    .filter(p => !filter || p.capabilities.includes(filter))
    .map(p => ({
      id: p.providerId,
      name: p.displayName || p.providerId,
      capabilities: p.capabilities,
    }))
    .sort((a, b) => a.name.localeCompare(b.name, locale.value))
})

const isLocal = computed(() => form.value.providerId === OPENAI_COMPATIBLE_PROVIDER_ID)
const displayNameValid = computed(() => !!form.value.displayName.trim())
const slugValid = computed(() => isValidProviderSlug(form.value.slug))
const baseURLValid = computed(() => isValidProviderURL(form.value.baseUrl, isLocal.value))
const apiKeyValid = computed(() => !!editingId.value || isLocal.value || !!form.value.apiKey.trim())
const formValid = computed(() =>
  !!form.value.providerId &&
  displayNameValid.value &&
  slugValid.value &&
  baseURLValid.value &&
  apiKeyValid.value,
)

function proposeSlug(preferred: string) {
  if (slugManual.value || !form.value.providerId) return
  form.value.slug = uniqueProviderSlug(
    form.value.providerId,
    preferred,
    store.providers,
    editingId.value ?? '',
  )
}

function onDisplayNameInput() {
  proposeSlug(form.value.displayName)
}

function onSlugInput() {
  slugManual.value = true
}

function openCreate(capability?: Capability) {
  editingId.value = null
  dialogCapabilityFilter.value = capability ?? null
  form.value = { providerId: '', slug: '', displayName: '', baseUrl: '', apiKey: '' }
  slugManual.value = false
  creationPath.value = 'hosted'
  localPreset.value = 'ollama'
  dialogVisible.value = true
}

function openEdit(provider: { id: string; providerId: string; slug: string; displayName: string; baseUrl: string }) {
  editingId.value = provider.id
  dialogCapabilityFilter.value = null
  form.value = {
    providerId: provider.providerId,
    slug: provider.slug,
    displayName: provider.displayName,
    baseUrl: provider.baseUrl,
    apiKey: '',
  }
  slugManual.value = true
  dialogVisible.value = true
}

function onProviderSelect(id: string) {
  const match = dialogCandidates.value.find(c => c.id === id)
  if (match) {
    form.value.displayName = match.name
    proposeSlug(match.id)
  }
}

function onCreationPathChange(path: 'hosted' | 'local') {
  slugManual.value = false
  form.value = { providerId: '', slug: '', displayName: '', baseUrl: '', apiKey: '' }
  if (path === 'local') onLocalPresetSelect(localPreset.value)
}

function onLocalPresetSelect(value: string) {
  const preset = localPresets.value.find((item) => item.value === value)!
  form.value.providerId = OPENAI_COMPATIBLE_PROVIDER_ID
  form.value.displayName = preset.value === 'custom' ? t('administration.providers.localEndpointName') : preset.label
  form.value.baseUrl = preset.url
  proposeSlug(form.value.displayName)
}

async function onSubmit() {
  if (!formValid.value) {
    toast.add({ severity: 'error', summary: t('administration.providers.checkDetails'), life: 3000 })
    return
  }
  try {
    if (editingId.value) {
      await store.updateProvider(editingId.value, {
        displayName: form.value.displayName,
        slug: form.value.slug,
        baseUrl: form.value.baseUrl,
        ...(form.value.apiKey ? { apiKey: form.value.apiKey } : {}),
      })
      toast.add({ severity: 'success', summary: t('administration.providers.updated'), life: 3000 })
    } else {
      await store.createProvider(form.value)
      toast.add({ severity: 'success', summary: t('administration.providers.created'), life: 3000 })
    }
    dialogVisible.value = false
    catalog.fetchCapabilities() // refresh the matrix after a change
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.providers.operationFailed'), life: 5000 })
  }
}

function providerPending(id: string): boolean {
  return togglingIds.value.has(id)
}

function markProviderPending(id: string, pending: boolean) {
  togglingIds.value = setRowPending(togglingIds.value, id, pending)
}

async function toggleEnabled(provider: Provider, isEnabled: boolean) {
  if (providerPending(provider.id) || provider.isEnabled === isEnabled) return
  markProviderPending(provider.id, true)
  try {
    await store.updateProvider(provider.id, { isEnabled })
    await catalog.fetchCapabilities()
    toast.add({ severity: 'success', summary: isEnabled ? t('administration.providers.enabledToast') : t('administration.providers.disabledToast'), life: 3000 })
  } catch (err: any) {
    toast.add({
      severity: 'error',
      summary: isEnabled ? t('administration.providers.enableFailed') : t('administration.providers.disableFailed'),
      detail: err.response?.data?.error || err.message || t('administration.providers.statusUpdateFailed'),
      life: 5000,
    })
  } finally {
    markProviderPending(provider.id, false)
  }
}

function requestToggleEnabled(provider: Provider, isEnabled: boolean) {
  if (providerPending(provider.id) || provider.isEnabled === isEnabled) return
  if (isEnabled) {
    void toggleEnabled(provider, true)
    return
  }
  confirm.require({
    message: t('administration.providers.confirmDisable', { provider: provider.displayName || provider.slug }),
    header: t('administration.providers.confirmDisableTitle'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    acceptLabel: t('administration.action.disable'),
    rejectLabel: t('administration.action.cancel'),
    accept: () => void toggleEnabled(provider, false),
  })
}

function openModels(provider: Provider) {
  modelsProvider.value = provider
  modelsVisible.value = true
}

function confirmDelete(provider: { id: string; displayName: string }) {
  confirm.require({
    message: t('administration.providers.confirmDelete', { provider: provider.displayName }),
    header: t('administration.providers.confirmDeleteTitle'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteProvider(provider.id)
        toast.add({ severity: 'success', summary: t('administration.providers.deleted'), life: 3000 })
        catalog.fetchCapabilities()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.providers.deleteFailed'), life: 5000 })
      }
    },
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">{{ t('administration.providers.title') }}</h1>
      <Button :label="t('administration.providers.action.add')" icon="pi pi-plus" @click="openCreate()" />
    </div>

    <!-- Capability matrix -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>{{ t('administration.providers.capabilitiesTitle') }}</template>
      <template #subtitle>{{ t('administration.providers.capabilitiesSubtitle') }}</template>
      <template #content>
        <div class="cap-matrix">
          <div v-for="cap in capabilityOrder" :key="cap" class="cap-row">
            <div class="cap-label">
              <i :class="capabilityMeta[cap].icon" />
              <span>{{ capabilityMeta[cap].label }}</span>
            </div>
            <div class="cap-coverage">
              <template v-if="coverageByCapability[cap].length > 0">
                <Tag
                  v-for="p in coverageByCapability[cap]"
                  :key="p.id"
                  :value="`${p.displayName || p.providerId} (${p.slug})`"
                  severity="success"
                  style="font-size: 0.75rem"
                />
              </template>
              <span v-else class="cap-missing">{{ t('administration.providers.notAvailable') }}</span>
            </div>
            <div class="cap-action">
              <Button
                v-if="coverageByCapability[cap].length === 0"
                :label="t('administration.providers.action.addCapability', { capability: capabilityMeta[cap].label })"
                icon="pi pi-plus"
                size="small"
                severity="secondary"
                text
                @click="openCreate(cap)"
              />
            </div>
          </div>
        </div>
      </template>
    </Card>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column :header="t('administration.providers.name')"><template #body><Skeleton width="60%" /></template></Column>
      <Column :header="t('administration.providers.baseURL')"><template #body><Skeleton width="70%" /></template></Column>
      <Column :header="t('administration.providers.status')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column :header="t('administration.providers.actions')"><template #body><Skeleton width="5rem" /></template></Column>
    </DataTable>

    <!-- Configured providers table -->
    <DataTable v-else :value="store.providers" stripedRows scrollable class="providers-table">
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('administration.providers.noProviders') }}
        </div>
      </template>
      <Column :header="t('administration.providers.name')">
        <template #body="{ data }">
          <div class="provider-identity">
            <strong>{{ data.displayName || data.providerId }}</strong>
            <span>{{ data.providerId }}/{{ data.slug }}</span>
          </div>
        </template>
      </Column>
      <Column field="baseUrl" :header="t('administration.providers.baseURL')">
        <template #body="{ data }">
          <span class="base-url">{{ data.baseUrl || t('administration.providers.providerDefault') }}</span>
        </template>
      </Column>
      <Column :header="t('administration.providers.status')">
        <template #body="{ data }">
          <div class="status-control">
            <ToggleSwitch
              :model-value="data.isEnabled"
              :disabled="providerPending(data.id)"
              @update:model-value="(value: boolean) => requestToggleEnabled(data, value)"
            />
            <span>{{ data.isEnabled ? t('administration.providers.enabled') : t('administration.providers.disabled') }}</span>
          </div>
        </template>
      </Column>
      <Column :header="t('administration.providers.actions')">
        <template #body="{ data }">
          <div class="row-actions">
            <Button
              v-if="data.providerId === OPENAI_COMPATIBLE_PROVIDER_ID"
              :label="t('administration.providers.action.models')"
              icon="pi pi-box"
              severity="secondary"
              text
              @click="openModels(data)"
            />
            <Button icon="pi pi-pencil" :aria-label="t('administration.providers.action.editAria')" severity="secondary" text rounded @click="openEdit(data)" />
            <Button icon="pi pi-trash" :aria-label="t('administration.providers.action.deleteAria')" severity="danger" text rounded @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create / Edit dialog. The wrapping <form autocomplete="off"> + per-
         field autocomplete="off" stops browsers from treating Display Name +
         API Key like a username/password pair and offering to save it. -->
    <Dialog
      v-model:visible="dialogVisible"
      :header="editingId ? t('administration.providers.action.editTitle') : t('administration.providers.action.add')"
      modal
      style="width: 32rem; max-width: 96vw"
      :breakpoints="{ '600px': '96vw' }"
    >
      <form autocomplete="off" style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem" @submit.prevent>
        <Message
          v-if="!editingId && dialogCapabilityFilter"
          severity="info"
          :closable="false"
          style="margin-bottom: 0"
        >
          {{ t('administration.providers.showingCapability', { capability: capabilityMeta[dialogCapabilityFilter].label }) }}
          <a href="#" style="margin-left: 0.5rem" @click.prevent="dialogCapabilityFilter = null">{{ t('administration.providers.showAll') }}</a>
        </Message>
        <SelectButton
          v-if="!editingId"
          v-model="creationPath"
          :options="creationPaths"
          option-label="label"
          option-value="value"
          :allow-empty="false"
          fluid
          @update:model-value="onCreationPathChange"
        >
          <template #option="slotProps">
            <i :class="slotProps.option.icon" />
            <span>{{ slotProps.option.label }}</span>
          </template>
        </SelectButton>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <FloatLabel variant="on">
            <Select
              v-if="!editingId && creationPath === 'hosted'"
              id="providerId"
              v-model="form.providerId"
              :options="dialogCandidates"
              optionLabel="name"
              optionValue="id"
              :disabled="dialogCandidates.length === 0"
              filter
              autoFilterFocus
              resetFilterOnHide
              style="width: 100%"
              @update:modelValue="onProviderSelect"
            />
            <InputText v-else id="providerId" v-model="form.providerId" disabled autocomplete="off" style="width: 100%" />
            <label for="providerId">{{ t('administration.providers.name') }}</label>
          </FloatLabel>
        </div>
        <div v-if="!editingId && creationPath === 'local'" style="display: flex; flex-direction: column; gap: 0.25rem">
          <FloatLabel variant="on">
            <Select
              id="localPreset"
              v-model="localPreset"
              :options="localPresets"
              option-label="label"
              option-value="value"
              style="width: 100%"
              @update:model-value="onLocalPresetSelect"
            />
            <label for="localPreset">{{ t('administration.providers.endpointPreset') }}</label>
          </FloatLabel>
          <small style="color: var(--p-text-muted-color)">{{ t('administration.providers.endpointPresetHelp') }}</small>
        </div>
        <Message v-if="isLocal" severity="info" :closable="false">
          {{ t('administration.providers.localURLHelp') }}
        </Message>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <FloatLabel variant="on">
            <InputText id="displayName" v-model="form.displayName" autocomplete="off" style="width: 100%" @input="onDisplayNameInput" />
            <label for="displayName">{{ t('administration.providers.displayName') }}</label>
          </FloatLabel>
          <small v-if="form.displayName && !displayNameValid" class="field-error">{{ t('administration.providers.displayNameRequired') }}</small>
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <FloatLabel variant="on">
            <InputText id="slug" v-model="form.slug" autocomplete="off" style="width: 100%" @input="onSlugInput" />
            <label for="slug">{{ t('administration.providers.slug') }}</label>
          </FloatLabel>
          <small style="color: var(--p-text-muted-color)">
            {{ t('administration.providers.slugHelp') }}
          </small>
          <small v-if="form.slug && !slugValid" class="field-error">{{ t('administration.providers.slugInvalid') }}</small>
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <FloatLabel variant="on">
            <InputText id="baseUrl" v-model="form.baseUrl" autocomplete="off" style="width: 100%" />
            <label for="baseUrl">{{ isLocal ? t('administration.providers.baseURL') : t('administration.providers.baseURLOptional') }}</label>
          </FloatLabel>
          <small v-if="!isLocal" style="color: var(--p-text-muted-color)">{{ t('administration.providers.baseURLDefaultHelp') }}</small>
          <small v-if="form.baseUrl && !baseURLValid" class="field-error">{{ t('administration.providers.baseURLInvalid') }}</small>
          <small v-else-if="isLocal && !form.baseUrl" class="field-error">{{ t('administration.providers.localURLRequired') }}</small>
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <!-- type="text" + -webkit-text-security keeps the visual masking but
               avoids the password manager entirely — Chrome fixates on
               type="password" and ignores autocomplete tokens. -->
          <FloatLabel variant="on">
            <InputText
              id="apiKey"
              v-model="form.apiKey"
              type="text"
              autocomplete="off"
              name="provider-api-key"
              data-1p-ignore="true"
              data-lpignore="true"
              data-bwignore="true"
              style="width: 100%; -webkit-text-security: disc;"
            />
            <label for="apiKey">
              {{ editingId ? t('administration.providers.apiKeyKeepCurrent') : isLocal ? t('administration.providers.apiKeyOptional') : t('administration.providers.apiKey') }}
            </label>
          </FloatLabel>
          <small v-if="!apiKeyValid" class="field-error">{{ t('administration.providers.apiKeyRequired') }}</small>
        </div>
      </form>
      <template #footer>
        <Button :label="t('administration.action.cancel')" severity="secondary" text @click="dialogVisible = false" />
        <Button :label="editingId ? t('administration.action.update') : t('administration.action.create')" :disabled="!formValid" @click="onSubmit" />
      </template>
    </Dialog>

    <ProviderModelsDialog v-model:visible="modelsVisible" :provider="modelsProvider" />
  </div>
</template>

<style scoped>
.cap-matrix {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.cap-row {
  display: grid;
  grid-template-columns: 8rem 1fr auto;
  gap: 1rem;
  align-items: center;
}
.cap-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
}
.cap-coverage {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
  min-height: 1.75rem;
  align-items: center;
}
.cap-missing {
  color: var(--p-text-muted-color);
  font-style: italic;
  font-size: 0.85rem;
}
.provider-identity {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}
.provider-identity span,
.status-control span {
  color: var(--p-text-muted-color);
  font-size: 0.8rem;
}
.base-url {
  overflow-wrap: anywhere;
}
.status-control,
.row-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.row-actions {
  white-space: nowrap;
}
.field-error {
  color: var(--p-red-500);
}
:deep(.providers-table .p-datatable-table) {
  min-width: 52rem;
}
@media (max-width: 600px) {
  .cap-row {
    grid-template-columns: 6.5rem 1fr;
  }
  .cap-action {
    grid-column: 2;
  }
  :deep(.p-selectbutton) {
    display: grid;
    grid-template-columns: 1fr;
  }
}
</style>
