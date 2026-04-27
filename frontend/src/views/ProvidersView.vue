<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useProvidersStore } from '@/stores/providers'
import { useCatalogStore } from '@/stores/catalog'

const store = useProvidersStore()
const catalog = useCatalogStore()
const toast = useToast()
const confirm = useConfirm()

type Capability = 'text' | 'vision' | 'stt' | 'tts' | 'image_gen' | 'search'

const capabilityOrder: Capability[] = ['text', 'vision', 'stt', 'tts', 'image_gen', 'search']
const capabilityMeta: Record<Capability, { label: string; icon: string; description: string }> = {
  text:      { label: 'Text',       icon: 'pi pi-align-left',  description: 'LLMs that take text in and produce text out.' },
  vision:    { label: 'Vision',     icon: 'pi pi-image',       description: 'Models that can read images.' },
  stt:       { label: 'STT',        icon: 'pi pi-microphone',  description: 'Speech-to-text (audio in → text out).' },
  tts:       { label: 'TTS',        icon: 'pi pi-volume-up',   description: 'Text-to-speech (text in → audio out).' },
  image_gen: { label: 'Image gen',  icon: 'pi pi-palette',     description: 'Text-to-image generation.' },
  search:    { label: 'Web search', icon: 'pi pi-search',      description: 'Live web search for agents.' },
}

const dialogVisible = ref(false)
const editingId = ref<string | null>(null)
const dialogCapabilityFilter = ref<Capability | null>(null)
const form = ref({ providerId: '', displayName: '', baseUrl: '', apiKey: '' })

onMounted(() => {
  store.fetchProviders()
  catalog.fetchCapabilities()
})

const coverageByCapability = computed<Record<Capability, typeof catalog.capabilities>>(() => {
  const out: Record<string, typeof catalog.capabilities> = {}
  for (const cap of capabilityOrder) out[cap] = []
  for (const p of catalog.capabilities) {
    if (!p.configured) continue
    for (const c of p.capabilities) {
      if (out[c]) out[c].push(p)
    }
  }
  return out as Record<Capability, typeof catalog.capabilities>
})

// For the Add Provider dialog: candidates = known providers that aren't
// already configured. When a capability filter is active, require that
// capability to be in the candidate's set.
const dialogCandidates = computed(() => {
  const filter = dialogCapabilityFilter.value
  return catalog.capabilities
    .filter(p => !p.configured)
    .filter(p => !filter || p.capabilities.includes(filter))
    .map(p => ({
      id: p.providerId,
      name: p.displayName || p.providerId,
      capabilities: p.capabilities,
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
})

function openCreate(capability?: Capability) {
  editingId.value = null
  dialogCapabilityFilter.value = capability ?? null
  form.value = { providerId: '', displayName: '', baseUrl: '', apiKey: '' }
  dialogVisible.value = true
}

function openEdit(provider: { id: string; providerId: string; displayName: string; baseUrl: string }) {
  editingId.value = provider.id
  dialogCapabilityFilter.value = null
  form.value = {
    providerId: provider.providerId,
    displayName: provider.displayName,
    baseUrl: provider.baseUrl,
    apiKey: '',
  }
  dialogVisible.value = true
}

function onProviderSelect(id: string) {
  const match = dialogCandidates.value.find(c => c.id === id)
  if (match) form.value.displayName = match.name
}

async function onSubmit() {
  try {
    if (editingId.value) {
      await store.updateProvider(editingId.value, {
        displayName: form.value.displayName,
        baseUrl: form.value.baseUrl,
        ...(form.value.apiKey ? { apiKey: form.value.apiKey } : {}),
      })
      toast.add({ severity: 'success', summary: 'Provider updated', life: 3000 })
    } else {
      await store.createProvider(form.value)
      toast.add({ severity: 'success', summary: 'Provider created', life: 3000 })
    }
    dialogVisible.value = false
    catalog.fetchCapabilities() // refresh the matrix after a change
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Operation failed', life: 5000 })
  }
}

function confirmDelete(provider: { id: string; displayName: string }) {
  confirm.require({
    message: `Delete provider "${provider.displayName}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteProvider(provider.id)
        toast.add({ severity: 'success', summary: 'Provider deleted', life: 3000 })
        catalog.fetchCapabilities()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Providers</h1>
      <Button label="Add Provider" icon="pi pi-plus" @click="openCreate()" />
    </div>

    <!-- Capability matrix -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>Capabilities</template>
      <template #subtitle>What your configured providers can do. Click Add on any missing capability to discover providers that supply it.</template>
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
                  :key="p.providerId"
                  :value="p.displayName || p.providerId"
                  severity="success"
                  style="font-size: 0.75rem"
                />
              </template>
              <span v-else class="cap-missing">Not available</span>
            </div>
            <div class="cap-action">
              <Button
                v-if="coverageByCapability[cap].length === 0"
                :label="`Add ${capabilityMeta[cap].label}`"
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
      <Column header="Display Name"><template #body><Skeleton width="60%" /></template></Column>
      <Column header="Provider ID"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Base URL"><template #body><Skeleton width="70%" /></template></Column>
      <Column header="Status"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Actions"><template #body><Skeleton width="5rem" /></template></Column>
    </DataTable>

    <!-- Configured providers table -->
    <DataTable v-else :value="store.providers" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No providers configured yet.
        </div>
      </template>
      <Column field="displayName" header="Display Name" />
      <Column field="providerId" header="Provider ID" />
      <Column field="baseUrl" header="Base URL" />
      <Column header="Status">
        <template #body="{ data }">
          <Tag :value="data.isEnabled ? 'Enabled' : 'Disabled'" :severity="data.isEnabled ? 'success' : 'secondary'" />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <div style="display: flex; gap: 0.5rem">
            <Button icon="pi pi-pencil" severity="secondary" text rounded @click="openEdit(data)" />
            <Button icon="pi pi-trash" severity="danger" text rounded @click="confirmDelete(data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <!-- Create / Edit dialog. The wrapping <form autocomplete="off"> + per-
         field autocomplete="off" stops browsers from treating Display Name +
         API Key like a username/password pair and offering to save it. -->
    <Dialog v-model:visible="dialogVisible" :header="editingId ? 'Edit Provider' : 'Add Provider'" modal style="width: 28rem">
      <form autocomplete="off" style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem" @submit.prevent>
        <Message
          v-if="!editingId && dialogCapabilityFilter"
          severity="info"
          :closable="false"
          style="margin-bottom: 0"
        >
          Showing providers that supply <b>{{ capabilityMeta[dialogCapabilityFilter].label }}</b>.
          <a href="#" style="margin-left: 0.5rem" @click.prevent="dialogCapabilityFilter = null">Show all</a>
        </Message>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="providerId">Provider</label>
          <Select
            v-if="!editingId"
            id="providerId"
            v-model="form.providerId"
            :options="dialogCandidates"
            optionLabel="name"
            optionValue="id"
            :placeholder="dialogCandidates.length ? 'Select a provider' : 'No matching providers available'"
            :disabled="dialogCandidates.length === 0"
            filter
            autoFilterFocus
            style="width: 100%"
            @update:modelValue="onProviderSelect"
          />
          <InputText v-else id="providerId" v-model="form.providerId" disabled autocomplete="off" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="displayName">Display Name</label>
          <InputText id="displayName" v-model="form.displayName" autocomplete="off" placeholder="e.g. OpenAI" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="baseUrl">Base URL (optional)</label>
          <InputText id="baseUrl" v-model="form.baseUrl" autocomplete="off" placeholder="Leave blank for provider default" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="apiKey">API Key{{ editingId ? ' (leave blank to keep current)' : '' }}</label>
          <Password id="apiKey" v-model="form.apiKey" :feedback="false" toggleMask :input-props="{ autocomplete: 'off' }" />
        </div>
      </form>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button :label="editingId ? 'Update' : 'Create'" :disabled="!editingId && !form.providerId" @click="onSubmit" />
      </template>
    </Dialog>
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
</style>
