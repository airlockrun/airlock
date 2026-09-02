<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useProvidersStore } from '@/stores/providers'
import { useCatalogStore } from '@/stores/catalog'
import { useModelGrantsStore } from '@/stores/modelGrants'
import type { ModelInfo, Provider } from '@/gen/airlock/v1/types_pb'
import { modelMatchesProvider } from '@/composables/useModelCapabilities'
import { useAirlockI18n } from '@/i18n'

const providers = useProvidersStore()
const catalog = useCatalogStore()
const grants = useModelGrantsStore()
const toast = useToast()
const confirm = useConfirm()
const { t, locale, formatNumber } = useAirlockI18n()

const search = ref('')

onMounted(async () => {
  await Promise.all([
    providers.fetchProviders(),
    catalog.fetchConfiguredModels(),
    grants.fetchGrants(),
  ])
})

// modelHaystack is the lowercased text the search box matches against: name + id
// plus capabilities — the kind (transcription/speech/image/embedding/language)
// and per-model caps (vision, …) — so a query like "transcription" or "vision"
// surfaces those models, not just name matches.
function modelHaystack(m: ModelInfo): string {
  const caps = [m.kind, ...m.caps]
  if (m.toolCall) caps.push('tools')
  if (m.reasoning) caps.push('reasoning')
  return [m.name, m.id, ...caps, ...caps.map(capabilityLabel)].join(' ').toLocaleLowerCase(locale.value)
}

function capabilityLabel(capability: string): string {
  const label = (() => {
    switch (capability) {
      case 'text': return t('administration.capability.text')
      case 'vision': return t('administration.capability.vision')
      case 'transcription': return t('administration.capability.transcription')
      case 'speech': return t('administration.capability.speech')
      case 'image': return t('administration.capability.image')
      case 'image_gen': return t('administration.capability.imageGeneration')
      case 'embedding': return t('administration.capability.embedding')
      case 'reranking': return t('administration.capability.reranking')
      case 'search': return t('administration.capability.search')
      case 'video': return t('administration.capability.video')
      case 'file': return t('administration.capability.file')
      case 'tools': return t('administration.capability.tools')
      case 'reasoning': return t('administration.capability.reasoning')
      default: return capability
    }
  })()
  return label.toLocaleLowerCase(locale.value)
}

// One group per configured (enabled) provider row, with the catalog models that
// provider supplies. Allowance is keyed on the provider row, so two rows for the
// same catalog provider are listed (and toggled) independently.
const groups = computed(() => {
  const q = search.value.trim().toLocaleLowerCase(locale.value)
  return providers.providers
    .filter((p) => p.isEnabled)
    .map((p) => ({
      provider: p,
      models: catalog.models
        .filter((m) => modelMatchesProvider(m, p))
        .filter((m) => !q || modelHaystack(m).includes(q))
        .sort((a, b) => a.id.localeCompare(b.id)),
    }))
    .filter((g) => g.models.length > 0)
})

const allowedCount = computed(() => {
  const current = new Set<string>()
  for (const provider of providers.providers) {
    if (!provider.isEnabled) continue
    for (const model of catalog.models) {
      if (modelMatchesProvider(model, provider)) current.add(`${provider.id}::${model.id}`)
    }
  }
  return grants.grants.filter((grant) => current.has(`${grant.providerId}::${grant.model}`)).length
})

// Catalog costs are USD per 1M tokens. Trim trailing zeros so $3.00 reads
// "$3" but $0.15 stays "$0.15"; 0 (unknown) renders as a dash by the caller.
function fmtPrice(v: number): string {
  return formatNumber(v, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  })
}

async function toggle(provider: Provider, model: ModelInfo, on: boolean) {
  if (on) {
    try {
      await grants.grant(provider.id, model.id)
    } catch (err: any) {
      toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.models.updateFailed'), life: 5000 })
      await grants.fetchGrants()
    }
    return
  }

  const id = grants.grantId(provider.id, model.id)
  if (!id) return

  // Before disabling, see how the model is configured. Agents that pin it as an
  // override get reset to the workspace default — confirm that first. A
  // configured system default stays usable, so it's revoked without fuss.
  let agentCount = 0
  try {
    const u = await grants.usage(provider.id, model.id)
    agentCount = u.isSystemDefault ? 0 : u.agentCount
  } catch {
    // Usage lookup is advisory; fall through to a plain revoke on failure.
  }

  const doRevoke = async () => {
    try {
      await grants.revoke(id)
    } catch (err: any) {
      toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.models.updateFailed'), life: 5000 })
    } finally {
      await grants.fetchGrants()
    }
  }

  if (agentCount > 0) {
    confirm.require({
      header: t('administration.models.disableTitle'),
      message: t('administration.models.disableConfirm', { count: agentCount, formattedCount: formatNumber(agentCount) }),
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: t('administration.action.disable'),
      rejectLabel: t('administration.action.cancel'),
      accept: doRevoke,
      reject: () => grants.fetchGrants(), // re-sync the switch back on
    })
    return
  }
  await doRevoke()
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">{{ t('administration.models.title') }}</h1>
      <Tag :value="t('administration.models.allowedCount', { count: allowedCount, formattedCount: formatNumber(allowedCount) })" severity="success" />
    </div>
    <p style="margin: 0 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem">
      {{ t('administration.models.description') }}
    </p>

    <div style="margin-bottom: 1rem; max-width: 24rem">
      <IconField>
        <InputIcon class="pi pi-search" />
        <InputText v-model="search" :placeholder="t('administration.models.searchPlaceholder')" style="width: 100%" />
      </IconField>
    </div>

    <div v-if="providers.loading || catalog.loading" style="display: flex; flex-direction: column; gap: 0.75rem">
      <Skeleton v-for="i in 4" :key="i" height="2.5rem" />
    </div>

    <Message v-else-if="groups.length === 0" severity="info" :closable="false">
      {{ t('administration.models.emptyBeforeLink') }} <router-link to="/providers">{{ t('administration.models.emptyLink') }}</router-link>{{ t('administration.models.emptyAfterLink') }}
    </Message>

    <Card v-for="g in groups" v-else :key="g.provider.id" style="margin-bottom: 1.25rem">
      <template #title>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-server" style="color: var(--p-text-muted-color)" />
          <span>{{ g.provider.displayName || g.provider.providerId }}</span>
          <Tag :value="g.provider.slug" severity="secondary" style="font-size: 0.7rem" />
        </div>
      </template>
      <template #content>
        <DataTable :value="g.models" stripedRows size="small">
          <Column :header="t('administration.models.modelHeader')">
            <template #body="{ data }">
              <div style="display: flex; flex-direction: column">
                <span style="font-weight: 500">{{ data.name }}</span>
                <span style="font-size: 0.75rem; color: var(--p-text-muted-color)">{{ data.id }}</span>
              </div>
            </template>
          </Column>
          <Column :header="t('administration.models.capabilitiesHeader')">
            <template #body="{ data }">
              <div style="display: flex; flex-wrap: wrap; gap: 0.25rem">
                <Tag v-if="data.toolCall" :value="t('administration.capability.tools')" severity="info" style="font-size: 0.7rem" />
                <Tag v-if="data.reasoning" :value="t('administration.capability.reasoning')" severity="info" style="font-size: 0.7rem" />
                <Tag
                  v-for="c in data.caps"
                  :key="c"
                  :value="capabilityLabel(c)"
                  severity="secondary"
                  style="font-size: 0.7rem"
                />
              </div>
            </template>
          </Column>
          <Column :header="t('administration.models.priceHeader')" style="width: 8rem">
            <template #body="{ data }">
              <div
                v-if="data.costInput || data.costOutput"
                style="font-size: 0.75rem; line-height: 1.35"
              >
                <div>
                   <span style="color: var(--p-text-muted-color)">{{ t('administration.models.inputPrice') }}</span>
                  {{ fmtPrice(data.costInput) }}
                </div>
                <div>
                   <span style="color: var(--p-text-muted-color)">{{ t('administration.models.outputPrice') }}</span>
                  {{ fmtPrice(data.costOutput) }}
                </div>
              </div>
              <span v-else style="color: var(--p-text-muted-color)">-</span>
            </template>
          </Column>
          <Column :header="t('administration.models.allowedHeader')" style="width: 8rem">
            <template #body="{ data }">
              <ToggleSwitch
                :modelValue="grants.isAllowed(g.provider.id, data.id)"
                @update:modelValue="(v: boolean) => toggle(g.provider, data, v)"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>
