import { computed, type ComputedRef } from 'vue'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'
import { useModelsAllowedStore } from '@/stores/modelsAllowed'
import { useAirlockI18n } from '@/i18n'

// CatalogModel mirrors the airlock ModelInfo proto fields the pickers
// need. `kind` is sol's derived classification (models.dev + OpenRouter);
// `caps` are the per-model capability flags sol's CapabilitiesFromModel emits.
export type CatalogModel = {
  kind?: string
  caps: string[]
  toolCall?: boolean
}
export type FlatOption = { label: string; value: string }
export type GroupedOption = { label: string; items: FlatOption[] }

export type ProviderModelRoute = { providerId: string; providerConfigId?: string }
export type ConfiguredProviderRoute = {
  id: string
  providerId: string
  slug: string
  displayName: string
  isEnabled: boolean
}

export function modelMatchesProvider(model: ProviderModelRoute, provider: ConfiguredProviderRoute): boolean {
  if (model.providerConfigId) return model.providerConfigId === provider.id
  return model.providerId === provider.providerId
}

export function providerModelGroupLabel(provider: ConfiguredProviderRoute): string {
  const identity = `${provider.providerId}/${provider.slug}`
  return provider.displayName ? `${provider.displayName} (${identity})` : identity
}

// Multi-key encoding: each picker option's `value` packs the providers row
// UUID and the bare model name into one string ("rowUUID|modelName"). Pipe
// is safe because UUIDs are hex-only and model IDs from models.dev never
// contain `|`. The form encodes here; submission decodes via splitModelValue.
const SEP = '|'
export function packModelValue(providerRowID: string, modelName: string): string {
  return providerRowID + SEP + modelName
}
export function splitModelValue(v: string): { providerRowID: string; modelName: string } {
  if (!v) return { providerRowID: '', modelName: '' }
  const idx = v.indexOf(SEP)
  if (idx < 0) return { providerRowID: '', modelName: v }
  return { providerRowID: v.slice(0, idx), modelName: v.slice(idx + 1) }
}

// Kind predicates are the primary axis for picker filtering. The catalog
// publishes an explicit kind for every model.
export function isLanguage(m: CatalogModel): boolean {
  return m.kind === 'language'
}
export function isEmbedding(m: CatalogModel): boolean {
  return m.kind === 'embedding'
}
// isImageGen selects models for the image-generation slot by CAPABILITY, not
// kind: any model that outputs images qualifies — a dedicated generator
// (kind=image) or a chat model with image output (kind=language, output
// includes "image"). Both carry the image_gen capability from sol's
// CapabilitiesFromModel. Mirrors the backend gate (ModelMeetsCapability "image").
export function isImageGen(m: CatalogModel): boolean {
  return hasCap(m, 'image_gen')
}
export function isSpeech(m: CatalogModel): boolean {
  return m.kind === 'speech'
}
export function isTranscription(m: CatalogModel): boolean {
  return m.kind === 'transcription'
}

// hasCap checks for a per-model capability flag. Used to compose
// sub-filters within a kind — e.g. the vision picker is
// `isLanguage(m) && hasCap(m, 'vision')`.
export function hasCap(m: CatalogModel, cap: string): boolean {
  return m.caps.includes(cap)
}

// isToolTextModel gates the web-search picker: the backend drives web search
// by calling the model with a search tool, so the model must support tool
// calls and text in + text out. (sol's "text" cap already means text-in AND
// text-out.)
export function isToolTextModel(m: CatalogModel): boolean {
  return !!m.toolCall && hasCap(m, 'text')
}

// Options for useModelCapabilities. restrictToAllowed filters picker options to
// the models the caller may assign (per the modelsAllowed store): used by the
// agent capability-override pickers. The system-default pickers (activation,
// settings) leave it off — that's where the defaults themselves are chosen.
export type ModelCapabilitiesOptions = { restrictToAllowed?: boolean }

export function useModelCapabilities(opts: ModelCapabilitiesOptions = {}) {
  const catalog = useCatalogStore()
  const providers = useProvidersStore()
  const allowed = useModelsAllowedStore()
  const { t, locale } = useAirlockI18n()

  // Static catalog models fan out to enabled rows sharing their provider_id.
  // Endpoint-specific models carry providerConfigId and bind only to that row.
  // The option value packs (row UUID, bare model name) so submission routes to
  // the selected configured provider instance.
  function groupModels(accept: (m: CatalogModel) => boolean): GroupedOption[] {
    const groups: Record<string, FlatOption[]> = {}
    for (const m of catalog.models) {
      if (!accept(m)) continue
      const rows = providers.providers.filter(p => p.isEnabled && modelMatchesProvider(m, p))
      for (const row of rows) {
        if (opts.restrictToAllowed && !allowed.isAllowed(row.id, m.id)) continue
        const key = providerModelGroupLabel(row)
        if (!groups[key]) groups[key] = []
        groups[key].push({
          label: m.name || m.id,
          value: packModelValue(row.id, m.id),
        })
      }
    }
    for (const items of Object.values(groups)) {
      items.sort((a, b) => a.label.localeCompare(b.label, locale.value))
    }
    return Object.keys(groups).sort((a, b) => a.localeCompare(b, locale.value)).map(label => ({
      label,
      items: groups[label],
    }))
  }

  // Search is provider-scoped, but the backend can also run a specific model
  // (threaded into the websearch client). Per configured search-capable
  // provider row we offer a "Provider default" entry (packs an empty model →
  // the backend's default search model) plus that provider's language models
  // (allowed-filtered when restrictToAllowed). The packed value is
  // (row UUID, model id | '').
  const searchModelOptions: ComputedRef<GroupedOption[]> = computed(() => {
    const searchCapable = new Set<string>()
    for (const p of catalog.capabilities) {
      if (p.capabilities.includes('search')) searchCapable.add(p.providerId)
    }
    const groups: GroupedOption[] = []
    for (const row of providers.providers) {
      if (!row.isEnabled) continue
      if (!searchCapable.has(row.providerId)) continue
      const items: FlatOption[] = [{
        label: t('administration.providers.providerDefault'),
        value: packModelValue(row.id, ''),
      }]
      for (const m of catalog.models) {
        // A search model must be tool-capable and text-in/text-out — the
        // backend runs web search by calling it with a search tool.
        if (!modelMatchesProvider(m, row) || !isToolTextModel(m)) continue
        if (opts.restrictToAllowed && !allowed.isAllowed(row.id, m.id)) continue
        items.push({ label: m.name || m.id, value: packModelValue(row.id, m.id) })
      }
      groups.push({ label: providerModelGroupLabel(row), items })
    }
    return groups.sort((a, b) => a.label.localeCompare(b.label, locale.value))
  })

  return { groupModels, searchModelOptions }
}
