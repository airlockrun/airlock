import { computed, type ComputedRef } from 'vue'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'

// CatalogModel mirrors the airlock ModelInfo proto fields the pickers
// need. `kind` is sol's goai-aggregated classification; `caps` are the
// per-model capability flags sol's CapabilitiesFromModel emits.
export type CatalogModel = {
  kind?: string
  caps: string[]
}
export type FlatOption = { label: string; value: string }
export type GroupedOption = { label: string; items: FlatOption[] }

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

// Kind predicates — primary axis for picker filtering. Empty kind means
// sol has no goai typed-list coverage for the provider (the openai-compat
// bucket: groq, xai, cerebras, fireworks, etc.). Those providers ship
// language models exclusively today, so isLanguage treats empty as
// language; the other predicates require an exact match.
export function isLanguage(m: CatalogModel): boolean {
  return !m.kind || m.kind === 'language'
}
export function isEmbedding(m: CatalogModel): boolean {
  return m.kind === 'embedding'
}
export function isImageGen(m: CatalogModel): boolean {
  return m.kind === 'image'
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

export function useModelCapabilities() {
  const catalog = useCatalogStore()
  const providers = useProvidersStore()

  // groupModels fans out catalog models across every configured provider
  // row that shares the model's catalog provider_id. Multiple keys per
  // provider produce multiple groups: a model that exists once in the
  // catalog under "openai" appears under both "openai/personal" and
  // "openai/team-acme" if both rows are configured. The option `value`
  // packs (row UUID, bare model name) so the submit path can route to
  // the correct providers row.
  function groupModels(accept: (m: CatalogModel) => boolean): GroupedOption[] {
    const groups: Record<string, FlatOption[]> = {}
    for (const m of catalog.models) {
      if (!accept(m)) continue
      const rows = providers.providers.filter(p => p.providerId === m.providerId)
      for (const row of rows) {
        const key = `${row.providerId}/${row.slug}`
        if (!groups[key]) groups[key] = []
        groups[key].push({
          label: m.name || m.id,
          value: packModelValue(row.id, m.id),
        })
      }
    }
    for (const items of Object.values(groups)) {
      items.sort((a, b) => a.label.localeCompare(b.label))
    }
    return Object.keys(groups).sort().map(label => ({
      label,
      items: groups[label],
    }))
  }

  // Search is provider-scoped — the stored value is a row UUID, not a
  // model. Only configured rows of providers that declare the capability
  // appear, with the picker label disambiguating slug-by-slug.
  const searchProviderOptions: ComputedRef<FlatOption[]> = computed(() => {
    const searchCapable = new Set<string>()
    for (const p of catalog.capabilities) {
      if (p.capabilities.includes('search')) searchCapable.add(p.providerId)
    }
    return providers.providers
      .filter(row => searchCapable.has(row.providerId))
      .map(row => ({
        label: `${row.providerId}/${row.slug}`,
        value: packModelValue(row.id, ''),
      }))
      .sort((a, b) => a.label.localeCompare(b.label))
  })

  return { groupModels, searchProviderOptions }
}
