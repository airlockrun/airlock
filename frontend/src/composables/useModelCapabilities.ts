import { computed, type ComputedRef } from 'vue'
import { useCatalogStore } from '@/stores/catalog'

// CatalogModel mirrors the airlock ModelInfo proto fields the pickers
// need. `kind` is sol's goai-aggregated classification; `caps` are the
// per-model capability flags sol's CapabilitiesFromModel emits.
export type CatalogModel = {
  kind?: string
  caps: string[]
}
export type FlatOption = { label: string; value: string }
export type GroupedOption = { label: string; items: FlatOption[] }

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

  function groupModels(accept: (m: CatalogModel) => boolean): GroupedOption[] {
    const groups: Record<string, FlatOption[]> = {}
    for (const m of catalog.models) {
      if (!accept(m)) continue
      if (!groups[m.providerId]) groups[m.providerId] = []
      groups[m.providerId].push({
        label: m.name || m.id,
        value: `${m.providerId}/${m.id}`,
      })
    }
    for (const items of Object.values(groups)) {
      items.sort((a, b) => a.label.localeCompare(b.label))
    }
    return Object.keys(groups).sort().map(provider => ({
      label: provider,
      items: groups[provider],
    }))
  }

  // Search is provider-scoped — the stored value is a provider ID, not a
  // model. Only configured providers that declare the capability appear.
  const searchProviderOptions: ComputedRef<FlatOption[]> = computed(() =>
    catalog.capabilities
      .filter(p => p.configured && p.capabilities.includes('search'))
      .map(p => ({ label: p.displayName || p.providerId, value: p.providerId }))
      .sort((a, b) => a.label.localeCompare(b.label))
  )

  return { groupModels, searchProviderOptions }
}
