import { computed, type ComputedRef } from 'vue'
import { useCatalogStore } from '@/stores/catalog'
import { useProvidersStore } from '@/stores/providers'
import { useModelsAllowedStore } from '@/stores/modelsAllowed'

// CatalogModel mirrors the airlock ModelInfo proto fields the pickers
// need. `kind` is sol's goai-aggregated classification; `caps` are the
// per-model capability flags sol's CapabilitiesFromModel emits.
export type CatalogModel = {
  kind?: string
  caps: string[]
  toolCall?: boolean
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
        if (opts.restrictToAllowed && !allowed.isAllowed(row.id, m.id)) continue
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
      if (!searchCapable.has(row.providerId)) continue
      const items: FlatOption[] = [{ label: 'Provider default', value: packModelValue(row.id, '') }]
      for (const m of catalog.models) {
        // A search model must be tool-capable and text-in/text-out — the
        // backend runs web search by calling it with a search tool.
        if (m.providerId !== row.providerId || !isToolTextModel(m)) continue
        if (opts.restrictToAllowed && !allowed.isAllowed(row.id, m.id)) continue
        items.push({ label: m.name || m.id, value: packModelValue(row.id, m.id) })
      }
      groups.push({ label: `${row.providerId}/${row.slug}`, items })
    }
    return groups.sort((a, b) => a.label.localeCompare(b.label))
  })

  return { groupModels, searchModelOptions }
}
