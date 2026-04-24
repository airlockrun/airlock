import { computed, type ComputedRef } from 'vue'
import { useCatalogStore } from '@/stores/catalog'

export type ModalityModel = { inputModalities: string[]; outputModalities: string[] }
export type FlatOption = { label: string; value: string }
export type GroupedOption = { label: string; items: FlatOption[] }

// Modality predicates mirror sol/provider/capabilities.go
// (CapabilitiesFromModel). A models.dev entry without modality info is
// treated as text-only so legitimate text models aren't hidden from pickers.
export function supportsText(m: ModalityModel): boolean {
  const inOk = m.inputModalities.length === 0 || m.inputModalities.includes('text')
  const outOk = m.outputModalities.length === 0 || m.outputModalities.includes('text')
  return inOk && outOk
}
export function supportsVision(m: ModalityModel): boolean {
  return m.inputModalities.includes('image') && m.outputModalities.includes('text')
}
export function supportsSTT(m: ModalityModel): boolean {
  return m.inputModalities.includes('audio') && m.outputModalities.includes('text')
}
export function supportsTTS(m: ModalityModel): boolean {
  return m.inputModalities.includes('text') && m.outputModalities.includes('audio')
}
export function supportsImageGen(m: ModalityModel): boolean {
  return m.inputModalities.includes('text') && m.outputModalities.includes('image')
}

export function useModelCapabilities() {
  const catalog = useCatalogStore()

  function groupModels(accept: (m: ModalityModel) => boolean): GroupedOption[] {
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
