import { describe, expect, it } from 'vitest'
import { modelMatchesProvider, providerModelGroupLabel } from './useModelCapabilities'

const first = {
  id: 'provider-row-1',
  providerId: 'openai-compatible',
  slug: 'ollama',
  displayName: 'Ollama workstation',
  isEnabled: true,
}
const second = { ...first, id: 'provider-row-2', slug: 'vllm', displayName: 'vLLM server' }

describe('configured provider model routing', () => {
  it('binds endpoint-specific models only to their configured provider row', () => {
    const model = { providerId: 'openai-compatible', providerConfigId: first.id }
    expect(modelMatchesProvider(model, first)).toBe(true)
    expect(modelMatchesProvider(model, second)).toBe(false)
  })

  it('fans static catalog models out by provider type', () => {
    const model = { providerId: 'openai-compatible', providerConfigId: '' }
    expect(modelMatchesProvider(model, first)).toBe(true)
    expect(modelMatchesProvider(model, second)).toBe(true)
  })

  it('uses the display name while retaining provider ID and slug context', () => {
    expect(providerModelGroupLabel(first)).toBe('Ollama workstation (openai-compatible/ollama)')
  })
})
