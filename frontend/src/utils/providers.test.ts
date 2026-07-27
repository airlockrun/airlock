import { describe, expect, it } from 'vitest'
import {
  isCurrentProviderRequest,
  isValidProviderSlug,
  isValidProviderURL,
  nextProviderRequestSession,
  setRowPending,
  toProviderSlug,
  uniqueProviderSlug,
} from './providers'

describe('provider form helpers', () => {
  it('creates strict kebab-case slugs', () => {
    expect(toProviderSlug(' Team OpenAI / West ')).toBe('team-openai-west')
    expect(isValidProviderSlug('team-openai-west')).toBe(true)
    expect(isValidProviderSlug('Team OpenAI')).toBe(false)
  })

  it('proposes a unique slug only within the selected provider type', () => {
    const rows = [
      { providerId: 'openai', slug: 'openai' },
      { providerId: 'openai', slug: 'openai-2' },
      { providerId: 'anthropic', slug: 'openai-3' },
    ]
    expect(uniqueProviderSlug('openai', 'openai', rows)).toBe('openai-3')
    expect(uniqueProviderSlug('anthropic', 'openai', rows)).toBe('openai')
  })

  it('validates absolute provider URLs without credentials, query, or fragment', () => {
    expect(isValidProviderURL('http://host.docker.internal:11434/v1', true)).toBe(true)
    expect(isValidProviderURL('', false)).toBe(true)
    expect(isValidProviderURL('', true)).toBe(false)
    expect(isValidProviderURL('localhost:11434/v1', true)).toBe(false)
    expect(isValidProviderURL('https://user:pass@example.com/v1', true)).toBe(false)
    expect(isValidProviderURL('https://example.com/v1?token=x', true)).toBe(false)
  })

  it('invalidates requests across provider switches and same-provider reopenings', () => {
    let current = { generation: 0, providerId: '' }
    current = nextProviderRequestSession(current, 'provider-a')
    const firstOpen = current

    current = nextProviderRequestSession(current, '')
    current = nextProviderRequestSession(current, 'provider-a')
    expect(isCurrentProviderRequest(current, firstOpen)).toBe(false)

    const secondOpen = current
    current = nextProviderRequestSession(current, 'provider-b')
    expect(isCurrentProviderRequest(current, secondOpen)).toBe(false)
  })

  it('tracks row pending state independently without mutating prior sets', () => {
    const none = new Set<string>()
    const first = setRowPending(none, 'provider-a', true)
    const both = setRowPending(first, 'provider-b', true)
    const second = setRowPending(both, 'provider-a', false)

    expect(none).toEqual(new Set())
    expect(first).toEqual(new Set(['provider-a']))
    expect(both).toEqual(new Set(['provider-a', 'provider-b']))
    expect(second).toEqual(new Set(['provider-b']))
  })
})
