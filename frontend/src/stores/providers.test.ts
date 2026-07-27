import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { patch } = vi.hoisted(() => ({ patch: vi.fn() }))

vi.mock('@/api/client', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch, delete: vi.fn() },
}))

import { useProvidersStore } from './providers'

describe('providers store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('serializes an explicitly disabled provider as optional false', async () => {
    patch.mockResolvedValueOnce({
      data: {
        provider: {
          id: 'provider-a',
          providerId: 'openai',
          slug: 'primary',
          displayName: 'Primary',
          isEnabled: false,
        },
      },
    })
    const store = useProvidersStore()

    await store.updateProvider('provider-a', { isEnabled: false })

    expect(patch).toHaveBeenCalledWith('/api/v1/providers/provider-a', { isEnabled: false })
  })
})
