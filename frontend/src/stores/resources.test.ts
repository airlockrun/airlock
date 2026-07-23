import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, post, patch, remove } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  patch: vi.fn(),
  remove: vi.fn(),
}))

vi.mock('@/api/client', () => ({ default: { get, post, patch, delete: remove } }))

import { useResourcesStore } from './resources'

describe('resources store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('parses the generated inventory response', async () => {
    get.mockResolvedValueOnce({ data: { resources: [{ id: 'r1', type: 'connection', displayName: 'GitHub', capabilities: ['view'] }] } })
    const store = useResourcesStore()

    await store.fetchResources()

    expect(store.resources[0]).toMatchObject({ id: 'r1', displayName: 'GitHub', capabilities: ['view'] })
    expect(store.error).toBe('')
  })

  it('exposes inventory failures without presenting an empty success state', async () => {
    get.mockRejectedValueOnce(new Error('network down'))
    const store = useResourcesStore()

    await expect(store.fetchResources()).rejects.toThrow('network down')

    expect(store.error).toBe('network down')
  })

})
