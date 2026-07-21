import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get } = vi.hoisted(() => ({ get: vi.fn() }))

vi.mock('@/api/client', () => ({
  default: { get, post: vi.fn(), delete: vi.fn() },
}))

import { useGitCredentialsStore } from './gitCredentials'

describe('git credentials store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('loads credentials without exposing an empty pending state', async () => {
    let resolveRequest!: (value: { data: unknown }) => void
    get.mockReturnValueOnce(new Promise((resolve) => { resolveRequest = resolve }))
    const store = useGitCredentialsStore()

    const request = store.fetchCredentials()
    expect(store.loading).toBe(true)

    resolveRequest({ data: { credentials: [{ id: 'credential-1', name: 'GitHub', type: 'pat' }] } })
    await request

    expect(store.loading).toBe(false)
    expect(store.error).toBe('')
    expect(store.credentials[0]).toMatchObject({ id: 'credential-1', name: 'GitHub' })
  })

  it('exposes load failures for retry', async () => {
    get.mockRejectedValueOnce(new Error('network down'))
    const store = useGitCredentialsStore()

    await expect(store.fetchCredentials()).rejects.toThrow('network down')

    expect(store.loading).toBe(false)
    expect(store.error).toBe('network down')
  })
})
