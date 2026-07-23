import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { User } from '@/gen/airlock/v1/types_pb'

const { patch, post, clearAccessToken, disconnect } = vi.hoisted(() => ({
  patch: vi.fn(),
  post: vi.fn(),
  clearAccessToken: vi.fn(),
  disconnect: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  default: { patch, post, get: vi.fn() },
  clearAccessToken,
  isAuthRejection: vi.fn(),
  refreshAccessToken: vi.fn(),
  setAccessToken: vi.fn(),
}))
vi.mock('@/api/passkeys', () => ({
  passkeyLogin: vi.fn(),
  registerPasskey: vi.fn(),
}))
vi.mock('@/api/ws', () => ({
  ws: { connect: vi.fn(), disconnect },
}))

import { useAuthStore } from './auth'

describe('auth logout', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('preserves local auth state when backend revocation fails', async () => {
    const auth = useAuthStore()
    auth.user = { displayName: 'Test User' } as User
    auth.tenantPermissions = new Set(['tenant.agent.create'])
    const failure = new Error('backend unavailable')
    post.mockRejectedValueOnce(failure)

    await expect(auth.logout()).rejects.toBe(failure)

    expect(auth.user?.displayName).toBe('Test User')
    expect(auth.tenantPermissions).toEqual(new Set(['tenant.agent.create']))
    expect(clearAccessToken).not.toHaveBeenCalled()
    expect(disconnect).not.toHaveBeenCalled()
  })

  it('clears local auth state only after backend revocation succeeds', async () => {
    const auth = useAuthStore()
    auth.user = { displayName: 'Test User' } as User
    auth.tenantPermissions = new Set(['tenant.agent.create'])
    let resolveRevocation!: () => void
    post.mockReturnValueOnce(new Promise<void>((resolve) => {
      resolveRevocation = resolve
    }))

    const logout = auth.logout()

    expect(auth.user).not.toBeNull()
    expect(clearAccessToken).not.toHaveBeenCalled()
    expect(disconnect).not.toHaveBeenCalled()

    resolveRevocation()
    await logout

    expect(post).toHaveBeenCalledWith('/auth/logout', {})
    expect(auth.user).toBeNull()
    expect(auth.tenantPermissions).toEqual(new Set())
    expect(clearAccessToken).toHaveBeenCalledOnce()
    expect(disconnect).toHaveBeenCalledOnce()
  })
})

describe('auth profile', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('updates the local display name after the backend succeeds', async () => {
    const auth = useAuthStore()
    auth.user = { displayName: 'Old Name' } as User
    patch.mockResolvedValueOnce({})

    await auth.updateDisplayName('  New Name  ')

    expect(patch).toHaveBeenCalledWith('/api/v1/me', { displayName: 'New Name' })
    expect(auth.user.displayName).toBe('New Name')
  })

  it('preserves the local display name when the backend rejects the update', async () => {
    const auth = useAuthStore()
    auth.user = { displayName: 'Old Name' } as User
    const failure = new Error('backend unavailable')
    patch.mockRejectedValueOnce(failure)

    await expect(auth.updateDisplayName('New Name')).rejects.toBe(failure)

    expect(auth.user.displayName).toBe('Old Name')
  })
})
