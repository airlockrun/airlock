import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { User } from '@/gen/airlock/v1/types_pb'

const { post, clearAccessToken, disconnect } = vi.hoisted(() => ({
  post: vi.fn(),
  clearAccessToken: vi.fn(),
  disconnect: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  default: { post: post, get: vi.fn() },
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
