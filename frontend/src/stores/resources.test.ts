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

  it('serializes resource grant capabilities and identifiers', async () => {
    post.mockResolvedValueOnce({})
    const store = useResourcesStore()

    await store.grant('mcp_server', 'resource-1', 'group-1', ['view', 'bind'])

    expect(post).toHaveBeenCalledWith('/api/v1/resources/mcp_server/resource-1/grants', {
      resourceType: 'mcp_server',
      resourceId: 'resource-1',
      granteeId: 'group-1',
      capabilities: ['view', 'bind'],
    })
  })

  it('uses the returned grant id when revoking access', async () => {
    remove.mockResolvedValueOnce({})
    const store = useResourcesStore()

    await store.revokeGrant('connection', 'resource-1', 'grant-9')

    expect(remove).toHaveBeenCalledWith('/api/v1/resources/connection/resource-1/grants/grant-9')
  })
})
