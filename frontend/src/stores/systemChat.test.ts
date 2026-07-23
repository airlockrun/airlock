import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get } = vi.hoisted(() => ({ get: vi.fn() }))

vi.mock('@/api/client', () => ({ default: { get, post: vi.fn(), delete: vi.fn() } }))
vi.mock('@/api/ws', () => ({ ws: { onMessage: vi.fn() } }))

import { useSystemChatStore } from './systemChat'

describe('system chat store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('omits llm and compaction rows from an enriched transcript', async () => {
    get.mockResolvedValueOnce({
      data: {
        conversation: { id: 'conv-1', userId: 'user-1', status: 'active' },
        messages: [
          { id: 'visible', role: 'assistant', source: 'user', content: 'visible' },
          { id: 'llm', role: 'assistant', source: 'llm', content: 'model context' },
          { id: 'compaction', role: 'assistant', source: 'compaction', content: 'compact context' },
        ],
      },
    })

    const chat = useSystemChatStore()
    await chat.loadConversation('conv-1')

    expect(chat.messages.map((message) => message.id)).toEqual(['visible'])
  })
})
