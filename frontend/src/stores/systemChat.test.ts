import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, post, loadFirst, wsHandlers, onMessage } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  loadFirst: vi.fn(),
  wsHandlers: new Map<string, Array<(payload: unknown, env: any) => void>>(),
  onMessage: vi.fn((type: string, handler: (payload: unknown, env: any) => void) => {
    const handlers = wsHandlers.get(type) ?? []
    handlers.push(handler)
    wsHandlers.set(type, handlers)
    return vi.fn()
  }),
}))

vi.mock('@/api/client', () => ({ default: { get, post, delete: vi.fn() } }))
vi.mock('@/api/ws', () => ({ ws: { onMessage } }))
vi.mock('@/stores/auth', () => ({ useAuthStore: () => ({ user: { id: 'user-1' } }) }))
vi.mock('@/stores/conversationFeed', () => ({
  useConversationFeedStore: () => ({ loadFirst }),
}))

import { useSystemChatStore } from './systemChat'

describe('system chat store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    wsHandlers.clear()
  })

  function emit(type: string, payload: unknown) {
    for (const handler of wsHandlers.get(type) ?? []) {
      handler(payload, { topicId: 'user-1', conversationId: 'conv-1' })
    }
  }

  async function loadedChat() {
    get.mockResolvedValueOnce({
      data: {
        conversation: { id: 'conv-1', userId: 'user-1', status: 'active' },
        messages: [],
      },
    })
    const chat = useSystemChatStore()
    await chat.loadConversation('conv-1')
    chat.initListeners()
    return chat
  }

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

  it('restores the authoritative pending confirmation when approval rolls back', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-a', toolName: 'write', input: '{}' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', code: '{}',
    })
    post.mockRejectedValueOnce(new Error('approval failed'))
    get.mockResolvedValueOnce({
      data: {
        conversation: {
          id: 'conv-1', userId: 'user-1', status: 'awaiting_confirmation',
          pendingTool: { runId: 'run-a', callId: 'call-a', toolName: 'write', argsJson: '{}' },
        },
        messages: [],
      },
    })

    await expect(chat.sendPrompt('', true)).rejects.toThrow('approval failed')

    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-a', toolCallId: 'call-a' })
    expect(chat.currentRunId).toBe('run-a')
    expect(chat.sending).toBe(false)
  })

  it('does not restore a consumed confirmation after approval fails', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', code: '{}',
    })
    let rejectPost!: (reason: Error) => void
    post.mockReturnValueOnce(new Promise((_, reject) => { rejectPost = reject }))
    get.mockResolvedValueOnce({
      data: {
        conversation: { id: 'conv-1', userId: 'user-1', status: 'active' },
        messages: [],
      },
    })

    const approval = chat.sendPrompt('', true)
    emit('run.started', { runId: 'run-b' })
    rejectPost(new Error('response lost'))
    await expect(approval).rejects.toThrow('response lost')

    expect(chat.pendingConfirmation).toBeNull()
    expect(chat.currentRunId).toBe('run-b')
    expect(chat.sending).toBe(true)
  })

  it('falls back to the captured confirmation when reconciliation fails', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', code: '{}',
    })
    post.mockRejectedValueOnce(new Error('approval failed'))
    get.mockRejectedValueOnce(new Error('reconciliation failed'))

    await expect(chat.sendPrompt('', true)).rejects.toThrow('approval failed')

    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-a', toolCallId: 'call-a' })
    expect(chat.currentRunId).toBe('run-a')
  })

  it('restores resume run ID from a refreshed conversation', async () => {
    get.mockResolvedValueOnce({
      data: {
        conversation: {
          id: 'conv-1', userId: 'user-1', status: 'awaiting_confirmation',
          pendingTool: { runId: 'run-a', callId: 'call-a', toolName: 'write', argsJson: '{"n":1}' },
        },
        messages: [],
      },
    })
    const chat = useSystemChatStore()

    await chat.loadConversation('conv-1')

    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-a', toolCallId: 'call-a' })
    expect(chat.currentRunId).toBe('run-a')
  })

  it('keeps a finalized batch visible through result A and confirmation B', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-a', toolName: 'write_a', input: '{"n":1}' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-b', toolName: 'write_b', input: '{"n":2}' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write_a', code: '{"n":1}',
    })
    let resolvePost!: (value: { data: { runId: string; conversationId: string } }) => void
    post.mockReturnValueOnce(new Promise((resolve) => { resolvePost = resolve }))

    const approval = chat.sendPrompt('', true)
    emit('run.started', { runId: 'run-b' })
    emit('run.tool_result', {
      runId: 'run-b', toolCallId: 'call-a', toolName: 'write_a', output: 'A complete', outcome: 'success',
    })
    emit('run.confirmation_required', {
      runId: 'run-b', toolCallId: 'call-b', permission: 'write_b', code: '{"n":2}',
    })
    resolvePost({ data: { runId: 'run-b', conversationId: 'conv-1' } })
    await approval

    expect(chat.messages[0].blocks).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'tool', toolCallId: 'call-a', output: 'A complete', outcome: 'success' }),
      expect.objectContaining({ kind: 'tool', toolCallId: 'call-b' }),
    ]))
    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-b', toolCallId: 'call-b' })

    post.mockResolvedValueOnce({ data: { runId: 'run-c', conversationId: 'conv-1' } })
    await chat.sendPrompt('', true)
    expect(post).toHaveBeenLastCalledWith('/api/v1/system/conversations/conv-1/prompt', {
      message: '', approved: true, resumeRunId: 'run-b',
    })
  })
})
