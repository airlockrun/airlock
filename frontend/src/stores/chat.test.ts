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
vi.mock('@/stores/conversationFeed', () => ({
  useConversationFeedStore: () => ({ loadFirst }),
}))

import { useChatStore } from './chat'

describe('chat store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    wsHandlers.clear()
  })

  function emit(type: string, payload: unknown) {
    for (const handler of wsHandlers.get(type) ?? []) {
      handler(payload, { topicId: 'agent-1', conversationId: 'conv-1' })
    }
  }

  async function loadedChat() {
    get
      .mockResolvedValueOnce({
        data: { conversations: [{ id: 'conv-1', agentId: 'agent-1', source: 'web' }] },
      })
      .mockResolvedValueOnce({
        data: {
          conversation: { id: 'conv-1', agentId: 'agent-1', source: 'web' },
          messages: [],
        },
      })
    const chat = useChatStore()
    await chat.loadConversation('agent-1', 'conv-1')
    chat.initListeners()
    return chat
  }

  it('keeps a persisted tool turn visible when restoring its confirmation', async () => {
    const toolCallId = 'call-confirm'
    get
      .mockResolvedValueOnce({
        data: { conversations: [{ id: 'conv-1', agentId: 'agent-1', source: 'web' }] },
      })
      .mockResolvedValueOnce({
        data: {
          conversation: { id: 'conv-1', agentId: 'agent-1', source: 'web' },
          messages: [{
            id: 'message-1',
            seq: '1',
            role: 'assistant',
            source: 'user',
            content: 'I need approval before continuing.',
            runId: 'run-1',
            parts: JSON.stringify([
              { type: 'text', text: 'I need approval before continuing.' },
              {
                type: 'tool-call',
                toolCallId,
                toolName: 'run_js',
                args: { code: 'tools.skip_track({})', request_confirmation: true },
              },
            ]),
          }],
          pendingConfirmation: {
            runId: 'run-1',
            toolCallId,
            toolName: 'run_js',
            input: JSON.stringify({ code: 'tools.skip_track({})', request_confirmation: true }),
            description: 'Skip the current track',
          },
        },
      })

    const chat = useChatStore()
    await chat.loadConversation('agent-1', 'conv-1')

    expect(chat.pendingConfirmation?.toolCallId).toBe(toolCallId)
    expect((chat.messages[0] as any)._hidden).not.toBe(true)
    expect((chat.messages[0] as any).blocks).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'text', text: 'I need approval before continuing.' }),
      expect.objectContaining({ kind: 'tool', toolCallId }),
    ]))
  })

  it('restores the authoritative pending confirmation when approval rolls back', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-a', toolName: 'write', input: '{}' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', patterns: ['*'], code: '{}',
    })
    post.mockRejectedValueOnce(new Error('approval failed'))
    get.mockResolvedValueOnce({
      data: {
        conversation: { id: 'conv-1', agentId: 'agent-1', source: 'web' },
        messages: [],
        pendingConfirmation: {
          runId: 'run-a', toolCallId: 'call-a', toolName: 'write', input: '{}',
          permission: 'write', patterns: ['*'], code: '{}',
        },
      },
    })

    await expect(chat.sendMessage('agent-1', '', true)).rejects.toThrow('approval failed')

    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-a', toolCallId: 'call-a' })
    expect(chat.currentRunId).toBe('run-a')
    expect(chat.sending).toBe(false)
  })

  it('does not restore a consumed confirmation after approval fails', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', patterns: ['*'], code: '{}',
    })
    let rejectPost!: (reason: Error) => void
    post.mockReturnValueOnce(new Promise((_, reject) => { rejectPost = reject }))
    get.mockResolvedValueOnce({
      data: {
        conversation: { id: 'conv-1', agentId: 'agent-1', source: 'web' },
        messages: [],
      },
    })

    const approval = chat.sendMessage('agent-1', '', true)
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
      runId: 'run-a', toolCallId: 'call-a', permission: 'write', patterns: ['*'], code: '{}',
    })
    post.mockRejectedValueOnce(new Error('approval failed'))
    get.mockRejectedValueOnce(new Error('reconciliation failed'))

    await expect(chat.sendMessage('agent-1', '', true)).rejects.toThrow('approval failed')

    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-a', toolCallId: 'call-a' })
    expect(chat.currentRunId).toBe('run-a')
  })

  it('keeps a finalized batch visible through result A and confirmation B', async () => {
    const chat = await loadedChat()
    emit('run.started', { runId: 'run-a', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-a', toolName: 'write_a', input: '{"n":1}' })
    emit('run.tool_call', { runId: 'run-a', toolCallId: 'call-b', toolName: 'write_b', input: '{"n":2}' })
    emit('run.confirmation_required', {
      runId: 'run-a', toolCallId: 'call-a', permission: 'write_a', patterns: ['*'], code: '{"n":1}',
    })
    let resolvePost!: (value: { data: { runId: string; conversationId: string } }) => void
    post.mockReturnValueOnce(new Promise((resolve) => { resolvePost = resolve }))

    const approval = chat.sendMessage('agent-1', '', true)
    emit('run.started', { runId: 'run-b' })
    emit('run.tool_result', {
      runId: 'run-b', toolCallId: 'call-a', toolName: 'write_a', output: 'A complete', outcome: 'success',
    })
    emit('run.confirmation_required', {
      runId: 'run-b', toolCallId: 'call-b', permission: 'write_b', patterns: ['*'], code: '{"n":2}',
    })
    resolvePost({ data: { runId: 'run-b', conversationId: 'conv-1' } })
    await approval

    const blocks = (chat.messages[0] as any).blocks
    expect(blocks).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'tool', toolCallId: 'call-a', output: 'A complete', outcome: 'success' }),
      expect.objectContaining({ kind: 'tool', toolCallId: 'call-b' }),
    ]))
    expect(chat.pendingConfirmation).toMatchObject({ runId: 'run-b', toolCallId: 'call-b' })

    post.mockResolvedValueOnce({ data: { runId: 'run-c', conversationId: 'conv-1' } })
    await chat.sendMessage('agent-1', '', true)
    expect(post).toHaveBeenLastCalledWith('/api/v1/agents/agent-1/prompt', {
      message: '', conversationId: 'conv-1', approved: true, resumeRunId: 'run-b',
    })
  })

  it('adopts a conversation created by a synchronous slash command', async () => {
    post.mockResolvedValueOnce({
      data: { conversationId: 'conv-1', commandReply: 'Context cleared.' },
    })
    get
      .mockResolvedValueOnce({ data: { conversations: [{ id: 'conv-1', agentId: 'agent-1', source: 'web' }] } })
      .mockResolvedValueOnce({ data: { conversations: [{ id: 'conv-1', agentId: 'agent-1', source: 'web' }] } })
      .mockResolvedValueOnce({
        data: {
          conversation: { id: 'conv-1', agentId: 'agent-1', source: 'web' },
          messages: [],
        },
      })

    const chat = useChatStore()
    await chat.sendMessage('agent-1', '/clear')

    expect(chat.conversationId).toBe('conv-1')
    expect(loadFirst).toHaveBeenCalledOnce()
    expect(get).toHaveBeenLastCalledWith('/api/v1/conversations/conv-1')
  })

  it('ignores a delayed completion from a prior run during compact', async () => {
    const chat = await loadedChat()
    post.mockResolvedValueOnce({ data: { runId: 'compact-run', conversationId: 'conv-1' } })

    await chat.sendMessage('agent-1', '/compact')
    emit('run.complete', { runId: 'prior-run' })

    expect(chat.sending).toBe(true)
    expect(chat.messages).toHaveLength(0)

    emit('run.complete', { runId: 'compact-run' })
    expect(chat.messages).toHaveLength(1)
    expect(chat.messages[0].source).toBe('checkpoint')
  })

  it('suppresses only the matching compact run and creates its divider', async () => {
    const chat = await loadedChat()
    post.mockResolvedValueOnce({ data: { runId: 'compact-run', conversationId: 'conv-1' } })

    await chat.sendMessage('agent-1', '/compact')
    emit('run.text_delta', { runId: 'compact-run', text: 'Context compacted. 42 tokens freed.' })
    emit('run.complete', { runId: 'compact-run' })

    expect(chat.streamingText).toBe('')
    expect(chat.messages).toHaveLength(1)
    expect(chat.messages[0].parts).toContain('"tokensFreed":42')
  })

  it('recognizes uppercase compact and binds run.started before the response', async () => {
    const chat = await loadedChat()
    let resolvePost!: (value: { data: { runId: string; conversationId: string } }) => void
    post.mockReturnValueOnce(new Promise((resolve) => { resolvePost = resolve }))

    const sending = chat.sendMessage('agent-1', '/COMPACT')
    emit('run.started', { runId: 'compact-run', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.text_delta', { runId: 'compact-run', text: 'Context compacted. 7 tokens freed.' })
    resolvePost({ data: { runId: 'compact-run', conversationId: 'conv-1' } })
    await sending
    emit('run.complete', { runId: 'compact-run' })

    expect(chat.messages).toHaveLength(1)
    expect(chat.messages[0].source).toBe('checkpoint')
    expect(chat.messages[0].parts).toContain('"tokensFreed":7')
  })

  it('keeps compact state through another run error and clears it on the matching error', async () => {
    const chat = await loadedChat()
    post.mockResolvedValueOnce({ data: { runId: 'compact-run', conversationId: 'conv-1' } })

    await chat.sendMessage('agent-1', '/compact')
    emit('run.started', { runId: 'prior-run', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.error', { runId: 'prior-run', error: 'late failure' })
    emit('run.started', { runId: 'compact-run', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.text_delta', { runId: 'compact-run', text: 'Context compacted. 5 tokens freed.' })
    emit('run.complete', { runId: 'compact-run' })

    expect(chat.messages.some((message) => message.source === 'checkpoint')).toBe(true)

    post.mockResolvedValueOnce({ data: { runId: 'failed-compact', conversationId: 'conv-1' } })
    await chat.sendMessage('agent-1', '/compact')
    emit('run.error', { runId: 'failed-compact', error: 'compact failed' })
    emit('run.started', { runId: 'failed-compact', agentId: 'agent-1', conversationId: 'conv-1' })
    emit('run.complete', { runId: 'failed-compact' })

    expect(chat.messages.filter((message) => message.source === 'checkpoint')).toHaveLength(1)
    expect(chat.messages.some((message) => message.source === 'error')).toBe(true)
  })

  it('clears only its own compact request when the POST fails', async () => {
    const chat = await loadedChat()
    post.mockRejectedValueOnce(new Error('request failed'))

    await expect(chat.sendMessage('agent-1', '/compact')).rejects.toThrow('request failed')

    post.mockResolvedValueOnce({ data: { runId: 'normal-run', conversationId: 'conv-1' } })
    await chat.sendMessage('agent-1', 'hello')
    emit('run.text_delta', { runId: 'normal-run', text: 'visible reply' })
    emit('run.complete', { runId: 'normal-run' })

    expect(chat.messages.some((message) => message.content === 'visible reply')).toBe(true)
    expect(chat.messages.some((message) => message.source === 'checkpoint')).toBe(false)
  })
})
