import { ref, reactive } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { useAuthStore } from '@/stores/auth'
import {
  type SystemConversationInfo,
  type SystemMessageInfo,
  ListSystemConversationsResponseSchema,
  GetSystemConversationResponseSchema,
} from '@/gen/airlock/v1/system_agent_pb'
import { PromptResponseSchema } from '@/gen/airlock/v1/api_pb'
import {
  RunStartedEventSchema,
  TextDeltaEventSchema,
  ToolCallEventSchema,
  ToolResultEventSchema,
  ConfirmationRequiredEventSchema,
  RunCompleteEventSchema,
  RunErrorEventSchema,
  NotificationEventSchema,
  type RunStartedEvent,
  type TextDeltaEvent,
  type ToolCallEvent,
  type ToolResultEvent,
  type ConfirmationRequiredEvent,
  type RunCompleteEvent,
  type RunErrorEvent,
  type NotificationEvent,
} from '@/gen/airlock/v1/realtime_pb'
import { formatToolArgs, toolLabel, type MsgBlock, type ToolBlock } from '@/utils/messageGroup'

// Trimmed sysagent equivalent of stores/chat.ts. Sysagent conversations stay
// short (operator chats), so this store skips the agent-chat machinery
// for sliding-window pagination, file uploads, slash commands, /compact,
// and A2A subagent gating. WS event shapes are reused verbatim — backend
// emits the same TextDelta/ToolCall/ToolResult/ConfirmationRequired/
// RunComplete/RunError envelopes on the conversation topic.

export interface ToolCall {
  toolCallId: string
  toolName: string
  input: string
  output: string
  error: string
  status: 'running' | 'done' | 'error' | 'denied' | 'confirmation'
}

export interface Confirmation {
  runId: string
  toolName: string
  argsJson: string
  toolCallId: string
}

// Display message — wraps the wire SystemMessageInfo + adds the same
// MsgBlock[] shape the agent chat renderer expects (so MessageParts.vue
// renders identically). Mirrors how enrichMessages enhances
// AgentMessageInfo.
export interface DisplayMessage {
  id: string
  role: string // "user" | "assistant" | "tool"
  source: string
  parts: string
  content?: string
  blocks?: MsgBlock[]
  costEstimate: number
  _cancelled?: boolean
}

function enrichMessage(m: SystemMessageInfo): DisplayMessage {
  // parts is the goai content JSON (same shape as agent_messages.parts).
  // We pass it through verbatim — MessageParts.vue handles the goai
  // content layout for both surfaces.
  let blocks: MsgBlock[] | undefined
  let content = ''
  if (m.parts) {
    try {
      const parsed = JSON.parse(m.parts)
      if (Array.isArray(parsed)) {
        // Pull plain text out for the text fallback / search.
        content = parsed
          .filter((p: any) => p && p.type === 'text' && typeof p.text === 'string')
          .map((p: any) => p.text)
          .join('\n')
        // Map goai parts → MsgBlock shape for the renderer.
        blocks = parsed
          .map((p: any): MsgBlock | null => {
            if (!p) return null
            if (p.type === 'text') return { kind: 'text', text: p.text || '' }
            if (p.type === 'tool_call' || p.type === 'tool_use') {
              const rawArgs = (() => { try { return typeof p.input === 'string' ? JSON.parse(p.input) : p.input } catch { return p.input ?? '' } })()
              return {
                kind: 'tool',
                toolCallId: p.tool_call_id || p.id || '',
                toolName: p.tool_name || p.name || 'tool',
                label: toolLabel(p.tool_name || p.name || 'tool', rawArgs),
                input: formatToolArgs(rawArgs),
                output: '',
                error: '',
                outcome: '' as ToolBlock['outcome'],
              }
            }
            if (p.type === 'tool_result') {
              return null // tool_result entries are folded into their sibling tool_call below
            }
            return null
          })
          .filter((b: any): b is MsgBlock => b !== null)
        // Second pass — fold tool_result entries into their matching tool block.
        for (const part of parsed) {
          if (!part || part.type !== 'tool_result') continue
          const tcid = part.tool_call_id || part.id
          const hit = blocks?.find((b): b is Extract<MsgBlock, { kind: 'tool' }> =>
            b.kind === 'tool' && b.toolCallId === tcid)
          if (!hit) continue
          hit.output = typeof part.output === 'string' ? part.output : JSON.stringify(part.output ?? '')
          hit.error = part.error || ''
          hit.outcome = (part.outcome as ToolBlock['outcome']) || (part.error ? 'error' : 'success')
        }
      }
    } catch {
      // parts wasn't JSON — fall back to displaying parts as raw content.
      content = m.parts
    }
  }
  return {
    id: m.id,
    role: m.role,
    source: m.source || '',
    parts: m.parts,
    content,
    blocks,
    costEstimate: m.costEstimate,
  }
}

export const useSystemChatStore = defineStore('systemChat', () => {
  const conversations = ref<SystemConversationInfo[]>([])
  const conversationId = ref<string | null>(null)
  const conversation = ref<SystemConversationInfo | null>(null)
  const messages = ref<DisplayMessage[]>([])
  const streamingText = ref('')
  const activeToolCalls = reactive(new Map<string, ToolCall>())
  const streamingBlocks = ref<Array<{ kind: 'text'; text: string } | { kind: 'tool'; toolCallId: string }>>([])
  const pendingConfirmation = ref<Confirmation | null>(null)
  const currentRunId = ref<string | null>(null)
  const sending = ref(false)
  const loading = ref(false)
  // Late events for runs the user cancelled locally — drop so the
  // optimistically finalized bubble stays put.
  const cancelledRunIds = new Set<string>()
  // Block boundary marker — set by tool_call/tool_result to force the
  // next text_delta into a fresh text block (matches enrichMessage's
  // per-step layout on refetch).
  let textBlockBoundary = false

  const unsubscribers: (() => void)[] = []

  function tryFromJson<T>(schema: any, payload: unknown): T | null {
    if (!payload || typeof payload !== 'object') return null
    try {
      return fromJson(schema, payload as any) as T
    } catch {
      return null
    }
  }

  function isActiveRun(evRunId: string): boolean {
    if (cancelledRunIds.has(evRunId)) return false
    return evRunId === currentRunId.value
  }

  // Address gate — sysagent events publish on the user's UUID topic
  // with the conversation id on envelope.conversationId. Both must match for
  // the event to belong to the active conversation. Subagent envelopes don't
  // apply (no A2A surface in sysagent).
  function onConversationMessage(type: string, handler: (payload: unknown) => void) {
    return ws.onMessage(type, (payload, env) => {
      if (!env || env.subagent) return
      const auth = useAuthStore()
      if (!auth.user?.id || env.topicId !== auth.user.id) return
      if (!conversationId.value || env.conversationId !== conversationId.value) return
      handler(payload)
    })
  }

  function initListeners() {
    if (unsubscribers.length > 0) return
    unsubscribers.push(
      onConversationMessage('run.started', (payload) => {
        const ev = tryFromJson<RunStartedEvent>(RunStartedEventSchema, payload)
        if (!ev || cancelledRunIds.has(ev.runId)) return
        currentRunId.value = ev.runId
        streamingText.value = ''
        activeToolCalls.clear()
        streamingBlocks.value = []
        textBlockBoundary = false
      }),
      onConversationMessage('run.text_delta', (payload) => {
        const ev = tryFromJson<TextDeltaEvent>(TextDeltaEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        const tail = streamingBlocks.value[streamingBlocks.value.length - 1]
        if (textBlockBoundary || !tail || tail.kind !== 'text') {
          streamingBlocks.value.push({ kind: 'text', text: ev.text })
        } else {
          tail.text += ev.text
        }
        textBlockBoundary = false
        streamingText.value += ev.text
      }),
      onConversationMessage('run.tool_call', (payload) => {
        const ev = tryFromJson<ToolCallEvent>(ToolCallEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        textBlockBoundary = true
        activeToolCalls.set(ev.toolCallId, {
          toolCallId: ev.toolCallId,
          toolName: ev.toolName,
          input: ev.input,
          output: '',
          error: '',
          status: 'running',
        })
        streamingBlocks.value.push({ kind: 'tool', toolCallId: ev.toolCallId })
      }),
      onConversationMessage('run.tool_result', (payload) => {
        const ev = tryFromJson<ToolResultEvent>(ToolResultEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        textBlockBoundary = true
        const status =
          ev.outcome === 'error' ? 'error' : ev.outcome === 'denied' ? 'denied' : 'done'
        const tc = activeToolCalls.get(ev.toolCallId)
        if (tc) {
          tc.output = ev.output
          tc.error = ev.error
          tc.status = status
        }
      }),
      onConversationMessage('run.confirmation_required', (payload) => {
        const ev = tryFromJson<ConfirmationRequiredEvent>(ConfirmationRequiredEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        // sysagent permission requests carry the tool args under metadata.args
        // (set by the gated executor). The ConfirmationRequired envelope
        // surfaces `code` for the agent flow's run_js callsite snippet —
        // we map it to argsJson here for the sysagent UI's pretty-print.
        pendingConfirmation.value = {
          runId: ev.runId,
          toolName: ev.permission,
          argsJson: ev.code || '',
          toolCallId: ev.toolCallId,
        }
        const tc = activeToolCalls.get(ev.toolCallId)
        if (tc) tc.status = 'confirmation'
      }),
      onConversationMessage('run.complete', (payload) => {
        const ev = tryFromJson<RunCompleteEvent>(RunCompleteEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        if (pendingConfirmation.value) return // suspended, not complete
        finalizeMessage()
      }),
      onConversationMessage('run.error', (payload) => {
        const ev = tryFromJson<RunErrorEvent>(RunErrorEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        finalizeMessage()
        messages.value.push({
          id: `error-${ev.runId}`,
          role: 'assistant',
          source: 'error',
          parts: '',
          content: ev.error || 'Run failed.',
          costEstimate: 0,
        })
      }),
      onConversationMessage('notification', (payload) => {
        const ev = tryFromJson<NotificationEvent>(NotificationEventSchema, payload)
        if (!ev) return
        const source = ev.source || 'notification'
        let content = ''
        if (ev.partsJson) {
          try {
            const parsed = JSON.parse(ev.partsJson)
            if (Array.isArray(parsed)) {
              content = parsed
                .filter((p: any) => p && p.type === 'text' && typeof p.text === 'string')
                .map((p: any) => p.text)
                .join('\n')
            }
          } catch { /* ignore */ }
        }
        messages.value.push({
          id: `notif-${Date.now()}`,
          role: 'user',
          source,
          parts: ev.partsJson,
          content,
          costEstimate: 0,
        })
      }),
    )
  }

  function finalizeMessage(opts?: { cancelled?: boolean }) {
    const blocks: MsgBlock[] = streamingBlocks.value.map((b) => {
      if (b.kind === 'text') return { kind: 'text', text: b.text }
      const tc = activeToolCalls.get(b.toolCallId)
      const rawArgs = (() => { try { return JSON.parse(tc?.input ?? '') } catch { return tc?.input ?? '' } })()
      const outcome: ToolBlock['outcome'] =
        tc?.status === 'error'
          ? 'error'
          : tc?.status === 'denied'
            ? 'denied'
            : tc?.status === 'done'
              ? 'success'
              : ''
      return {
        kind: 'tool',
        toolCallId: b.toolCallId,
        toolName: tc?.toolName || 'tool',
        label: toolLabel(tc?.toolName || 'tool', rawArgs),
        input: formatToolArgs(rawArgs),
        output: tc?.output || '',
        error: tc?.error || '',
        outcome,
      }
    })

    if (blocks.length || streamingText.value || opts?.cancelled) {
      const stamp = currentRunId.value || Date.now().toString()
      const msg: DisplayMessage = {
        id: `msg-${stamp}`,
        role: 'assistant',
        source: '',
        parts: '',
        content: streamingText.value,
        costEstimate: 0,
      }
      if (blocks.length) msg.blocks = blocks
      if (opts?.cancelled) msg._cancelled = true
      messages.value.push(msg)
    }
    streamingText.value = ''
    activeToolCalls.clear()
    streamingBlocks.value = []
    textBlockBoundary = false
    currentRunId.value = null
    sending.value = false
  }

  function resetTransient() {
    streamingText.value = ''
    activeToolCalls.clear()
    streamingBlocks.value = []
    pendingConfirmation.value = null
    currentRunId.value = null
    sending.value = false
  }

  async function refreshConversations() {
    const { data } = await api.get('/api/v1/system/conversations')
    const resp = fromJson(ListSystemConversationsResponseSchema, data)
    conversations.value = [...resp.conversations].sort(
      (a, b) => Number(b.updatedAt?.seconds ?? 0n) - Number(a.updatedAt?.seconds ?? 0n))
    return conversations.value
  }

  async function createConversation(title?: string): Promise<SystemConversationInfo> {
    const payload: Record<string, any> = {}
    if (title) payload.title = title
    const { data } = await api.post('/api/v1/system/conversations', payload)
    // CreateSystemConversationResponse shape: { conversation }
    const created: SystemConversationInfo = data.conversation
    conversations.value = [created, ...conversations.value.filter(t => t.id !== created.id)]
    return created
  }

  async function deleteConversation(id: string) {
    await api.delete(`/api/v1/system/conversations/${id}`)
    conversations.value = conversations.value.filter(t => t.id !== id)
    if (conversationId.value === id) {
      conversationId.value = null
      conversation.value = null
      messages.value = []
      resetTransient()
    }
  }

  // Load a conversation's full history. Subscribes to the conversation topic for
  // live events; restores a pending confirmation if the conversation is
  // suspended.
  async function loadConversation(id: string) {
    resetTransient()
    loading.value = true
    conversationId.value = id
    try {
      const { data } = await api.get(`/api/v1/system/conversations/${id}`)
      const resp = fromJson(GetSystemConversationResponseSchema, data)
      conversation.value = resp.conversation || null
      messages.value = resp.messages.map(enrichMessage)
      if (conversation.value?.status === 'awaiting_confirmation' && conversation.value.pendingTool) {
        const pt = conversation.value.pendingTool
        pendingConfirmation.value = {
          runId: '',
          toolName: pt.toolName,
          argsJson: pt.argsJson,
          toolCallId: pt.callId,
        }
      }
      // No explicit WS subscribe — the user's UUID topic is auto-subscribed
      // on WS connect (api/ws.go), so every sysagent event for any of this
      // user's conversations is already arriving on the socket. onConversationMessage
      // filters by env.conversationId to pin to the active conversation.
    } finally {
      loading.value = false
    }
  }

  // Submit operator input. text is the prompt body (empty on approve/
  // deny resume). approved is set when responding to a pending
  // confirmation — sysagent's executor resolves the prior gated call
  // before continuing the run.
  async function sendPrompt(text: string, approved?: boolean) {
    if (!conversationId.value) throw new Error('no active conversation')
    const isResume = approved !== undefined

    if (isResume) {
      // The suspended turn's partial assistant text + the gated tool
      // call live in transient state. The resume's run.started clears
      // activeToolCalls — commit the bubble first so the user doesn't
      // see it vanish until refetch.
      finalizeMessage()
      cancelledRunIds.clear()
      // Drop _cancelled tags on bubbles we're now resuming — no longer true.
      for (const m of messages.value) if (m._cancelled) delete m._cancelled
    } else {
      // Optimistic user message.
      messages.value.push({
        id: `pending-${Date.now()}`,
        role: 'user',
        source: '',
        parts: '',
        content: text,
        costEstimate: 0,
      })
      streamingText.value = ''
      activeToolCalls.clear()
      streamingBlocks.value = []
      textBlockBoundary = false
    }

    sending.value = true
    pendingConfirmation.value = null

    const payload: Record<string, any> = { message: text }
    if (approved !== undefined) payload.approved = approved

    try {
      const { data } = await api.post(`/api/v1/system/conversations/${conversationId.value}/prompt`, payload)
      const response = fromJson(PromptResponseSchema, data)
      currentRunId.value = response.runId
      void refreshConversations() // bubble updated_at to top
    } catch (err) {
      sending.value = false
      // Roll back optimistic user row on send failure.
      messages.value = messages.value.filter(m => !m.id.startsWith('pending-'))
      throw err
    }
  }

  function cleanup() {
    for (const unsub of unsubscribers) unsub()
    unsubscribers.length = 0
    conversations.value = []
    conversationId.value = null
    conversation.value = null
    messages.value = []
    resetTransient()
  }

  return {
    conversations,
    conversationId,
    conversation,
    messages,
    streamingText,
    streamingBlocks,
    activeToolCalls,
    pendingConfirmation,
    currentRunId,
    sending,
    loading,
    initListeners,
    refreshConversations,
    createConversation,
    deleteConversation,
    loadConversation,
    sendPrompt,
    cleanup,
  }
})
