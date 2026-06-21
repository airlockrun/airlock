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
import { formatToolArgs, toolDescription, toolLabel, toolOutputInfo, type MsgBlock, type ToolBlock } from '@/utils/messageGroup'

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
  description: string
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
  _hidden?: boolean
}

// Mirrors @/utils/messageGroup::enrichMessages adapted to the sysagent
// row shape (no run-anchor folding — sysagent doesn't have a runId
// column on its messages; one row per goai sub-message, in seq order).
//
// Storage contract matches agent_messages:
//   * content = plain-text display string (always populated server-side
//     via extractDisplayText in sysagent/sessionstore.go).
//   * parts   = goai multi-part Content JSON (typed array with
//     hyphenated discriminators: text / tool-call / tool-result), set
//     ONLY when goai's Content.IsMultiPart(). Plain text answers
//     leave parts empty so the renderer's "no blocks → render
//     content" fast path lights up the same way agent chat does.
//
// Tool results from sol's MessageToGoAI expansion land on their own
// role=tool row; we fold each into the matching tool-call block from
// a prior row, then hide the tool row from the bubble list.
function enrichMessages(rows: SystemMessageInfo[]): DisplayMessage[] {
  const out: DisplayMessage[] = rows.map((m) => ({
    id: m.id,
    role: m.role,
    source: m.source || '',
    parts: m.parts,
    content: m.content,
    costEstimate: m.costEstimate,
  }))

  // Pass 1: parse parts on each row, build per-row blocks, register
  // every tool-call so pass 2 can fold its result.
  const callEntries = new Map<string, ToolBlock>()
  for (let i = 0; i < out.length; i++) {
    const msg = out[i]
    if (msg.role !== 'assistant') continue
    const parts = parseParts(rows[i].parts)
    if (!parts) continue
    const rowBlocks: MsgBlock[] = []
    for (const p of parts) {
      if (!p) continue
      if (p.type === 'text' && typeof p.text === 'string' && p.text) {
        const last = rowBlocks[rowBlocks.length - 1]
        if (last && last.kind === 'text') last.text += p.text
        else rowBlocks.push({ kind: 'text', text: p.text })
      } else if (p.type === 'tool-call' && p.toolCallId) {
        const rawArgs = (() => {
          try {
            return typeof p.args === 'string' ? JSON.parse(p.args) : p.args
          } catch {
            return p.args ?? ''
          }
        })()
        const tb: ToolBlock = {
          kind: 'tool',
          toolCallId: p.toolCallId,
          toolName: p.toolName || 'tool',
          label: toolLabel(p.toolName || 'tool', rawArgs),
          input: formatToolArgs(rawArgs),
          description: toolDescription(rawArgs),
          output: '',
          error: '',
          outcome: '' as ToolBlock['outcome'],
        }
        callEntries.set(tb.toolCallId, tb)
        rowBlocks.push(tb)
      }
    }
    if (rowBlocks.some((b) => b.kind === 'tool')) {
      msg.blocks = rowBlocks
    }
  }

  // Pass 2: fold each tool-result row's output into its matching
  // tool-call block (by toolCallId). The persisted `output` is the
  // discriminated goai ToolResultOutput — toolOutputInfo extracts the
  // displayable text + outcome the same way agent chat does.
  for (let i = 0; i < out.length; i++) {
    const msg = out[i]
    if (msg.role !== 'tool') continue
    const parts = parseParts(rows[i].parts)
    if (!parts) continue
    for (const p of parts) {
      if (p?.type !== 'tool-result' || !p.toolCallId) continue
      const entry = callEntries.get(p.toolCallId)
      if (!entry) continue
      if (p.output && typeof p.output === 'object') {
        const info = toolOutputInfo(p.output)
        entry.outcome = info.outcome
        if (info.outcome === 'error') entry.error = info.text
        else entry.output = info.text
      } else if (msg.content) {
        entry.output = msg.content
      }
      msg._hidden = true
    }
  }

  return out.filter((m) => !m._hidden)
}

// parseParts mirrors the agent-chat helper: JSON-parse a string into
// an array, return null when it's not an array (text-only goai content
// marshals as a bare JSON string — the renderer uses .content instead).
function parseParts(parts: unknown): any[] | null {
  if (!parts) return null
  try {
    const parsed = typeof parts === 'string' ? JSON.parse(parts) : parts
    return Array.isArray(parsed) ? parsed : null
  } catch {
    return null
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
          description: ev.description || '',
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
        description: toolDescription(rawArgs),
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
      messages.value = enrichMessages(resp.messages)
      if (conversation.value?.status === 'awaiting_confirmation' && conversation.value.pendingTool) {
        const pt = conversation.value.pendingTool
        pendingConfirmation.value = {
          runId: '',
          toolName: pt.toolName,
          argsJson: pt.argsJson,
          toolCallId: pt.callId,
          description: toolDescription(pt.argsJson),
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

  // Reset the messages view to a clean "no active conversation" state.
  // Called by SystemChatView when it lands on /system/chat with no
  // route param — the row appears in the sidebar only after the first
  // message is sent (mirrors agent chat's wasNew flow).
  function resetConversationView() {
    conversationId.value = null
    conversation.value = null
    messages.value = []
    resetTransient()
  }

  // Submit operator input. text is the prompt body (empty on approve/
  // deny resume). approved is set when responding to a pending
  // confirmation — sysagent's executor resolves the prior gated call
  // before continuing the run. Returns the conversation id the prompt
  // landed on so the caller (view) can route to /system/chat/:id once
  // the server-side conversation has been minted on first send.
  async function sendPrompt(text: string, approved?: boolean): Promise<string> {
    const isResume = approved !== undefined
    const wasNew = !conversationId.value
    if (wasNew && isResume) throw new Error('cannot resume without an active conversation')
    if (wasNew) {
      // Mint the conversation server-side now that there's a first
      // message to anchor it. Title defaults to "New chat" on the
      // server; later turns can rename. The HTTP POST blocks the
      // optimistic-message render briefly — minor — but keeps the
      // "no row until first send" contract intact.
      const created = await createConversation()
      conversationId.value = created.id
      conversation.value = created
    }
    if (!conversationId.value) throw new Error('no active conversation')
    // The run this confirmation belongs to (from the run.confirmation_required
    // event). Sent so the backend waits for THIS run to suspend rather than
    // racing the conversation's awaiting_confirmation flip. Empty on the
    // refresh-restore path — fine, the conversation is already suspended.
    const resumeRunId = pendingConfirmation.value?.runId

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
    if (resumeRunId) payload.resumeRunId = resumeRunId

    try {
      const { data } = await api.post(`/api/v1/system/conversations/${conversationId.value}/prompt`, payload)
      const response = fromJson(PromptResponseSchema, data)
      currentRunId.value = response.runId
      void refreshConversations() // bubble updated_at to top
      return conversationId.value!
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
    resetConversationView,
    sendPrompt,
    cleanup,
  }
})
