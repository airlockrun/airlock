import { ref, reactive } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListConversationsResponseSchema,
  GetConversationResponseSchema,
  PaginatedMessagesResponseSchema,
  PromptResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import { enrichMessages as enrichMessagesShared, formatToolArgs } from '@/utils/messageGroup'

// Sliding-window pagination keeps the browser's in-memory message list
// bounded. Scrolling up past the top fetches an older page; if the window
// grows past WINDOW_CAP the far end is dropped from memory (and re-fetched
// on demand if the user scrolls back). Scrolling down past the bottom does
// the mirror operation.
const INITIAL_LOAD = 100
const PAGE_SIZE = 100
const WINDOW_CAP = 300
import type {
  RunStartedEvent,
  TextDeltaEvent,
  ToolCallEvent,
  ToolResultEvent,
  ConfirmationRequiredEvent,
  RunCompleteEvent,
  RunErrorEvent,
  NotificationEvent,
} from '@/gen/airlock/v1/realtime_pb'
import {
  RunStartedEventSchema,
  TextDeltaEventSchema,
  ToolCallEventSchema,
  ToolResultEventSchema,
  ConfirmationRequiredEventSchema,
  RunCompleteEventSchema,
  RunErrorEventSchema,
  NotificationEventSchema,
} from '@/gen/airlock/v1/realtime_pb'

export interface ToolCall {
  toolCallId: string
  toolName: string
  input: string
  output: string
  error: string
  status: 'running' | 'done' | 'error' | 'confirmation'
}

export interface Confirmation {
  runId: string
  permission: string
  patterns: string[]
  code: string
  toolCallId: string
}

export const useChatStore = defineStore('chat', () => {
  const conversationId = ref<string | null>(null)
  const messages = ref<AgentMessageInfo[]>([])
  const streamingText = ref('')
  const activeToolCalls = reactive(new Map<string, ToolCall>())
  const pendingConfirmation = ref<Confirmation | null>(null)
  const currentRunId = ref<string | null>(null)
  const sending = ref(false)

  // Sliding-window pagination state. hasOlder means messages exist older
  // than `messages[0]` — enable the top sentinel observer. hasNewer means
  // the window has been scrolled up past its starting position: new agent
  // responses can't be appended directly (they'd sit out-of-order above the
  // evicted tail), so newMessagesPending surfaces a "jump to latest" banner.
  const hasOlder = ref(false)
  const hasNewer = ref(false)
  const newMessagesPending = ref(false)
  const loadingOlder = ref(false)
  const loadingNewer = ref(false)
  // Notifications arriving mid-run are buffered here and flushed at the end
  // of finalizeMessage — same ordering rule the backend applies in SQL.
  const pendingNotifications: AgentMessageInfo[] = []

  const unsubscribers: (() => void)[] = []

  function tryFromJson<T>(schema: any, payload: unknown): T | null {
    if (!payload || typeof payload !== 'object') return null
    try {
      return fromJson(schema, payload as any) as T
    } catch {
      return null
    }
  }

  // Match events by runId, or accept if we're sending (race: WS arrives before HTTP response).
  function isCurrentRun(evRunId: string): boolean {
    if (evRunId === currentRunId.value) return true
    if (sending.value) return true
    // Silently ignore stale events (e.g., WS replay buffer from previous runs).
    return false
  }

  function initListeners() {
    unsubscribers.push(
      // Adopt server-initiated runs (e.g., post-upgrade notification) for the current conversation.
      ws.onMessage('run.started', (payload) => {
        const ev = tryFromJson<RunStartedEvent>(RunStartedEventSchema, payload)
        if (!ev) return
        if (ev.conversationId === conversationId.value && !sending.value && !currentRunId.value) {
          currentRunId.value = ev.runId
          streamingText.value = ''
          activeToolCalls.clear()
        }
      }),
      ws.onMessage('run.text_delta', (payload) => {
        const ev = tryFromJson<TextDeltaEvent>(TextDeltaEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        streamingText.value += ev.text
      }),
      ws.onMessage('run.tool_call', (payload) => {
        const ev = tryFromJson<ToolCallEvent>(ToolCallEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        activeToolCalls.set(ev.toolCallId, {
          toolCallId: ev.toolCallId,
          toolName: ev.toolName,
          input: ev.input,
          output: '',
          error: '',
          status: 'running',
        })
      }),
      ws.onMessage('run.tool_result', (payload) => {
        const ev = tryFromJson<ToolResultEvent>(ToolResultEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        const tc = activeToolCalls.get(ev.toolCallId)
        if (tc) {
          tc.output = ev.output
          tc.error = ev.error
          tc.status = ev.error ? 'error' : 'done'
        }
      }),
      ws.onMessage('run.confirmation_required', (payload) => {
        const ev = tryFromJson<ConfirmationRequiredEvent>(ConfirmationRequiredEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        pendingConfirmation.value = {
          runId: ev.runId,
          permission: ev.permission,
          patterns: [...ev.patterns],
          code: ev.code,
          toolCallId: ev.toolCallId,
        }
        // Mark the associated tool call as awaiting confirmation.
        if (ev.toolCallId) {
          const tc = activeToolCalls.get(ev.toolCallId)
          if (tc) {
            tc.status = 'confirmation'
          }
        }
      }),
      ws.onMessage('run.complete', (payload) => {
        const ev = tryFromJson<RunCompleteEvent>(RunCompleteEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        // Don't finalize if awaiting confirmation — run is suspended, not complete.
        if (pendingConfirmation.value) return
        console.log('[chat] run.complete', { runId: ev.runId, textLen: streamingText.value.length })
        finalizeMessage()
      }),
      ws.onMessage('run.error', (payload) => {
        const ev = tryFromJson<RunErrorEvent>(RunErrorEventSchema, payload)
        if (!ev || !isCurrentRun(ev.runId)) return
        console.warn('[chat] run.error', { runId: ev.runId, error: ev.error })
        // Finalize whatever assistant text streamed before the failure (don't
        // discard partial output) and append a separate source='error' bubble
        // matching the shape airlock persists to agent_messages on RunComplete.
        // The persisted row arrives via DB fetch on refresh; this synth makes
        // the live experience match without waiting.
        finalizeMessage()
        const errText = ev.error || 'Run failed.'
        messages.value.push({
          $typeName: 'airlock.v1.AgentMessageInfo',
          id: `error-${ev.runId}`,
          role: 'assistant',
          source: 'error',
          content: errText,
          tokensIn: 0,
          tokensOut: 0,
          costEstimate: 0,
        } as any)
      }),
      ws.onMessage('run.suspended', () => {
        // Run suspended (e.g., awaiting approval) — keep state as-is.
      }),
      ws.onMessage('notification', (payload) => {
        const ev = tryFromJson<NotificationEvent>(NotificationEventSchema, payload)
        if (!ev || !ev.conversationId) return
        if (ev.conversationId !== conversationId.value) return
        // Don't append while the user is scrolled back into history —
        // finalizeMessage surfaces the banner and this notification
        // reappears on jumpToLatest via DB fetch.
        if (hasNewer.value) {
          newMessagesPending.value = true
          return
        }
        const source = ev.source || 'notification'
        const msg = buildNotificationMessage(ev.partsJson, source)
        // Upload echoes belong before the assistant's response (they are the
        // user's just-attached files), so bypass the buffer that holds
        // mid-run printToUser notifications until finalizeMessage.
        if ((currentRunId.value || sending.value) && source !== 'upload') {
          pendingNotifications.push(msg)
        } else {
          enrichNotification(msg)
          messages.value.push(msg)
        }
      }),
    )
  }

  function buildNotificationMessage(partsJson: string, source: string = 'notification'): AgentMessageInfo {
    // Extract a plain-text summary from the parts so source-specific
    // renderers (upgrade/error/system) that bind to msg.content show
    // the body live, matching what the persisted DB row will return on
    // refresh. Without this the live bubble renders empty until reload.
    let content = ''
    if (partsJson) {
      try {
        const parsed = JSON.parse(partsJson)
        if (Array.isArray(parsed)) {
          content = parsed
            .filter((p: any) => p && p.type === 'text' && typeof p.text === 'string')
            .map((p: any) => p.text)
            .join('\n')
        }
      } catch { /* leave content empty */ }
    }
    return {
      $typeName: 'airlock.v1.AgentMessageInfo',
      id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      role: source === 'upload' ? 'user' : 'assistant',
      content,
      parts: partsJson,
      source,
      tokensIn: 0,
      tokensOut: 0,
      costEstimate: 0,
    } as any
  }

  function enrichNotification(msg: AgentMessageInfo) {
    if (!msg.parts) return
    try {
      const parsed = typeof msg.parts === 'string' ? JSON.parse(msg.parts) : msg.parts
      if (Array.isArray(parsed)) {
        ;(msg as any).displayParts = parsed
      }
    } catch { /* leave unparsed — the view falls back to content */ }
  }

  let sendingTimeout: ReturnType<typeof setTimeout> | null = null

  function finalizeMessage() {
    if (sendingTimeout) { clearTimeout(sendingTimeout); sendingTimeout = null }
    console.log('[chat] finalizeMessage', { textLen: streamingText.value.length, toolCalls: activeToolCalls.size, sending: sending.value, runId: currentRunId.value })

    // If the window has been scrolled back (hasNewer=true), appending new
    // messages would place them out-of-order above evicted history. Drop
    // the just-streamed text/tool output and surface a banner instead; the
    // user clicks to reset to the newest page and see the full exchange.
    if (hasNewer.value) {
      streamingText.value = ''
      activeToolCalls.clear()
      pendingNotifications.length = 0
      newMessagesPending.value = true
      currentRunId.value = null
      sending.value = false
      return
    }

    // Collect tool calls before clearing. Each is normalized to the same
    // GroupedToolCall shape that enrichMessages produces on persisted rows
    // so the live and refresh paths render identically.
    const toolCalls = activeToolCalls.size > 0
      ? [...activeToolCalls.values()].map((tc) => ({
          toolCallId: tc.toolCallId,
          toolName: tc.toolName,
          input: formatToolArgs((() => { try { return JSON.parse(tc.input) } catch { return tc.input } })()),
          output: tc.output || '',
          error: tc.error || '',
        }))
      : undefined

    // Push ONE assistant message carrying both the streamed text and the
    // tool calls inline. The render template groups them inside a single
    // bubble (tool calls first, text last) — matches the streaming layout
    // so finalize doesn't visually snap. Need to push even when there's
    // no text, since a tool-only assistant turn (typical of run_js loops)
    // still has to surface its tool calls.
    if (toolCalls || streamingText.value) {
      const stamp = currentRunId.value || Date.now().toString()
      const msg: any = {
        $typeName: 'airlock.v1.AgentMessageInfo',
        id: `msg-${stamp}`,
        role: 'assistant',
        content: streamingText.value,
        tokensIn: 0,
        tokensOut: 0,
        costEstimate: 0,
      }
      if (toolCalls) msg.toolCalls = toolCalls
      messages.value.push(msg as AgentMessageInfo)
    }
    // Drain notifications buffered during the run — now the assistant/tool
    // bubbles are in place, so notifications land after them.
    if (pendingNotifications.length > 0) {
      for (const n of pendingNotifications) {
        enrichNotification(n)
        messages.value.push(n)
      }
      pendingNotifications.length = 0
    }
    streamingText.value = ''
    activeToolCalls.clear()
    currentRunId.value = null
    sending.value = false
  }

  // Enrich messages with tool call/result info, then layer on the chat-store-
  // specific notification enrichment that the run views don't need.
  function enrichMessages(msgs: AgentMessageInfo[]): AgentMessageInfo[] {
    enrichMessagesShared(msgs)
    for (const msg of msgs) {
      if (msg.source === 'notification' || msg.source === 'upload') enrichNotification(msg)
    }
    return msgs
  }

  // Restore confirmation state from server-provided pending confirmation.
  function restorePendingConfirmation(pc: { toolCallId: string; toolName: string; input: string }, msgs: AgentMessageInfo[]) {
    const input = formatToolArgs((() => { try { return JSON.parse(pc.input) } catch { return pc.input } })())
    activeToolCalls.set(pc.toolCallId, {
      toolCallId: pc.toolCallId,
      toolName: pc.toolName,
      input,
      output: '',
      error: '',
      status: 'confirmation',
    })
    pendingConfirmation.value = {
      runId: '',
      permission: pc.toolName,
      patterns: [],
      code: input,
      toolCallId: pc.toolCallId,
    }
    // Hide the assistant message that contains this tool call — it's shown via activeToolCalls.
    for (let i = msgs.length - 1; i >= 0; i--) {
      if (msgs[i].role === 'assistant' && (msgs[i] as any).toolCalls?.some((c: any) => c.toolCallId === pc.toolCallId)) {
        ;(msgs[i] as any)._hidden = true
        break
      }
    }
  }

  async function loadConversation(agentId: string) {
    const { data } = await api.get(`/api/v1/agents/${agentId}/conversations`)
    const response = fromJson(ListConversationsResponseSchema, data)
    // Only surface the web conversation here. Bridge conversations (telegram,
    // etc.) live alongside it in the same list ordered by updated_at, so
    // picking [0] would flip the UI to the bridge thread whenever someone
    // chatted via the bot more recently than via the web.
    const web = response.conversations.find(c => c.source === 'web')
    if (web) {
      conversationId.value = web.id
      const { data: convData } = await api.get(`/api/v1/conversations/${conversationId.value}`)
      const convResponse = fromJson(GetConversationResponseSchema, convData)
      messages.value = enrichMessages(convResponse.messages)
      hasOlder.value = convResponse.hasOlderMessages
      hasNewer.value = false
      newMessagesPending.value = false
      // Restore pending confirmation from server if present.
      if (convResponse.pendingConfirmation?.toolCallId) {
        restorePendingConfirmation(convResponse.pendingConfirmation, messages.value)
      }
    } else {
      conversationId.value = null
      messages.value = []
      hasOlder.value = false
      hasNewer.value = false
      newMessagesPending.value = false
    }
  }

  // Fetch the next older page. Triggered by the chat view's top sentinel
  // when it enters the viewport. Returns the number of messages prepended
  // so the caller can preserve scroll offset via scrollHeight delta.
  async function loadOlder(): Promise<number> {
    if (!conversationId.value || !hasOlder.value || loadingOlder.value) return 0
    loadingOlder.value = true
    try {
      const oldest = messages.value[0]
      if (!oldest) return 0
      const { data } = await api.get(
        `/api/v1/conversations/${conversationId.value}/messages`,
        { params: { before: oldest.seq.toString(), limit: PAGE_SIZE } })
      const resp = fromJson(PaginatedMessagesResponseSchema, data)
      const older = enrichMessages(resp.messages)
      messages.value = [...older, ...messages.value]
      hasOlder.value = resp.hasMore

      // Evict from the tail if we've exceeded the window cap.
      if (messages.value.length > WINDOW_CAP) {
        const evict = messages.value.length - WINDOW_CAP
        messages.value = messages.value.slice(0, messages.value.length - evict)
        hasNewer.value = true
      }
      return older.length
    } finally {
      loadingOlder.value = false
    }
  }

  // Fetch the next newer page. Triggered when the user scrolls back down
  // into a region we've previously evicted.
  async function loadNewer(): Promise<number> {
    if (!conversationId.value || !hasNewer.value || loadingNewer.value) return 0
    loadingNewer.value = true
    try {
      const newest = messages.value[messages.value.length - 1]
      if (!newest) return 0
      const { data } = await api.get(
        `/api/v1/conversations/${conversationId.value}/messages`,
        { params: { after: newest.seq.toString(), limit: PAGE_SIZE } })
      const resp = fromJson(PaginatedMessagesResponseSchema, data)
      const newer = enrichMessages(resp.messages)
      messages.value = [...messages.value, ...newer]
      hasNewer.value = resp.hasMore
      if (!hasNewer.value) newMessagesPending.value = false

      // Evict from the head if we've exceeded the window cap.
      if (messages.value.length > WINDOW_CAP) {
        const evict = messages.value.length - WINDOW_CAP
        messages.value = messages.value.slice(evict)
        hasOlder.value = true
      }
      return newer.length
    } finally {
      loadingNewer.value = false
    }
  }

  // Reset the window to the latest page. Called from the "new messages"
  // banner — when the user is scrolled up in history and new agent output
  // arrives, they can click to jump back to live.
  async function jumpToLatest(agentId: string) {
    await loadConversation(agentId)
  }

  async function sendMessage(agentId: string, text: string, approved?: boolean, filePaths?: string[]) {
    const isResume = approved !== undefined
    // Slash commands (/clear, /compact, ...) are handled synchronously by
    // Airlock — no run is created and no optimistic user bubble should appear.
    const isSlashCommand = !isResume && text.trim().startsWith('/')

    if (!isResume && !isSlashCommand) {
      // Add optimistic user message for normal sends only. Skip when the
      // window is scrolled back (hasNewer=true) so we don't insert above
      // evicted history — the user will see their message after clicking
      // "jump to latest."
      if (!hasNewer.value) {
        messages.value.push({
          $typeName: 'airlock.v1.AgentMessageInfo',
          id: `pending-${Date.now()}`,
          role: 'user',
          content: text,
          tokensIn: 0,
          tokensOut: 0,
          costEstimate: 0,
        } as AgentMessageInfo)
      }
      // Reset streaming state for new messages.
      streamingText.value = ''
      activeToolCalls.clear()
    }

    sending.value = true
    pendingConfirmation.value = null

    const payload: Record<string, any> = { message: text }
    if (approved !== undefined) payload.approved = approved
    if (filePaths?.length) payload.filePaths = filePaths

    try {
      const { data } = await api.post(`/api/v1/agents/${agentId}/prompt`, payload)
      const response = fromJson(PromptResponseSchema, data)
      console.log('[chat] prompt response', { runId: response.runId, conversationId: response.conversationId, commandReply: response.commandReply })

      // Slash-command path: empty run_id + a command_reply. Reload messages
      // to pick up any checkpoint markers or other backend-inserted rows.
      if (!response.runId && response.commandReply) {
        sending.value = false
        await loadConversation(agentId)
        return
      }

      currentRunId.value = response.runId
      if (response.conversationId) {
        conversationId.value = response.conversationId
      }

      // Safety timeout: if run.complete/run.error never arrives (e.g., WS down),
      // unblock the input so the user isn't stuck.
      if (sendingTimeout) clearTimeout(sendingTimeout)
      sendingTimeout = setTimeout(() => {
        if (sending.value) finalizeMessage()
      }, 5 * 60 * 1000)
    } catch {
      sending.value = false
    }
  }

  function cleanup() {
    for (const unsub of unsubscribers) unsub()
    unsubscribers.length = 0
    conversationId.value = null
    messages.value = []
    streamingText.value = ''
    activeToolCalls.clear()
    pendingConfirmation.value = null
    currentRunId.value = null
    sending.value = false
    hasOlder.value = false
    hasNewer.value = false
    newMessagesPending.value = false
  }

  return {
    conversationId,
    messages,
    streamingText,
    activeToolCalls,
    pendingConfirmation,
    currentRunId,
    sending,
    hasOlder,
    hasNewer,
    newMessagesPending,
    loadingOlder,
    loadingNewer,
    initListeners,
    loadConversation,
    loadOlder,
    loadNewer,
    jumpToLatest,
    sendMessage,
    cleanup,
  }
})
