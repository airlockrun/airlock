import { ref, reactive } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import type { AgentMessageInfo, ConversationInfo } from '@/gen/airlock/v1/types_pb'
import {
  ListConversationsResponseSchema,
  GetConversationResponseSchema,
  PaginatedMessagesResponseSchema,
  PromptResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import { enrichMessages as enrichMessagesShared, formatToolArgs, toolLabel, type MsgBlock, type ToolBlock } from '@/utils/messageGroup'
import { useConversationsStore } from '@/stores/conversations'

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
  status: 'running' | 'done' | 'error' | 'denied' | 'confirmation'
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
  // Web conversations for this agent, newest first — the switcher list.
  // Bridge/a2a threads are excluded server-side (ListConversationsByAgent).
  const conversations = ref<ConversationInfo[]>([])
  const messages = ref<AgentMessageInfo[]>([])
  const streamingText = ref('')
  const activeToolCalls = reactive(new Map<string, ToolCall>())
  // Ordered live render list for the in-flight assistant turn: text and
  // tool entries in true emission order (mirrors the persisted blocks[]
  // enrichMessages builds). Text entries hold their own text; tool
  // entries reference activeToolCalls by id for live status/output. The
  // streaming bubble iterates this so the live view interleaves exactly
  // like the finalized/refetched one — no reordering, no finalize snap.
  const streamingBlocks = ref<Array<{ kind: 'text'; text: string } | { kind: 'tool'; toolCallId: string }>>([])
  const pendingConfirmation = ref<Confirmation | null>(null)
  const currentRunId = ref<string | null>(null)
  // The agent this store is bound to (its WS topic == this agent's UUID).
  // Every run/notification envelope is addressed by topicId+conversationId;
  // events not matching this binding belong to a different agent (e.g. an
  // A2A sibling's own run) and are rejected at the edge — no runId guessing.
  const boundAgentId = ref<string | null>(null)
  const sending = ref(false)
  const cancelling = ref(false)
  // Runs the user cancelled locally — late NDJSON events for these runIDs
  // are ignored so the optimistically finalized bubble doesn't repaint
  // with stale tool output. Bounded growth: we only ever add the current
  // runId, and there's at most one in-flight run per conversation.
  const cancelledRunIds = new Set<string>()
  // /compact spawns a real run, but the only meaningful UI output is the
  // checkpoint divider that the backend inserts into the DB. The streamed
  // text-delta ("Context compacted. N tokens freed.") would otherwise land
  // as a regular assistant bubble. When this is set, run.text_delta is
  // ignored and run.complete refetches from the DB so the divider shows.
  const compactRunInFlight = ref(false)
  // Buffers the agent's "Context compacted. N tokens freed." text so we can
  // extract tokensFreed and push a synthetic divider on run.complete.
  const compactReplyBuffer = ref('')
  // Set by tool-call/tool-result; consumed by the next text-delta to insert
  // a \n separator between text blocks across LLM steps. Mirrors how
  // enrichMessages joins persisted per-step rows on refetch.
  let textBlockBoundary = false

  // Extracts the integer N from "Context compacted. N tokens freed." Falls
  // back to 0 when the agent emits a different shape — the divider still
  // renders, just without a token count.
  function extractTokensFreed(text: string): number {
    const m = text.match(/(\d+)\s+tokens?\s+freed/i)
    return m ? Number(m[1]) || 0 : 0
  }

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
  // Drops events for runs the user cancelled locally so the optimistically
  // finalized bubble doesn't repaint as the agent's straggling tool output
  // arrives.
  // The run we're tracking in this (agent, conversation). The address
  // gate already guarantees the event is for the bound agent+conversation,
  // so the only remaining ambiguity is run *sequencing* within this
  // conversation (a delayed event from a previous run, or a duplicate
  // terminal after currentRunId was cleared). runId === currentRunId
  // resolves that precisely — no `sending ⇒ accept any` heuristic.
  function isActiveRun(evRunId: string): boolean {
    if (cancelledRunIds.has(evRunId)) return false
    return evRunId === currentRunId.value
  }

  // Address gate: a run/notification envelope is for this store iff it
  // is on this agent's topic and this conversation. Subagent (A2A
  // sub-run) envelopes carry the parent topic+conversation but a foreign
  // run; until a sub-run UI exists they're dropped here (their data
  // still reaches run_js via the tool return). A foreign agent's events
  // (e.g. an A2A sibling reporting its own run on its own topic) have a
  // different topicId and never reach the handler. This replaces the
  // whole isCurrentRun/cancelledRunIds cross-scope guessing layer.
  // Forward-compat: when envelope.scope lands (user/tenant/system
  // events), also require scope === 'agent' here.
  function onRunMessage(type: string, handler: (payload: unknown) => void) {
    return ws.onMessage(type, (payload, env) => {
      if (!env || env.subagent) return
      if (!boundAgentId.value || env.topicId !== boundAgentId.value) return
      if (conversationId.value) {
        // Known conversation: reject other conversations on this agent.
        // Some terminal events carry no conversationId — allow them; the
        // handler's isActiveRun(runId) check scopes them to our run.
        if (env.conversationId && env.conversationId !== conversationId.value) return
      } else if (env.conversationId && sending.value) {
        // Brand-new web conversation, first prompt in flight: adopt the
        // id the server assigned (HTTP response will also set it).
        conversationId.value = env.conversationId
      } else {
        return
      }
      handler(payload)
    })
  }

  function initListeners() {
    unsubscribers.push(
      // The address gate guarantees this is our agent+conversation; adopt
      // the run and reset stream state (run.started is a run's first
      // event). Covers both user-initiated (HTTP response also sets the
      // id) and server-initiated runs (post-upgrade notification).
      onRunMessage('run.started', (payload) => {
        const ev = tryFromJson<RunStartedEvent>(RunStartedEventSchema, payload)
        if (!ev || cancelledRunIds.has(ev.runId)) return
        currentRunId.value = ev.runId
        streamingText.value = ''
        activeToolCalls.clear()
        streamingBlocks.value = []
        textBlockBoundary = false
      }),
      onRunMessage('run.text_delta', (payload) => {
        const ev = tryFromJson<TextDeltaEvent>(TextDeltaEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        if (compactRunInFlight.value) {
          // Buffer the agent's "Context compacted. N tokens freed." line so
          // we can pull tokensFreed out for the synthetic divider, but
          // don't surface it as a streaming bubble.
          compactReplyBuffer.value += ev.text
          return
        }
        // Ordered live blocks: a tool roundtrip (textBlockBoundary) or a
        // non-text tail starts a new text block; otherwise the delta
        // extends the current one. This is what the streaming bubble
        // renders, so the live order matches the persisted blocks[].
        const tail = streamingBlocks.value[streamingBlocks.value.length - 1]
        if (textBlockBoundary || !tail || tail.kind !== 'text') {
          streamingBlocks.value.push({ kind: 'text', text: ev.text })
        } else {
          tail.text += ev.text
        }
        // streamingText is kept only for empty-state / watcher truthiness
        // now; the bubble renders from streamingBlocks.
        textBlockBoundary = false
        streamingText.value += ev.text
      }),
      onRunMessage('run.tool_call', (payload) => {
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
      onRunMessage('run.tool_result', (payload) => {
        const ev = tryFromJson<ToolResultEvent>(ToolResultEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        textBlockBoundary = true
        // outcome is the structured tool status (success|error|denied)
        // straight from the discriminated output — no text sniffing.
        const status =
          ev.outcome === 'error' ? 'error' : ev.outcome === 'denied' ? 'denied' : 'done'
        const tc = activeToolCalls.get(ev.toolCallId)
        if (tc) {
          tc.output = ev.output
          tc.error = ev.error
          tc.status = status
          return
        }
        // No live entry: the call was already finalized into messages[]
        // (e.g. a resume — the promptAgent call bubble was committed and
        // activeToolCalls cleared on run.started, then the sibling's
        // reply arrives as this result). Patch the finalized bubble so
        // the output renders live, matching what enrichMessages folds in
        // on refresh.
        for (let i = messages.value.length - 1; i >= 0; i--) {
          const blocks = (messages.value[i] as any).blocks as MsgBlock[] | undefined
          const hit = blocks?.find(
            (b): b is Extract<MsgBlock, { kind: 'tool' }> =>
              b.kind === 'tool' && b.toolCallId === ev.toolCallId,
          )
          if (hit) {
            hit.output = ev.output
            hit.error = ev.error
            hit.outcome = (ev.outcome as ToolBlock['outcome']) || ''
            break
          }
        }
      }),
      onRunMessage('run.confirmation_required', (payload) => {
        const ev = tryFromJson<ConfirmationRequiredEvent>(ConfirmationRequiredEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
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
      onRunMessage('run.complete', (payload) => {
        const ev = tryFromJson<RunCompleteEvent>(RunCompleteEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        // Don't finalize if awaiting confirmation — run is suspended, not complete.
        if (pendingConfirmation.value) return
        console.log('[chat] run.complete', { runId: ev.runId, textLen: streamingText.value.length })
        if (compactRunInFlight.value) {
          // Push a synthetic divider locally that mirrors the row the
          // backend persisted in SessionCompact. We avoid a full
          // loadConversation here because it re-runs enrichMessages, which
          // splits previously-bundled run_js tool bubbles (one persisted
          // assistant row per LLM step in the loop).
          const tokensFreed = extractTokensFreed(compactReplyBuffer.value)
          const stamp = ev.runId || Date.now().toString()
          messages.value.push({
            $typeName: 'airlock.v1.AgentMessageInfo',
            id: `compact-${stamp}`,
            role: 'system',
            source: 'checkpoint',
            content: '',
            parts: JSON.stringify([{ type: 'checkpoint', kind: 'compact', tokensFreed }]),
            costEstimate: 0,
          } as any)
          compactRunInFlight.value = false
          compactReplyBuffer.value = ''
          streamingText.value = ''
          activeToolCalls.clear()
          streamingBlocks.value = []
          textBlockBoundary = false
          currentRunId.value = null
          sending.value = false
          return
        }
        finalizeMessage()
      }),
      onRunMessage('run.error', (payload) => {
        const ev = tryFromJson<RunErrorEvent>(RunErrorEventSchema, payload)
        if (!ev || !isActiveRun(ev.runId)) return
        console.warn('[chat] run.error', { runId: ev.runId, error: ev.error })
        // Finalize whatever assistant text streamed before the failure (don't
        // discard partial output) and append a separate source='error' bubble
        // matching the shape airlock persists to agent_messages on RunComplete.
        // The persisted row arrives via DB fetch on refresh; this synth makes
        // the live experience match without waiting.
        compactRunInFlight.value = false
        finalizeMessage()
        const errText = ev.error || 'Run failed.'
        messages.value.push({
          $typeName: 'airlock.v1.AgentMessageInfo',
          id: `error-${ev.runId}`,
          role: 'assistant',
          source: 'error',
          content: errText,
          costEstimate: 0,
        } as any)
      }),
      onRunMessage('run.suspended', () => {
        // Run suspended (e.g., awaiting approval) — keep state as-is.
      }),
      onRunMessage('notification', (payload) => {
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
      // Replay gap: the server couldn't serve the delta since our cursor
      // (buffer rolled or was cleared during a disconnect). Refetch
      // authoritative state from the DB for the bound agent. Topic-scoped
      // only — not run/conversation — so handled directly, not via the
      // address-gated onRunMessage.
      ws.onMessage('resync', (_payload, env) => {
        if (!boundAgentId.value || env?.topicId !== boundAgentId.value) return
        void reloadCurrentThread()
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

  // cancelRun — fired by the streaming bubble's Cancel button. Optimistic
  // UX: finalize the bubble locally with whatever streamed so far and a
  // "(cancelled)" marker, re-enable input. The DELETE call to airlock
  // signals the agent through the dispatcher; the agent's terminal POST
  // and any straggling NDJSON events are ignored client-side via
  // cancelledRunIds. If the DELETE itself fails (404 because the run
  // already finalized server-side), we don't surface it — the optimistic
  // flip already won.
  async function cancelRun() {
    const runId = currentRunId.value
    if (!runId || cancelling.value) return
    cancelling.value = true
    cancelledRunIds.add(runId)
    finalizeMessage({ cancelled: true })

    try {
      await api.delete(`/api/v1/runs/${runId}`)
    } catch (err) {
      // 404 is expected when the run already finalized between the user
      // clicking and the request landing. Other errors aren't actionable
      // here — the optimistic UI flip is what the user sees.
      console.warn('[chat] cancel run failed (ignored)', err)
    } finally {
      cancelling.value = false
    }
  }

  function finalizeMessage(opts?: { cancelled?: boolean }) {
    if (sendingTimeout) { clearTimeout(sendingTimeout); sendingTimeout = null }
    console.log('[chat] finalizeMessage', { textLen: streamingText.value.length, toolCalls: activeToolCalls.size, sending: sending.value, runId: currentRunId.value })

    // If the window has been scrolled back (hasNewer=true), appending new
    // messages would place them out-of-order above evicted history. Drop
    // the just-streamed text/tool output and surface a banner instead; the
    // user clicks to reset to the newest page and see the full exchange.
    if (hasNewer.value) {
      streamingText.value = ''
      activeToolCalls.clear()
      streamingBlocks.value = []
      textBlockBoundary = false
      pendingNotifications.length = 0
      newMessagesPending.value = true
      currentRunId.value = null
      sending.value = false
      return
    }

    // Freeze the ordered live blocks into the same MsgBlock[] shape
    // enrichMessages produces on persisted rows, resolving each tool
    // entry's details from activeToolCalls. Live and refetch paths then
    // render identically and in the same order — no finalize snap.
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

    // Push ONE assistant message carrying the ordered blocks. content is
    // still set (plain-text fallback / non-block consumers) but the
    // renderer prefers blocks. Push even with no text, since a tool-only
    // turn (typical of run_js loops) still has to surface its tools.
    if (blocks.length || streamingText.value || opts?.cancelled) {
      const stamp = currentRunId.value || Date.now().toString()
      const msg: any = {
        $typeName: 'airlock.v1.AgentMessageInfo',
        id: `msg-${stamp}`,
        role: 'assistant',
        content: streamingText.value,
        costEstimate: 0,
      }
      if (blocks.length) msg.blocks = blocks
      // Marker used by the renderer to fade the bubble + show a small
      // "(cancelled)" tag. The persisted assistant row from the agent's
      // r.Complete arrives later and lacks this flag, but by then the
      // user has moved on; the run history view shows the same details
      // when they need to audit.
      if (opts?.cancelled) msg._cancelled = true
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
    streamingBlocks.value = []
    textBlockBoundary = false
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

  // Restore confirmation state from a server-provided pending confirmation
  // (conversation load after a refresh). A delegated A2A confirmation
  // (permission/patterns/code populated) carries its own detail; a direct
  // run_js confirmation describes the call via toolName/input.
  function restorePendingConfirmation(
    pc: { toolCallId: string; toolName: string; input: string; permission?: string; patterns?: string[]; code?: string },
    msgs: AgentMessageInfo[],
  ) {
    const input = formatToolArgs((() => { try { return JSON.parse(pc.input) } catch { return pc.input } })())
    activeToolCalls.set(pc.toolCallId, {
      toolCallId: pc.toolCallId,
      toolName: pc.toolName,
      input,
      output: '',
      error: '',
      status: 'confirmation',
    })
    // Anchor the inline confirmation box to the assistant message bearing
    // this tool call, if the thread has one — and hide that message, since
    // it renders via activeToolCalls instead.
    let anchored = false
    for (let i = msgs.length - 1; i >= 0; i--) {
      if (msgs[i].role === 'assistant' && (msgs[i] as any).blocks?.some((b: any) => b.kind === 'tool' && b.toolCallId === pc.toolCallId)) {
        ;(msgs[i] as any)._hidden = true
        anchored = true
        break
      }
    }
    pendingConfirmation.value = {
      runId: '',
      permission: pc.permission || pc.toolName,
      patterns: pc.patterns ? [...pc.patterns] : [],
      code: pc.code || input,
      // Keep toolCallId only when an assistant message anchors it (drives
      // the inline box). A delegated A2A confirmation's suspending turn is
      // not persisted to the thread, so there's no anchor — blank it and
      // the standalone confirmation card renders instead of nothing.
      toolCallId: anchored ? pc.toolCallId : '',
    }
  }

  // Clear all ephemeral run state. Without this a deleted/!switched
  // thread leaves its streaming text, active tool-call bubbles and
  // pending confirmation on screen — e.g. after deleting the open
  // conversation the empty-state text and a stale permission card
  // render at the same time.
  function resetTransient() {
    streamingText.value = ''
    activeToolCalls.clear()
    streamingBlocks.value = []
    pendingConfirmation.value = null
    currentRunId.value = null
    sending.value = false
    cancelling.value = false
  }

  // Reset the message view to an empty "new conversation" state without
  // touching the conversation list. The next sendMessage with no
  // conversation_id mints a fresh thread server-side.
  function resetThreadView() {
    messages.value = []
    hasOlder.value = false
    hasNewer.value = false
    newMessagesPending.value = false
    resetTransient()
  }

  // Fetch and render one conversation's messages. Assumes the id belongs
  // to a web thread the user owns (the server enforces this).
  async function loadConversationById(convId: string) {
    // Drop the previous thread's in-flight/streaming state before
    // swapping in the new history (restorePendingConfirmation below
    // re-establishes a gate if this thread has a suspended run).
    resetTransient()
    conversationId.value = convId
    const { data: convData } = await api.get(`/api/v1/conversations/${convId}`)
    const convResponse = fromJson(GetConversationResponseSchema, convData)
    messages.value = enrichMessages(convResponse.messages)
    hasOlder.value = convResponse.hasOlderMessages
    hasNewer.value = false
    newMessagesPending.value = false
    if (convResponse.pendingConfirmation) {
      restorePendingConfirmation(convResponse.pendingConfirmation, messages.value)
    }
    // Adopt an already-in-flight run so subsequent WS deltas
    // (run.text_delta / run.tool_call / run.complete) survive the
    // isActiveRun gate, and so the Cancel button is enabled. The
    // pre-join text won't be visible (no replay of streamed deltas) —
    // run.complete will refetch the conversation and the persisted
    // assistant message fills in the gap.
    if (convResponse.inFlightRunId) {
      currentRunId.value = convResponse.inFlightRunId
      sending.value = true
    }
  }

  // Refresh the switcher list (web threads only — bridge/a2a are excluded
  // server-side). Newest first so [0] is the natural default.
  async function refreshConversations(agentId: string): Promise<ConversationInfo[]> {
    const { data } = await api.get(`/api/v1/agents/${agentId}/conversations`)
    const response = fromJson(ListConversationsResponseSchema, data)
    conversations.value = response.conversations
      .filter(c => c.source === 'web')
      .sort((a, b) => Number(b.updatedAt?.seconds ?? 0n) - Number(a.updatedAt?.seconds ?? 0n))
    return conversations.value
  }

  // convId pins a specific thread (sidebar click / ?c= in the URL).
  // Omitted — or naming a thread that no longer exists — opens an empty
  // "new conversation" view rather than resuming the most recent thread,
  // so "New chat" and an agent's Chat button always start fresh. Past
  // threads are reached through the sidebar.
  async function loadConversation(agentId: string, convId?: string) {
    boundAgentId.value = agentId
    const web = await refreshConversations(agentId)
    if (convId && web.some(c => c.id === convId)) {
      await loadConversationById(convId)
    } else {
      conversationId.value = null
      resetThreadView()
    }
  }

  // Re-fetch the active thread (and refresh the switcher list) without
  // switching threads — for a resync, a jump-to-latest, or a slash
  // command that inserted backend rows. Stays on the empty view when no
  // thread is active.
  async function reloadCurrentThread() {
    if (boundAgentId.value) await refreshConversations(boundAgentId.value)
    if (conversationId.value) {
      await loadConversationById(conversationId.value)
    } else {
      resetThreadView()
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
    boundAgentId.value = agentId
    await reloadCurrentThread()
  }

  async function sendMessage(agentId: string, text: string, approved?: boolean, filePaths?: string[]) {
    boundAgentId.value = agentId
    const isResume = approved !== undefined
    // Slash commands (/clear, /compact, ...) are handled synchronously by
    // Airlock — no run is created and no optimistic user bubble should appear.
    const isSlashCommand = !isResume && text.trim().startsWith('/')
    compactRunInFlight.value = !isResume && /^\/compact(\s|$)/.test(text.trim())
    if (compactRunInFlight.value) compactReplyBuffer.value = ''

    if (isResume) {
      // The suspended run's partial turn (assistant text + the tool call
      // that requested confirmation) lives only in transient streaming
      // state: run.complete is skipped while a confirmation is pending,
      // so it was never finalized. The resume's run.started clears
      // activeToolCalls — commit the bubble to messages first or it
      // vanishes until a refresh repopulates it from the DB.
      finalizeMessage()

      // If the user hit Stop on this run before approving/denying, its id
      // is in cancelledRunIds and isActiveRun() filters out every event
      // the resumed run emits (run.started/text_delta/complete) — the
      // backend resumes and finishes but the UI stays stuck on
      // "(cancelled)". Approving/denying is an explicit decision to
      // continue, so drop the cancel guard. Clearing the whole set is
      // safe: event scoping still goes through the currentRunId check in
      // isActiveRun, and a different old run's id can't equal the new
      // resume run's id.
      cancelledRunIds.clear()
      cancelling.value = false
      // Drop the optimistic "(cancelled)" tag cancelRun() stamped on the
      // turn we're now resuming — it's no longer true. (Refresh wouldn't
      // show it either; the DB never had it.)
      for (const m of messages.value) {
        if ((m as any)._cancelled) delete (m as any)._cancelled
      }
    }

    // id of the optimistic user row, so the catch below can roll it back
    // if the prompt POST fails (e.g. 409 on a stopped agent).
    let optimisticID = ''
    if (!isResume && !isSlashCommand) {
      // Add optimistic user message for normal sends only. Skip when the
      // window is scrolled back (hasNewer=true) so we don't insert above
      // evicted history — the user will see their message after clicking
      // "jump to latest."
      if (!hasNewer.value) {
        optimisticID = `pending-${Date.now()}`
        messages.value.push({
          $typeName: 'airlock.v1.AgentMessageInfo',
          id: optimisticID,
          role: 'user',
          content: text,
          costEstimate: 0,
        } as AgentMessageInfo)
      }
      // Reset streaming state for new messages.
      streamingText.value = ''
      activeToolCalls.clear()
      streamingBlocks.value = []
      textBlockBoundary = false
    } else if (approved === false && text && !hasNewer.value) {
      // Deny resume: airlock persists `text` as a source="control"
      // message, but run.complete doesn't reload, so without an
      // optimistic row the confirmation card just vanishes until a
      // refresh. Mirror what the backend will store so the muted label
      // shows immediately; loadConversation later replaces the array
      // wholesale (no dedup needed).
      messages.value.push({
        $typeName: 'airlock.v1.AgentMessageInfo',
        id: `pending-control-${Date.now()}`,
        role: 'user',
        source: 'control',
        content: text,
        costEstimate: 0,
      } as AgentMessageInfo)
    }

    sending.value = true
    pendingConfirmation.value = null

    // Empty/absent conversation_id starts a fresh web thread server-side;
    // an explicit id continues that thread (multi-conversation).
    const wasNew = !conversationId.value
    const payload: Record<string, any> = { message: text }
    if (conversationId.value) payload.conversationId = conversationId.value
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
        await reloadCurrentThread()
        return
      }

      currentRunId.value = response.runId
      if (response.conversationId) {
        conversationId.value = response.conversationId
        // First message of a new thread — pull the freshly-created row
        // (with its server-assigned title) into both the per-agent list
        // and the global sidebar.
        if (wasNew) {
          await refreshConversations(agentId)
          void useConversationsStore().refresh()
        }
      }

      // Safety timeout: if run.complete/run.error never arrives (e.g., WS down),
      // unblock the input so the user isn't stuck.
      if (sendingTimeout) clearTimeout(sendingTimeout)
      sendingTimeout = setTimeout(() => {
        if (sending.value) finalizeMessage()
      }, 5 * 60 * 1000)
    } catch (err) {
      // Roll back the optimistic user row and re-throw so the view can
      // toast the backend's message (e.g. the 409 "agent is stopped"
      // notice) and restore the composer text.
      sending.value = false
      if (optimisticID) {
        messages.value = messages.value.filter(m => m.id !== optimisticID)
      }
      throw err
    }
  }

  function cleanup() {
    for (const unsub of unsubscribers) unsub()
    unsubscribers.length = 0
    boundAgentId.value = null
    conversationId.value = null
    conversations.value = []
    messages.value = []
    streamingText.value = ''
    activeToolCalls.clear()
    streamingBlocks.value = []
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
    streamingBlocks,
    activeToolCalls,
    pendingConfirmation,
    currentRunId,
    sending,
    cancelling,
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
    cancelRun,
    cleanup,
  }
})
