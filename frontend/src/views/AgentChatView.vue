<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useChatStore } from '@/stores/chat'
import { useAgentsStore } from '@/stores/agents'
import { ws } from '@/api/ws'
import { useMarkdown, renderMarkdown } from '@/composables/useMarkdown'
import { toolLabel, toolDescription } from '@/utils/messageGroup'
import api from '@/api/client'
import MessageParts from '@/components/chat/MessageParts.vue'
import ToolBadge from '@/components/chat/ToolBadge.vue'
import { buildBadgeText } from '@/utils/buildBadge'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const chat = useChatStore()
const agentsStore = useAgentsStore()

// Reactive: the sidebar can navigate between agents/conversations without
// remounting this view (same route record), so read the param live.
const agentId = computed(() => route.params.id as string)
const routeConvId = computed(() => (route.query.c as string) || undefined)
const agentName = computed(
  () => agentsStore.agents.find(a => a.id === agentId.value)?.name || '',
)
// A stopped agent won't auto-resume; prompting it 409s server-side. Gate
// the composer up front and offer a Start affordance instead.
const agentStopped = computed(
  () => agentsStore.agents.find(a => a.id === agentId.value)?.status === 'stopped',
)

// Build-in-progress badge: links to the dedicated Build page. Status comes
// from the agents store (kept fresh by the agent.build listener below); task
// counts ride the same events.
const buildActive = computed(() => {
  const a = agentsStore.agents.find(x => x.id === agentId.value)
  return a?.status === 'building' || a?.upgradeStatus === 'building'
})
const activeBuildId = ref<string | undefined>(undefined)
const buildTasksDone = ref(0)
const buildTasksTotal = ref(0)
const buildPhase = ref('')
const buildBadgeLabel = computed(() => buildBadgeText(buildPhase.value, buildTasksDone.value, buildTasksTotal.value))
let unsubBuild: (() => void) | null = null

const starting = ref(false)
async function startAgent() {
  starting.value = true
  try {
    await agentsStore.startAgent(agentId.value)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Start failed', life: 5000 })
  } finally {
    starting.value = false
  }
}
// No active conversation id yet — the next message mints the thread.
const isNewConversation = computed(() => !chat.conversationId)
const messageInput = ref('')
const messageInputRef = ref<any>(null)

// PrimeVue's autoResize only recomputes on a real `input` event, so clearing
// the model in code (e.g. after send) leaves a multi-line box stretched. Reset
// the inline height so an empty composer collapses back to a single row.
function resetComposerHeight() {
  nextTick(() => {
    const el = messageInputRef.value?.$el as HTMLTextAreaElement | undefined
    if (el) el.style.height = 'auto'
  })
}
const scrollContainer = ref<HTMLElement | null>(null)
const topSentinel = ref<HTMLElement | null>(null)
const bottomSentinel = ref<HTMLElement | null>(null)
const attachedFiles = ref<{ path: string; filename: string }[]>([])
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
let topObserver: IntersectionObserver | null = null
let bottomObserver: IntersectionObserver | null = null

async function reload() {
  try {
    await chat.loadConversation(agentId.value, routeConvId.value)
  } catch {
    // No conversation yet — empty state is fine.
  }
  await nextTick()
  scrollToBottom()
}

onMounted(async () => {
  // WS subscriptions are server-driven — the socket auto-subscribes to every
  // agent this user is a member of at connect time. No client subscribe call.
  chat.initListeners()
  // The sidebar (AppLayout) usually has these loaded already; fetch on a
  // deep-link/hard-refresh so the empty-state can name the agent.
  if (agentsStore.agents.length === 0) agentsStore.fetchAgents().catch(() => {})

  // Track build progress for the badge + keep the store agent's status fresh
  // so the badge appears/disappears as a build runs.
  unsubBuild = ws.onMessage('agent.build', (payload: any) => {
    if (payload?.agentId !== agentId.value) return
    if (payload.buildId) activeBuildId.value = payload.buildId
    buildTasksDone.value = payload.tasksDone ?? 0
    buildTasksTotal.value = payload.tasksTotal ?? 0
    buildPhase.value = payload.phase ?? ''
    const a = agentsStore.agents.find(x => x.id === agentId.value)
    if (!a) return
    if (payload.status === 'started') {
      if (a.status === 'draft' || a.status === 'failed') a.status = 'building'
      else a.upgradeStatus = 'building'
    } else if (payload.status === 'complete') {
      a.status = 'active'
      a.upgradeStatus = 'idle'
    } else if (payload.status === 'failed' || payload.status === 'cancelled' || payload.status === 'refused') {
      a.upgradeStatus = 'idle'
      if (a.status === 'building') a.status = 'failed'
    }
  })

  await reload()
  setupSentinelObservers()

  // Mobile soft keyboard: opening/closing resizes the visual viewport. The
  // send-time autoscroll runs while the keyboard is still up (short viewport);
  // when it dismisses the area grows but scrollTop stays, leaving the latest
  // bubble stranded above the bottom. Re-pin on viewport resize.
  const vv = window.visualViewport
  if (vv) vv.addEventListener('resize', onViewportResize)
  else window.addEventListener('resize', onViewportResize)
})

// Sidebar navigation reuses this view: reload when the agent or the
// selected conversation (?c=) changes.
//
// One exception: when the first message of a brand-new thread lands,
// the chat.conversationId watcher below stamps that id into the URL
// (?c=newId). That stamp changes routeConvId here and would otherwise
// fire reload() mid-stream — loadConversationById runs resetTransient,
// which wipes streamingText/currentRunId/sending, killing the live
// bubble and dropping every text_delta that's already in flight. The
// run resumes (loadConversationById restores currentRunId from
// inFlightRunId) but streamingText is empty, so the bubble only ever
// shows the second half until the next refresh.
//
// Skip the reload when the new routeConvId already matches the store's
// conversation — that case is always our own URL echo, never a user
// navigation.
watch(
  () => [agentId.value, routeConvId.value],
  (cur, prev) => {
    if (cur[0] === prev[0] && cur[1] === prev[1]) return
    if (cur[0] === prev[0] && cur[1] && cur[1] === chat.conversationId) return
    reload()
  },
)

// Keep the URL in sync with the active thread so refresh/back and the
// sidebar highlight track it — especially after the first message of a
// brand-new conversation mints an id.
watch(
  () => chat.conversationId,
  (id) => {
    if (id && id !== routeConvId.value) {
      router.replace({ query: { ...route.query, c: id } })
    }
  },
)

onUnmounted(() => {
  topObserver?.disconnect()
  bottomObserver?.disconnect()
  const vv = window.visualViewport
  if (vv) vv.removeEventListener('resize', onViewportResize)
  else window.removeEventListener('resize', onViewportResize)
  chat.cleanup()
  unsubBuild?.()
})

// IntersectionObserver sentinels at the top and bottom of the message list.
// The top one fires loadOlder when the user scrolls to historical content;
// the bottom one fires loadNewer when the user scrolls back down into a
// region that was evicted from the window.
function setupSentinelObservers() {
  if (!scrollContainer.value) return
  topObserver?.disconnect()
  bottomObserver?.disconnect()

  topObserver = new IntersectionObserver(async (entries) => {
    if (!entries[0].isIntersecting) return
    if (!chat.hasOlder || chat.loadingOlder) return
    // Anchor scroll to the content that was under the user's eye before
    // the prepend so the viewport doesn't jump.
    const el = scrollContainer.value
    if (!el) return
    const anchor = el.scrollHeight - el.scrollTop
    const prepended = await chat.loadOlder()
    if (prepended > 0) {
      await nextTick()
      el.scrollTop = el.scrollHeight - anchor
    }
  }, { root: scrollContainer.value, rootMargin: '200px 0px 0px 0px' })
  if (topSentinel.value) topObserver.observe(topSentinel.value)

  bottomObserver = new IntersectionObserver(async (entries) => {
    if (!entries[0].isIntersecting) return
    if (!chat.hasNewer || chat.loadingNewer) return
    await chat.loadNewer()
  }, { root: scrollContainer.value, rootMargin: '0px 0px 200px 0px' })
  if (bottomSentinel.value) bottomObserver.observe(bottomSentinel.value)
}

watch(
  () => [topSentinel.value, bottomSentinel.value],
  () => setupSentinelObservers(),
)

async function jumpToLatest() {
  await chat.jumpToLatest(agentId.value)
  await nextTick()
  scrollToBottom()
}

// Auto-scroll on new messages, streaming text, tool calls, or confirmations —
// but not when the user is scrolled into history (hasNewer=true) or is
// actively loading older messages. Otherwise prepend/eviction would yank
// their viewport to the bottom.
watch(
  () => [chat.messages.length, chat.streamingText, chat.streamingBlocks.length, chat.activeToolCalls.size, chat.pendingConfirmation],
  () => nextTick(() => {
    if (chat.hasNewer || chat.loadingOlder) return
    scrollToBottom()
  }),
)

function scrollToBottom() {
  if (scrollContainer.value) {
    scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight
  }
}

// Re-pin to the bottom only when the visual viewport GROWS — i.e. the mobile
// keyboard was dismissed (e.g. after a send), which otherwise leaves the last
// bubble stranded above the bottom. On shrink (keyboard opening) we leave the
// scroll alone so a short, top-anchored conversation isn't shoved up under the
// top bar. rAF so we read scrollHeight after the layout reflowed.
let prevViewportH = window.visualViewport?.height ?? window.innerHeight
function onViewportResize() {
  const h = window.visualViewport?.height ?? window.innerHeight
  const grew = h > prevViewportH + 1
  prevViewportH = h
  if (!grew) return
  if (chat.hasNewer || chat.loadingOlder) return
  requestAnimationFrame(scrollToBottom)
}

async function send() {
  const text = messageInput.value.trim()
  if (!text || chat.sending) return
  const sentFiles = attachedFiles.value.slice()
  const filePaths = sentFiles.map(f => f.path)
  messageInput.value = ''
  attachedFiles.value = []
  resetComposerHeight()
  try {
    await chat.sendMessage(agentId.value, text, undefined, filePaths.length ? filePaths : undefined)
  } catch (err: any) {
    // Restore the composer so the user doesn't lose their text/attachments
    // on a rejected send (e.g. 409 when the agent is stopped).
    messageInput.value = messageInput.value ? `${text}\n${messageInput.value}` : text
    attachedFiles.value = sentFiles
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Send failed', life: 5000 })
  }
}

async function onFileSelect(e: Event) {
  const input = e.target as HTMLInputElement
  const files = input.files
  if (!files?.length) return
  uploading.value = true
  try {
    for (const file of files) {
      const form = new FormData()
      form.append('file', file)
      const { data } = await api.post(`/api/v1/agents/${agentId.value}/files`, form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      attachedFiles.value.push({ path: data.path, filename: data.filename || file.name })
    }
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Upload failed', life: 5000 })
  } finally {
    uploading.value = false
    input.value = ''
  }
}

function removeFile(index: number) {
  attachedFiles.value.splice(index, 1)
}

async function approve() {
  try {
    await chat.sendMessage(agentId.value, '', true)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Approval failed', detail: err.response?.data?.error, life: 5000 })
  }
}

async function reject() {
  // Don't clear pendingConfirmation here — sendMessage reads its runId to tell
  // the backend which run to resume, then clears it itself.
  try {
    await chat.sendMessage(agentId.value, 'Rejected by user.', false)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Rejection failed', detail: err.response?.data?.error, life: 5000 })
  }
}

function onKeydown(e: KeyboardEvent) {
  // Desktop: Enter sends, Shift+Enter inserts a newline. Mobile keyboards let
  // Enter be a newline and use the on-screen Send button. Pointer capabilities
  // do not identify mobile devices because touch-enabled desktops are common.
  if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return
  if (/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent)) return
  e.preventDefault()
  send()
}

// Format tool input JSON for display — strips metadata keys and shows just the value for single-arg tools.
const metaKeys = new Set(['request_confirmation', 'description'])

function formatToolInput(raw: string): string {
  try {
    const args = JSON.parse(raw)
    if (args && typeof args === 'object') {
      const displayKeys = Object.keys(args).filter(k => !metaKeys.has(k))
      if (displayKeys.length === 1) return String(args[displayKeys[0]])
      if (displayKeys.length < Object.keys(args).length) {
        const filtered: Record<string, any> = {}
        for (const k of displayKeys) filtered[k] = args[k]
        return prettyArgs(filtered)
      }
    }
    return prettyArgs(args)
  } catch {
    return raw
  }
}

// Pretty-print args without escaping newlines inside string values.
function prettyArgs(obj: any): string {
  if (typeof obj !== 'object' || obj === null) return String(obj)
  const entries = Object.entries(obj)
  return entries.map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`).join('\n')
}

// Ordered live render units for the in-flight turn: text blocks carry
// their markdown source; tool blocks resolve their live ToolCall (status,
// output) from the reactive activeToolCalls map by id. Iterating this in
// the template renders the streaming turn in true emission order, the
// same as the persisted/finalized blocks[].
const streamingRender = computed(() =>
  chat.streamingBlocks.map((b) => {
    if (b.kind === 'text') return { kind: 'text' as const, text: b.text }
    const tc = chat.activeToolCalls.get(b.toolCallId)
    return {
      kind: 'tool' as const,
      tc,
      label: tc ? toolLabel(tc.toolName, tc.input) : 'tool',
    }
  }),
)

// Checkpoint markers (source === 'checkpoint') are rendered as a horizontal
// divider instead of a message bubble. Each marker carries a single part
// describing the checkpoint kind ("clear" | "compact") and how many tokens
// were freed at that point.
interface CheckpointInfo {
  kind: string
  tokensFreed: number
}

function checkpointInfo(msg: any): CheckpointInfo | null {
  if (msg.source !== 'checkpoint' || !msg.parts) return null
  try {
    const parts = typeof msg.parts === 'string' ? JSON.parse(msg.parts) : msg.parts
    if (!Array.isArray(parts)) return null
    const p = parts[0]
    if (!p || p.type !== 'checkpoint') return null
    return { kind: p.kind || 'clear', tokensFreed: Number(p.tokensFreed) || 0 }
  } catch {
    return null
  }
}

function checkpointLabel(kind: string): string {
  return kind === 'compact' ? 'compacted' : 'context cleared'
}

function formatTokens(n: number): string {
  return n.toLocaleString()
}
</script>

<template>
  <div class="chat-root">
    <!-- The dedicated chat header was removed; the back affordance lives
         in the app top bar (AppLayout) for chat routes so we don't burn a
         row inside the chat view itself. -->

    <!-- Conversation selection (list, new, delete) lives in the app
         sidebar now — this view is just the active thread. -->

    <!-- Build-in-progress banner → links to the dedicated Build page. -->
    <RouterLink
      v-if="buildActive && activeBuildId"
      :to="{ name: 'build-detail', params: { id: agentId, buildId: activeBuildId } }"
      class="chat-build-banner"
    >
      <i class="pi pi-spin pi-spinner" />
      <span>{{ buildBadgeLabel }}</span>
      <i class="pi pi-arrow-right" style="font-size: 0.75rem; margin-left: auto" />
    </RouterLink>

    <!-- Jump-to-latest banner: shown when new agent output arrived while the
         user was scrolled into history. Clicking resets the window. -->
    <div v-if="chat.newMessagesPending" class="chat-jump-banner" @click="jumpToLatest">
      <i class="pi pi-arrow-down" />
      <span>New messages - click to jump to latest</span>
    </div>

    <!-- Message area -->
    <div ref="scrollContainer" class="chat-messages">
        <!-- Empty state — name the agent so the user knows which one this
             not-yet-saved thread will belong to (the row appears in the
             sidebar only once the first message is sent). -->
        <div v-if="chat.messages.length === 0 && !chat.streamingText" class="chat-empty">
          <i class="pi pi-comments" />
          <p class="chat-empty-title">
            {{ isNewConversation ? 'New conversation' : 'Conversation' }}
            with <strong>{{ agentName || 'this app' }}</strong>
          </p>
          <p class="chat-empty-sub">
            Send a message to begin - it's saved as a new conversation once you do.
          </p>
        </div>

        <!-- Top sentinel — when visible, fetch older page via IntersectionObserver. -->
        <div ref="topSentinel" class="chat-sentinel">
          <div v-if="chat.loadingOlder" class="chat-sentinel-loading">
            <i class="pi pi-spin pi-spinner" />
            <span>Loading earlier messages…</span>
          </div>
        </div>

        <!-- Messages -->
        <template v-for="msg in chat.messages" :key="msg.id">
          <!-- Checkpoint dividers (/clear, auto-compact) -->
          <div
            v-if="checkpointInfo(msg)"
            class="chat-checkpoint"
          >
            <span class="chat-checkpoint-line" />
            <span class="chat-checkpoint-label">
              {{ checkpointLabel(checkpointInfo(msg)!.kind) }} · {{ formatTokens(checkpointInfo(msg)!.tokensFreed) }} tokens freed
            </span>
            <span class="chat-checkpoint-line" />
          </div>
          <!-- Tool-result fallback: persisted tool messages whose parent
               assistant we couldn't fold into (legacy / orphan rows).
               Folded rows are marked _hidden by enrichMessages. -->
          <div
            v-else-if="msg.role === 'tool' && !(msg as any)._hidden"
            class="msg-response"
          >
            <ToolBadge
              :label="toolLabel((msg as any).toolName || 'tool')"
              :tool-name="(msg as any).toolName"
              :input="(msg as any).toolInput"
              :output="msg.content"
            />
          </div>
          <!-- System messages (upgrade notifications, etc.) -->
          <div
            v-else-if="msg.source === 'system'"
            style="display: flex; justify-content: flex-start"
          >
            <div class="msg-bubble msg-system">
              <div style="display: flex; align-items: center; gap: 0.5rem">
                <i class="pi pi-sync" style="font-size: 0.7rem; opacity: 0.6" />
                <span style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">System</span>
              </div>
              <div style="margin-top: 0.25rem; font-size: 0.85rem">{{ msg.content }}</div>
            </div>
          </div>
          <!-- Upgrade-success messages (single message synthesized by
               airlock from the agent-builder's exit-tool summary; no
               follow-up LLM turn fires). -->
          <div
            v-else-if="msg.source === 'upgrade'"
            style="display: flex; justify-content: flex-start"
          >
            <div class="msg-bubble msg-system">
              <div style="display: flex; align-items: center; gap: 0.5rem">
                <i class="pi pi-arrow-circle-up" style="font-size: 0.7rem; opacity: 0.7" />
                <span style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">Upgrade</span>
              </div>
              <div style="margin-top: 0.25rem; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word">{{ msg.content }}</div>
            </div>
          </div>
          <!-- Run-error messages (synthesized by airlock when a run completes
               with status=error). Persists across refresh, unlike the
               transient WS-driven banner that the chat store paints inline. -->
          <div
            v-else-if="msg.source === 'error'"
            style="display: flex; justify-content: flex-start"
          >
            <div class="msg-bubble msg-error">
              <div style="display: flex; align-items: center; gap: 0.5rem">
                <i class="pi pi-exclamation-triangle" style="font-size: 0.7rem" />
                <span style="font-size: 0.7rem; text-transform: uppercase">Error</span>
              </div>
              <div style="margin-top: 0.25rem; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word">{{ msg.content }}</div>
            </div>
          </div>
          <!-- Control messages (e.g. the "Rejected by user." re-reason
               nudge sol persists on deny). It's a signal for the model,
               not something the human typed — render a muted inline
               label, not a user bubble. -->
          <div
            v-else-if="msg.source === 'control'"
            style="display: flex; justify-content: flex-start"
          >
            <div
              style="display: flex; align-items: center; gap: 0.4rem; font-size: 0.72rem; opacity: 0.5; padding: 0.15rem 0.5rem"
            >
              <i class="pi pi-ban" style="font-size: 0.7rem" />
              <span>{{ msg.content }}</span>
            </div>
          </div>
          <!-- Notification messages (printToUser / topic publish / user upload echo) — rich parts -->
          <div
            v-else-if="msg.source === 'notification' || msg.source === 'upload'"
            :style="{ display: 'flex', justifyContent: msg.source === 'upload' ? 'flex-end' : 'flex-start' }"
          >
            <div :class="['msg-bubble', msg.source === 'upload' ? 'msg-user' : 'msg-notification']">
              <MessageParts
                v-if="(msg as any).displayParts && (msg as any).displayParts.length"
                :parts="(msg as any).displayParts"
              />
              <div v-else style="font-size: 0.85rem">{{ msg.content }}</div>
            </div>
          </div>
          <!-- User / assistant content. Assistant turns carry an ordered
               blocks[] (text / tool, interleaved exactly as the model
               emitted them — built by enrichMessages from the persisted
               rows' parts, or by finalizeMessage from the live stream).
               Render blocks in order; no tools-first reordering. Plain
               user/text rows without blocks fall back to content. -->
          <div
            v-else-if="(msg.content || (msg as any).blocks?.length || (msg as any)._cancelled) && !(msg as any)._hidden"
            :class="{ 'msg-row-user': msg.role === 'user' }"
            :style="{
              display: 'flex',
              justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
            }"
          >
            <div
              :class="msg.role === 'user' ? ['msg-bubble', 'msg-user'] : ['msg-response']"
              :style="(msg as any)._cancelled ? { opacity: 0.6 } : undefined"
            >
              <div v-if="(msg as any).blocks?.length" :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
                <template v-for="(b, bi) in (msg as any).blocks" :key="bi">
                  <div
                    v-if="b.kind === 'text' && b.text"
                    v-html="renderMarkdown(b.text)"
                    class="chat-bubble"
                  />
                  <ToolBadge
                    v-else-if="b.kind === 'tool'"
                    :label="b.label"
                    :tool-name="b.toolName"
                    :input="b.input"
                    :description="b.description"
                    :output="b.output"
                    :error="b.error"
                    :outcome="b.outcome"
                  />
                </template>
              </div>
              <div
                v-else-if="msg.content"
                v-html="useMarkdown(computed(() => msg.content)).html.value"
                class="chat-bubble"
              />
              <div
                v-if="(msg as any)._cancelled"
                style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.5; margin-top: 0.5rem; font-style: italic"
              >
                (cancelled)
              </div>
            </div>
          </div>
        </template>

        <!-- Bottom sentinel — triggers loadNewer when the user scrolls into
             a tail that was evicted from the window. -->
        <div ref="bottomSentinel" class="chat-sentinel">
          <div v-if="chat.loadingNewer" class="chat-sentinel-loading">
            <i class="pi pi-spin pi-spinner" />
            <span>Loading newer messages…</span>
          </div>
        </div>

        <!-- Streaming response. Rendered strictly in emission order from
             streamingBlocks (text / tool interleaved) — same shape as the
             finalized/persisted blocks[], so there's no reordering and no
             visual snap when the run completes. -->
        <div v-if="streamingRender.length" style="display: flex; justify-content: flex-start">
          <div class="msg-response">
            <div :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
              <template v-for="(entry, ei) in streamingRender" :key="ei">
                <div
                  v-if="entry.kind === 'text' && entry.text"
                  v-html="renderMarkdown(entry.text)"
                  class="chat-bubble"
                />
                <template v-else-if="entry.kind === 'tool' && entry.tc">
                  <ToolBadge
                    :label="entry.label"
                    :tool-name="entry.tc.toolName"
                    :input="formatToolInput(entry.tc.input)"
                    :description="toolDescription(entry.tc.input)"
                    :output="entry.tc.output"
                    :error="entry.tc.error"
                    :status="entry.tc.status"
                    :force-expanded="!!(chat.pendingConfirmation && chat.pendingConfirmation.toolCallId === entry.tc.toolCallId)"
                  />
                  <!-- Inline confirmation — the user is being asked to
                       approve THIS tool call; keep it always visible. -->
                  <div v-if="chat.pendingConfirmation && chat.pendingConfirmation.toolCallId === entry.tc.toolCallId" class="confirmation-box">
                    <div style="display: flex; align-items: center; justify-content: space-between">
                      <span style="font-size: 0.8rem; font-weight: 500">Allow this action?</span>
                      <div style="display: flex; gap: 0.5rem">
                        <Button label="Reject" severity="secondary" size="small" @click="reject" />
                        <Button label="Approve" severity="success" size="small" @click="approve" />
                      </div>
                    </div>
                  </div>
                </template>
              </template>
            </div>
            <!-- Cancel button. Hidden when a confirmation is awaiting the
                 user (Approve/Reject is the relevant action then). The run
                 has an absolute ceiling on the server (PromptHTTPCeiling);
                 the user cancels manually if they want to stop earlier. -->
            <div
              v-if="!chat.pendingConfirmation && chat.currentRunId"
              :style="{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.5rem', marginTop: '0.5rem' }"
            >
              <Button
                label="Cancel"
                severity="secondary"
                size="small"
                :loading="chat.cancelling"
                @click="chat.cancelRun"
              />
            </div>
          </div>
        </div>

        <!-- Fallback confirmation card (when toolCallId not available) -->
        <div v-if="chat.pendingConfirmation && !chat.pendingConfirmation.toolCallId" style="padding: 0.5rem">
          <Message severity="warn" :closable="false">
            <div style="margin-bottom: 0.75rem">
              <strong>Confirmation required</strong>
              <div v-if="chat.pendingConfirmation.description" style="margin-top: 0.25rem">{{ chat.pendingConfirmation.description }}</div>
              <span v-else>: {{ chat.pendingConfirmation.permission }}</span>
            </div>
            <pre v-if="chat.pendingConfirmation.code" class="code-chip" style="white-space: pre-wrap; font-size: 0.8rem; padding: 0.5rem; margin-bottom: 0.75rem">{{ chat.pendingConfirmation.code }}</pre>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end">
              <Button label="Reject" severity="secondary" size="small" @click="reject" />
              <Button label="Approve" severity="success" size="small" @click="approve" />
            </div>
          </Message>
        </div>
    </div>

    <!-- Composer: floats over the bottom of the chat. The message list
         scrolls behind it and fades out into the gradient, so the transcript
         disappears under the input instead of peeking around it. No top
         divider — the fade is the separation. -->
    <div class="chat-composer">
      <!-- Attached files -->
      <div v-if="attachedFiles.length" class="composer-files">
        <Chip
          v-for="(file, i) in attachedFiles"
          :key="file.path"
          :label="file.filename"
          removable
          @remove="removeFile(i)"
        />
      </div>

      <!-- Stopped-agent banner: chatting is blocked until an admin starts it -->
      <div v-if="agentStopped" class="composer-stopped">
        <span style="font-size: 0.875rem">This app is stopped. Start it to chat.</span>
        <Button
          label="Start"
          icon="pi pi-play"
          size="small"
          :loading="starting"
          @click="startAgent"
        />
      </div>

      <!-- Input box: attach + textarea + send all live inside one rounded box -->
      <div class="composer-box">
        <input ref="fileInput" type="file" multiple hidden @change="onFileSelect" />
        <Button
          class="composer-btn"
          icon="pi pi-paperclip"
          severity="secondary"
          text
          rounded
          :disabled="chat.sending || uploading || agentStopped"
          :loading="uploading"
          @click="fileInput?.click()"
        />
        <Textarea
          ref="messageInputRef"
          v-model="messageInput"
          :placeholder="agentStopped ? 'App is stopped' : 'Type a message...'"
          :auto-resize="true"
          rows="1"
          :disabled="agentStopped"
          @keydown="onKeydown"
        />
        <Button
          class="composer-btn"
          icon="pi pi-send"
          rounded
          :disabled="!messageInput.trim() || chat.sending || agentStopped"
          @click="send"
        />
      </div>
    </div>
  </div>
</template>

<style>
.chat-bubble ul,
.chat-bubble ol {
  padding-left: 1.25rem;
  margin: 0.25rem 0;
}

.chat-bubble pre {
  overflow-x: auto;
  max-width: 100%;
  background: rgba(0, 0, 0, 0.06);
  border-radius: 0.375rem;
  padding: 0.5rem 0.75rem;
  margin: 0.5rem 0;
  font-size: 0.85rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}

:root.dark .chat-bubble pre {
  background: rgba(255, 255, 255, 0.08);
}

.chat-bubble code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.85em;
}

.chat-bubble :not(pre) > code {
  background: rgba(0, 0, 0, 0.06);
  border-radius: 0.25rem;
  padding: 0.1rem 0.3rem;
}

:root.dark .chat-bubble :not(pre) > code {
  background: rgba(255, 255, 255, 0.08);
}

.confirmation-box {
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--p-surface-200);
}

:root.dark .confirmation-box {
  border-top-color: var(--p-surface-600);
}

.chat-bubble p {
  margin: 0.25rem 0;
}

/* GFM tables: marked emits a real <table>; without these the browser
   default (no border-collapse, no padding) renders cramped/misaligned. */
.chat-bubble table {
  border-collapse: collapse;
  margin: 0.5rem 0;
  font-size: 0.85rem;
  /* size to content but never overflow the bubble — scroll instead. */
  display: block;
  width: max-content;
  max-width: 100%;
  overflow-x: auto;
}

.chat-bubble th,
.chat-bubble td {
  border: 1px solid var(--p-surface-300);
  padding: 0.35rem 0.6rem;
  text-align: left;
  vertical-align: top;
}

.chat-bubble th {
  font-weight: 600;
  background: rgba(0, 0, 0, 0.04);
}

:root.dark .chat-bubble th,
:root.dark .chat-bubble td {
  border-color: var(--p-surface-600);
}

:root.dark .chat-bubble th {
  background: rgba(255, 255, 255, 0.06);
}
</style>

<style scoped>
.chat-root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
  /* Positioning context for the floating composer. */
  position: relative;
}

.chat-empty {
  text-align: center;
  padding: 3rem 1.5rem;
  color: var(--p-text-muted-color);
}

.chat-empty .pi-comments {
  font-size: 2.5rem;
  margin-bottom: 1rem;
  opacity: 0.6;
}

.chat-empty-title {
  font-size: 1.1rem;
  color: var(--p-text-color);
  margin: 0 0 0.35rem;
}

.chat-empty-sub {
  font-size: 0.875rem;
  margin: 0;
}

.msg-bubble {
  max-width: 70%;
  min-width: 0;
  overflow-wrap: break-word;
  padding: 0.5rem 0.75rem;
  border-radius: 0.75rem;
}

/* Tighten the spacing around the user's bubble to half the list gap. The
   list uses a 1rem flex gap between every turn; negative vertical margin on
   the user row pulls its neighbours in to ~0.5rem above and below. */
.msg-row-user {
  margin-top: -0.5rem;
  margin-bottom: -0.5rem;
}

/* Don't pull the very first bubble up — the negative top margin would drag it
   under the top bar. Only tighten between siblings. */
.msg-row-user:first-child {
  margin-top: 0;
}

.msg-user {
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
}

/* Links in the user bubble sit on the primary-colour background. Default
   link / :visited colours (esp. the purple visited state in dark mode)
   blend into the dark-blue bubble — force the bubble's contrast colour
   and underline so they stay readable regardless of visited state. */
.msg-user :deep(a),
.msg-user :deep(a:visited) {
  color: var(--p-primary-contrast-color);
  text-decoration: underline;
}

/* Assistant replies render bare — no bubble, flat transcript. width:100%
   (not shrink-to-fit) so the response column is a stable width: tool
   badges and text are sized by the chat area, never stretched to match a
   long sibling message in the same turn. */
.msg-response {
  width: 100%;
  min-width: 0;
  overflow-wrap: break-word;
}

.msg-system {
  background-color: var(--p-surface-100);
  color: var(--p-text-color);
  border: 1px dashed var(--p-surface-300);
}

:root.dark .msg-system {
  background-color: var(--p-surface-800);
  border-color: var(--p-surface-600);
}

.msg-notification {
  background-color: var(--p-content-hover-background);
  color: var(--p-text-color);
  max-width: 80%;
}

.msg-error {
  background-color: var(--p-red-50);
  color: var(--p-red-700);
  border: 1px solid var(--p-red-200);
  max-width: 80%;
}

:root.dark .msg-error {
  background-color: color-mix(in srgb, var(--p-red-500) 12%, transparent);
  color: var(--p-red-300);
  border-color: color-mix(in srgb, var(--p-red-500) 30%, transparent);
}

.chat-messages {
  flex: 1 1 0;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  /* Bottom space so the last message can scroll clear of the floating
     composer instead of sitting permanently behind it. */
  padding: 0.25rem 1rem 3.75rem;
}

/* Floating composer overlaid on the bottom of the scroll area. */
.chat-composer {
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 1rem 1rem 0.5rem;
  /* Opaque fade: messages scrolling up dissolve into the page background as
     they approach the input rather than peeking around the floating box. The
     gradient itself is click-through so the transcript behind it stays
     scrollable; only the interactive children below opt back in. */
  background: linear-gradient(to top, var(--p-content-background) 60%, transparent);
  pointer-events: none;
}

.chat-composer > * {
  pointer-events: auto;
}

.composer-files {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.composer-stopped {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--p-surface-300);
  border-radius: 6px;
  background: var(--p-surface-100);
}

:root.dark .composer-stopped {
  border-color: var(--p-surface-600);
  background: var(--p-surface-800);
}

.composer-box {
  display: flex;
  align-items: flex-end;
  gap: 0.25rem;
  padding: 0.3rem 0.4rem;
  border: 1px solid var(--p-surface-300);
  border-radius: 1.4rem;
  background: var(--p-content-background);
  box-shadow: 0 2px 16px rgba(0, 0, 0, 0.12);
}

:root.dark .composer-box {
  border-color: var(--p-surface-600);
  box-shadow: 0 2px 16px rgba(0, 0, 0, 0.45);
}

/* Strip the textarea's own chrome so it reads as part of the box, not a
   nested control. Kill the focus ring too — the box owns the boundary. */
.composer-box :deep(.p-textarea) {
  flex: 1 1 auto;
  align-self: center;
  border: none;
  background: transparent;
  box-shadow: none !important;
  resize: none;
  padding: 0.5rem 0.4rem;
  max-height: 40vh;
}

.composer-btn {
  flex-shrink: 0;
}

/* Desktop (sidebar layout) — the tight mobile inset looks cramped on a wide
   column, so widen the horizontal gutters. Mirrors AppLayout's
   max-width:768px mobile breakpoint. Top/bottom padding is untouched. */
@media (min-width: 769px) {
  .chat-messages {
    padding-left: 2.5rem;
    padding-right: 2.5rem;
  }
  .chat-composer {
    padding-left: 2.5rem;
    padding-right: 2.5rem;
  }
}

.chat-checkpoint {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 0.25rem 0;
}

.chat-checkpoint-line {
  flex: 1 1 auto;
  height: 1px;
  background-color: var(--p-surface-300);
}

:root.dark .chat-checkpoint-line {
  background-color: var(--p-surface-600);
}

.chat-checkpoint-label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--p-text-muted-color);
  white-space: nowrap;
}

.chat-sentinel {
  min-height: 1px;
}

.chat-sentinel-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem;
  font-size: 0.8rem;
  color: var(--p-text-muted-color);
}

.chat-jump-banner {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  margin: 0.25rem 0;
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
  border-radius: 1rem;
  font-size: 0.85rem;
  cursor: pointer;
  align-self: center;
}

.chat-jump-banner:hover {
  opacity: 0.9;
}

.chat-build-banner {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.9rem;
  margin: 0.25rem 0.75rem;
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
  border-radius: 0.75rem;
  font-size: 0.85rem;
  font-weight: 500;
  text-decoration: none;
}
.chat-build-banner:hover {
  filter: brightness(1.05);
}
</style>
