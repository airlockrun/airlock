<script setup lang="ts">
import { ref, computed, nextTick, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useSystemChatStore } from '@/stores/systemChat'
import { useConversationFeedStore } from '@/stores/conversationFeed'
import ToolBadge from '@/components/chat/ToolBadge.vue'
import { renderMarkdown } from '@/composables/useMarkdown'
import { toolDescription } from '@/utils/messageGroup'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const sys = useSystemChatStore()
const feed = useConversationFeedStore()

// route.params.conversationId is undefined on /system/chat (the empty
// "new conversation" route). The chat view treats undefined as the
// not-yet-saved state — no row appears in the sidebar until first send.
const conversationId = computed(() => (route.params.conversationId as string) || '')
const isNew = computed(() => !conversationId.value)

const composer = ref('')
const composerRef = ref<any>(null)
const messagesEl = ref<HTMLElement | null>(null)

// PrimeVue's autoResize only recomputes on a real `input` event, so clearing
// the model in code (e.g. after send) leaves a multi-line box stretched. Reset
// the inline height so an empty composer collapses back to a single row.
function resetComposerHeight() {
  nextTick(() => {
    const el = composerRef.value?.$el as HTMLTextAreaElement | undefined
    if (el) el.style.height = 'auto'
  })
}

function scrollToBottom() {
  nextTick(() => {
    const el = messagesEl.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

// Re-pin to the bottom only when the visual viewport GROWS — i.e. the mobile
// keyboard was dismissed (e.g. after a send), which otherwise leaves the last
// bubble stranded above the bottom. On shrink (keyboard opening) leave the
// scroll alone so a short, top-anchored conversation isn't shoved up under the
// top bar. rAF so we read scrollHeight after the layout reflowed.
let prevViewportH = window.visualViewport?.height ?? window.innerHeight
function onViewportResize() {
  const h = window.visualViewport?.height ?? window.innerHeight
  const grew = h > prevViewportH + 1
  prevViewportH = h
  if (!grew) return
  requestAnimationFrame(() => {
    const el = messagesEl.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

async function load() {
  if (isNew.value) {
    // Empty-state landing: keep the sidebar conversations fresh so the
    // unified left pane reflects the live state, but don't load a thread.
    sys.resetConversationView()
    void feed.loadFirst()
    return
  }
  try {
    void feed.loadFirst()
    await sys.loadConversation(conversationId.value)
    scrollToBottom()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Failed to load chat', detail: err?.message, life: 5000 })
  }
}

onMounted(() => {
  sys.initListeners()
  load()
  const vv = window.visualViewport
  if (vv) vv.addEventListener('resize', onViewportResize)
  else window.addEventListener('resize', onViewportResize)
})

onUnmounted(() => {
  const vv = window.visualViewport
  if (vv) vv.removeEventListener('resize', onViewportResize)
  else window.removeEventListener('resize', onViewportResize)
})

watch(conversationId, (id) => {
  // First-send mints the conversation and sets sys.conversationId, then send()
  // does router.replace('/system/chat/{id}') — which lands here. The store is
  // already on this conversation and streaming the reply; calling load() would
  // run loadConversation → resetTransient and wipe the in-flight stream
  // (currentRunId/streamingText), so every text_delta already arriving gets
  // dropped — the "blink then nothing until refresh" bug. Skip when the URL has
  // merely caught up to the conversation we're already on; only reload on a real
  // switch to a different thread (or to the empty new-chat route).
  if (id && id === sys.conversationId) return
  load()
})
watch(
  () => [sys.messages.length, sys.streamingBlocks.length, sys.activeToolCalls.size, sys.pendingConfirmation],
  () => scrollToBottom(),
)

async function send() {
  const text = composer.value.trim()
  if (!text || sys.sending) return
  composer.value = ''
  resetComposerHeight()
  try {
    const cid = await sys.sendPrompt(text)
    // First send on the empty route mints the conversation server-side;
    // route to its canonical URL so a refresh / shared link works.
    if (isNew.value && cid) {
      router.replace(`/system/chat/${cid}`)
    }
  } catch (err: any) {
    composer.value = text
    toast.add({ severity: 'error', summary: 'Send failed', detail: err?.message, life: 5000 })
  }
}

async function approve() {
  try {
    await sys.sendPrompt('', true)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Approve failed', detail: err.response?.data?.error || err?.message, life: 5000 })
  }
}

async function reject() {
  // Don't clear pendingConfirmation here — sendPrompt reads its runId
  // to tell the backend which run to resume, then clears it itself.
  try {
    await sys.sendPrompt('Rejected by user.', false)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Reject failed', detail: err.response?.data?.error || err?.message, life: 5000 })
  }
}

function onKeydown(e: KeyboardEvent) {
  // Desktop: Enter sends, Shift+Enter inserts a newline. Touch keyboards
  // (coarse pointer) let Enter be a newline — the on-screen Send button
  // submits — so dumping multi-line text on mobile doesn't fire early. Skip
  // IME composition so selecting a candidate with Enter never sends.
  if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return
  if (window.matchMedia?.('(pointer: coarse)').matches) return
  e.preventDefault()
  send()
}

// Per-source accent class — notifications / errors / upgrade events
// render distinctly from regular bubbles without per-source props.
function msgClassForSource(source: string): string {
  switch (source) {
    case 'error':
      return 'msg-error'
    case 'upgrade':
      return 'msg-notification'
    default:
      return ''
  }
}
</script>

<template>
  <!-- Full-bleed chat root — composer pins to the bottom via flex.
       Mirrors AgentChatView's chat-root layout so both surfaces feel
       the same. The unified left sidebar (AppLayout) holds the
       conversation switcher across both. -->
  <div class="chat-root">
    <!-- Messages -->
    <div ref="messagesEl" class="chat-messages">
      <div v-if="sys.loading" class="chat-loading">
        <Skeleton width="60%" height="2rem" />
        <Skeleton width="80%" height="3rem" />
      </div>

      <div
        v-else-if="sys.messages.length === 0 && !sys.streamingText && sys.streamingBlocks.length === 0"
        class="chat-empty"
      >
        <i class="pi pi-cog" />
        <p class="chat-empty-title">
          {{ isNew ? 'New conversation' : 'Conversation' }} with <strong>System Agent</strong>
        </p>
        <p class="chat-empty-sub">
          Ask me anything — list your agents, trigger an upgrade, manage bridges, inspect runs. It's saved as a new conversation once you send.
        </p>
      </div>

      <template v-else>
        <!-- Render each persisted message. Assistant turns carry an
             ordered blocks[] (text / tool, interleaved exactly as the
             model emitted them — built by enrichMessages from the
             persisted rows' parts). Render blocks in order; plain
             user/text rows without blocks fall back to content. -->
        <template v-for="msg in sys.messages" :key="msg.id">
          <div
            v-if="!msg._hidden"
            :class="{ 'msg-row-user': msg.role === 'user' }"
            :style="{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }"
          >
            <div
              :class="msg.role === 'user' ? ['msg-bubble', 'msg-user'] : ['msg-response', msgClassForSource(msg.source)]"
              :style="msg._cancelled ? { opacity: 0.6 } : undefined"
            >
              <div v-if="msg.blocks?.length" :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
                <template v-for="(b, bi) in msg.blocks" :key="bi">
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
                v-html="renderMarkdown(msg.content)"
                class="chat-bubble"
              />
              <div v-if="msg._cancelled" class="msg-cancelled">(cancelled)</div>
            </div>
          </div>
        </template>

        <!-- Live streaming bubble — same shape as the finalized
             blocks[], rendered with the same ToolBadge so there's no
             visual snap when the run completes. -->
        <div
          v-if="sys.sending && (sys.streamingText || sys.streamingBlocks.length > 0)"
          style="display: flex; justify-content: flex-start"
        >
          <div class="msg-response">
            <div :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
              <template v-for="(block, i) in sys.streamingBlocks" :key="i">
                <div
                  v-if="block.kind === 'text' && block.text"
                  v-html="renderMarkdown(block.text)"
                  class="chat-bubble"
                />
                <ToolBadge
                  v-else-if="block.kind === 'tool'"
                  :label="sys.activeToolCalls.get(block.toolCallId)?.toolName || 'tool'"
                  :tool-name="sys.activeToolCalls.get(block.toolCallId)?.toolName || 'tool'"
                  :input="sys.activeToolCalls.get(block.toolCallId)?.input || ''"
                  :description="toolDescription(sys.activeToolCalls.get(block.toolCallId)?.input)"
                  :output="sys.activeToolCalls.get(block.toolCallId)?.output || ''"
                  :error="sys.activeToolCalls.get(block.toolCallId)?.error || ''"
                  :outcome="(sys.activeToolCalls.get(block.toolCallId)?.status === 'error' ? 'error' : sys.activeToolCalls.get(block.toolCallId)?.status === 'done' ? 'success' : '') as any"
                />
              </template>
            </div>
          </div>
        </div>

        <!-- Pending confirmation card -->
        <div v-if="sys.pendingConfirmation" class="confirmation-box">
          <div class="confirmation-title">
            <i class="pi pi-exclamation-triangle" style="margin-right: 0.25rem" />
            <template v-if="sys.pendingConfirmation.description">{{ sys.pendingConfirmation.description }}</template>
            <template v-else>Confirmation required: <code>{{ sys.pendingConfirmation.toolName }}</code></template>
          </div>
          <pre
            v-if="sys.pendingConfirmation.argsJson"
            class="confirmation-args"
          >{{ sys.pendingConfirmation.argsJson }}</pre>
          <div class="confirmation-actions">
            <Button label="Approve" severity="success" size="small" :loading="sys.sending" @click="approve" />
            <Button label="Reject" severity="danger" size="small" outlined :loading="sys.sending" @click="reject" />
          </div>
        </div>
      </template>
    </div>

    <!-- Composer: floats over the bottom of the chat. The message list scrolls
         behind it and fades into the gradient. No top divider — the fade is the
         separation. Send lives inside the rounded box. -->
    <div class="chat-composer">
      <div class="composer-box">
        <Textarea
          ref="composerRef"
          v-model="composer"
          :disabled="sys.sending || !!sys.pendingConfirmation"
          :placeholder="sys.pendingConfirmation ? 'Approve or reject the pending tool call above first.' : 'Ask me anything…'"
          autoResize
          rows="1"
          @keydown="onKeydown"
        />
        <Button
          class="composer-btn"
          icon="pi pi-send"
          rounded
          :disabled="!composer.trim() || sys.sending || !!sys.pendingConfirmation"
          @click="send"
        />
      </div>
    </div>
  </div>
</template>

<style>
/* Global chat-bubble styles — mirror AgentChatView so the same
   markdown rendering (lists, fenced code blocks, GFM tables,
   inline code) lights up on the sysagent surface without
   depending on AgentChatView being loaded first. */
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

.chat-messages {
  flex: 1 1 0;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  /* Bottom space so the last message clears the floating composer. */
  padding: 0.25rem 1rem 3.75rem;
}

/* Tighten the spacing around the user's bubble to half the list gap. */
.msg-row-user {
  margin-top: -0.5rem;
  margin-bottom: -0.5rem;
}

/* Don't pull the very first bubble up — system chat has no top sentinel, so a
   first-message user bubble would otherwise be dragged under the top bar. */
.msg-row-user:first-child {
  margin-top: 0;
}

.chat-loading {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding: 1rem;
}

.chat-empty {
  text-align: center;
  padding: 3rem 1.5rem;
  color: var(--p-text-muted-color);
}

.chat-empty .pi-cog {
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

.msg-user {
  align-self: flex-end;
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
}

.msg-response {
  align-self: flex-start;
  width: 100%;
  min-width: 0;
  overflow-wrap: break-word;
  max-width: 100%;
  padding: 0.25rem 0;
}

.msg-streaming {
  border-left: 3px solid var(--p-primary-500);
  padding-left: 0.75rem;
}

.msg-notification {
  background-color: var(--p-blue-50);
}

.msg-error {
  background-color: var(--p-red-50);
}

.msg-cancelled {
  font-size: 0.75rem;
  color: var(--p-text-muted-color);
  margin-top: 0.25rem;
}

.confirmation-box {
  align-self: flex-start;
  max-width: 85%;
  background: var(--p-yellow-50);
  padding: 0.75rem;
  border-radius: 0.5rem;
  border: 1px solid var(--p-yellow-300);
}

.confirmation-title {
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.confirmation-args {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 0.8rem;
  background: var(--p-surface-50);
  padding: 0.5rem;
  border-radius: 0.25rem;
  margin: 0 0 0.75rem;
}

.confirmation-actions {
  display: flex;
  gap: 0.5rem;
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
  /* Opaque fade so messages dissolve into the page background as they reach
     the input rather than peeking around the floating box. Click-through so
     the transcript behind it stays scrollable; the box opts back in. */
  background: linear-gradient(to top, var(--p-content-background) 60%, transparent);
  pointer-events: none;
}

.chat-composer > * {
  pointer-events: auto;
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

/* Strip the textarea's own chrome so it reads as part of the box. */
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

/* Desktop (sidebar layout) — widen the horizontal gutters; the tight mobile
   inset looks cramped on a wide column. Mirrors AppLayout's max-width:768px
   mobile breakpoint. Top/bottom padding is untouched. */
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
</style>
