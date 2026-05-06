<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useChatStore } from '@/stores/chat'
import { ws } from '@/api/ws'
import { useMarkdown } from '@/composables/useMarkdown'
import api from '@/api/client'
import MessageParts from '@/components/chat/MessageParts.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const chat = useChatStore()

const agentId = route.params.id as string
const messageInput = ref('')
const scrollContainer = ref<HTMLElement | null>(null)
const topSentinel = ref<HTMLElement | null>(null)
const bottomSentinel = ref<HTMLElement | null>(null)
const attachedFiles = ref<{ path: string; filename: string }[]>([])
const fileInput = ref<HTMLInputElement | null>(null)
// Explicit collapse state: true=collapsed, false=expanded. Absent=auto (collapsed unless last).
const toolCollapseState = ref<Record<string, boolean>>({})
const uploading = ref(false)
let topObserver: IntersectionObserver | null = null
let bottomObserver: IntersectionObserver | null = null

onMounted(async () => {
  // WS subscriptions are server-driven — the socket auto-subscribes to every
  // agent this user is a member of at connect time. No client subscribe call.
  chat.initListeners()
  try {
    await chat.loadConversation(agentId)
  } catch {
    // No conversation yet — empty state is fine.
  }
  scrollToBottom()
  setupSentinelObservers()
})

onUnmounted(() => {
  topObserver?.disconnect()
  bottomObserver?.disconnect()
  chat.cleanup()
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
  await chat.jumpToLatest(agentId)
  await nextTick()
  scrollToBottom()
}

// Auto-scroll on new messages, streaming text, tool calls, or confirmations —
// but not when the user is scrolled into history (hasNewer=true) or is
// actively loading older messages. Otherwise prepend/eviction would yank
// their viewport to the bottom.
watch(
  () => [chat.messages.length, chat.streamingText, chat.activeToolCalls.size, chat.pendingConfirmation],
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

async function send() {
  const text = messageInput.value.trim()
  if (!text || chat.sending) return
  messageInput.value = ''
  const filePaths = attachedFiles.value.map(f => f.path)
  attachedFiles.value = []
  try {
    await chat.sendMessage(agentId, text, undefined, filePaths.length ? filePaths : undefined)
  } catch (err: any) {
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
      const { data } = await api.post(`/api/v1/agents/${agentId}/files`, form, {
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
    await chat.sendMessage(agentId, '', true)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Approval failed', life: 5000 })
  }
}

async function reject() {
  chat.pendingConfirmation = null
  try {
    await chat.sendMessage(agentId, 'Rejected by user.', false)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Rejection failed', life: 5000 })
  }
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    send()
  }
}

// Format tool input JSON for display — strips metadata keys and shows just the value for single-arg tools.
const metaKeys = new Set(['request_confirmation'])

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

// Compute the ID of the last tool element (message or active tool call) for auto-collapse.
const lastToolId = computed(() => {
  // Check active tool calls first (streaming).
  if (chat.activeToolCalls.size) {
    let last = ''
    for (const [id] of chat.activeToolCalls) last = id
    return last
  }
  // Fall back to last tool message in history.
  for (let i = chat.messages.length - 1; i >= 0; i--) {
    if (chat.messages[i].role === 'tool') return chat.messages[i].id
  }
  return ''
})

function isToolCollapsed(id: string, toolName?: string): boolean {
  // A tool call awaiting confirmation must show its code — that's exactly
  // what the user is being asked to approve. Force-expanded regardless of
  // toolName or explicit user toggle.
  if (chat.pendingConfirmation?.toolCallId === id) return false
  const explicit = toolCollapseState.value[id]
  if (explicit !== undefined) return explicit
  // run_js bubbles are noisy (full script + full stdout). Collapse by default
  // even when the bubble is the latest one — user can still click to expand.
  if (toolName === 'run_js') return true
  // Other tools: collapsed unless it's the last one in the transcript.
  return id !== lastToolId.value
}

function toggleToolCollapse(id: string, toolName?: string) {
  const current = isToolCollapsed(id, toolName)
  toolCollapseState.value = { ...toolCollapseState.value, [id]: !current }
}

// Markdown helper for streaming text.
const streamingHtml = computed(() => {
  if (!chat.streamingText) return ''
  const { html } = useMarkdown(computed(() => chat.streamingText))
  return html.value
})

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
    <!-- Header -->
    <div style="display: flex; align-items: center; gap: 0.75rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--p-surface-200)">
      <Button icon="pi pi-arrow-left" text severity="secondary" @click="router.push(`/agents/${agentId}`)" />
      <h2 style="margin: 0; font-size: 1.25rem">Chat</h2>
    </div>

    <!-- Jump-to-latest banner: shown when new agent output arrived while the
         user was scrolled into history. Clicking resets the window. -->
    <div v-if="chat.newMessagesPending" class="chat-jump-banner" @click="jumpToLatest">
      <i class="pi pi-arrow-down" />
      <span>New messages — click to jump to latest</span>
    </div>

    <!-- Message area -->
    <div ref="scrollContainer" class="chat-messages">
        <!-- Empty state -->
        <div v-if="chat.messages.length === 0 && !chat.streamingText" style="text-align: center; padding: 3rem; color: var(--p-text-muted-color)">
          <i class="pi pi-comments" style="font-size: 3rem; margin-bottom: 1rem" />
          <p>Send a message to start a conversation.</p>
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
            style="display: flex; justify-content: flex-start"
          >
            <div class="msg-bubble msg-tool">
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem; cursor: pointer" @click="toggleToolCollapse(msg.id, (msg as any).toolName)">
                <div style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">
                  {{ (msg as any).toolName || 'Tool' }}
                </div>
                <i :class="isToolCollapsed(msg.id, (msg as any).toolName) ? 'pi pi-plus' : 'pi pi-minus'" style="font-size: 0.7rem; opacity: 0.4" />
              </div>
              <template v-if="!isToolCollapsed(msg.id, (msg as any).toolName)">
                <div v-if="(msg as any).toolInput" style="margin-top: 0.25rem; margin-bottom: 0.5rem">
                  <pre style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; opacity: 0.7">{{ (msg as any).toolInput }}</pre>
                </div>
                <pre v-if="msg.content" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0">{{ msg.content }}</pre>
              </template>
            </div>
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
          <!-- User / assistant content. Assistant turns may carry a
               toolCalls[] array (folded by enrichMessages from the
               separate role=tool rows the backend persists). When
               present, render them inside the same bubble first so the
               final layout mirrors the streaming layout: tool calls on
               top, text answer at the bottom. -->
          <div
            v-else-if="(msg.content || (msg as any).toolCalls?.length || (msg as any)._cancelled) && !(msg as any)._hidden"
            :style="{
              display: 'flex',
              justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
            }"
          >
            <div
              :class="['msg-bubble', msg.role === 'user' ? 'msg-user' : 'msg-assistant']"
              :style="(msg as any)._cancelled ? { opacity: 0.6 } : undefined"
            >
              <div v-if="(msg as any).toolCalls?.length" :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
                <div v-for="tc in (msg as any).toolCalls" :key="tc.toolCallId" style="padding: 0.25rem 0">
                  <div style="display: flex; align-items: center; justify-content: space-between; cursor: pointer" @click="toggleToolCollapse(tc.toolCallId, tc.toolName)">
                    <div style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">{{ tc.toolName }}</div>
                    <i :class="isToolCollapsed(tc.toolCallId, tc.toolName) ? 'pi pi-plus' : 'pi pi-minus'" style="font-size: 0.7rem; opacity: 0.4" />
                  </div>
                  <template v-if="!isToolCollapsed(tc.toolCallId, tc.toolName)">
                    <div v-if="tc.input" style="margin-top: 0.25rem; margin-bottom: 0.5rem">
                      <pre style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; opacity: 0.7">{{ tc.input }}</pre>
                    </div>
                    <pre v-if="tc.output" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0">{{ tc.output }}</pre>
                    <pre v-if="tc.error" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; color: var(--p-red-500)">{{ tc.error }}</pre>
                  </template>
                </div>
              </div>
              <div
                v-if="msg.content"
                v-html="useMarkdown(computed(() => msg.content)).html.value"
                class="chat-bubble"
                :style="{ marginTop: (msg as any).toolCalls?.length ? '0.75rem' : '0' }"
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

        <!-- Streaming response. Tool calls render first (chronological:
             think → call → answer); the assistant's text answer lands at
             the bottom. The finalized assistant bubble below mirrors this
             ordering so there's no visual snap when streaming completes. -->
        <div v-if="chat.streamingText || chat.activeToolCalls.size" style="display: flex; justify-content: flex-start">
          <div style="max-width: 70%; min-width: 0; overflow-wrap: break-word; padding: 0.75rem 1rem; border-radius: 0.75rem; background-color: var(--p-content-hover-background); color: var(--p-text-color)">
            <!-- Active tool calls -->
            <div v-if="chat.activeToolCalls.size" :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
              <template v-for="[id, tc] in chat.activeToolCalls" :key="id">
                <!-- Completed/errored tool calls: render like finalized msg-tool -->
                <div v-if="tc.status === 'done' || tc.status === 'error'" style="padding: 0.25rem 0">
                  <div style="display: flex; align-items: center; justify-content: space-between; cursor: pointer" @click="toggleToolCollapse(id, tc.toolName)">
                    <div style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">{{ tc.toolName }}</div>
                    <i :class="isToolCollapsed(id, tc.toolName) ? 'pi pi-plus' : 'pi pi-minus'" style="font-size: 0.7rem; opacity: 0.4" />
                  </div>
                  <template v-if="!isToolCollapsed(id, tc.toolName)">
                    <div v-if="tc.input" style="margin-top: 0.25rem; margin-bottom: 0.5rem">
                      <pre style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; opacity: 0.7">{{ formatToolInput(tc.input) }}</pre>
                    </div>
                    <pre v-if="tc.output" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0">{{ tc.output }}</pre>
                    <pre v-if="tc.error" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; color: var(--p-red-500)">{{ tc.error }}</pre>
                  </template>
                </div>
                <!-- Running/confirmation -->
                <div v-else style="padding: 0.25rem 0">
                  <div style="display: flex; align-items: center; justify-content: space-between; cursor: pointer" @click="toggleToolCollapse(id, tc.toolName)">
                    <div style="display: flex; align-items: center; gap: 0.5rem">
                      <div style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">{{ tc.toolName }}</div>
                      <Tag :value="tc.status" :severity="tc.status === 'running' ? 'warn' : 'info'" style="font-size: 0.65rem" />
                    </div>
                    <i :class="isToolCollapsed(id, tc.toolName) ? 'pi pi-plus' : 'pi pi-minus'" style="font-size: 0.7rem; opacity: 0.4" />
                  </div>
                  <template v-if="!isToolCollapsed(id, tc.toolName)">
                    <pre v-if="tc.input" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0.25rem 0 0; opacity: 0.7">{{ formatToolInput(tc.input) }}</pre>
                  </template>
                  <!-- Inline confirmation (always visible, even when collapsed) -->
                  <div v-if="chat.pendingConfirmation && chat.pendingConfirmation.toolCallId === id" class="confirmation-box">
                    <div style="display: flex; align-items: center; justify-content: space-between">
                      <span style="font-size: 0.8rem; font-weight: 500">Allow this action?</span>
                      <div style="display: flex; gap: 0.5rem">
                        <Button label="Reject" severity="secondary" size="small" @click="reject" />
                        <Button label="Approve" severity="success" size="small" @click="approve" />
                      </div>
                    </div>
                  </div>
                </div>
              </template>
            </div>
            <div v-if="chat.streamingText" v-html="streamingHtml" class="chat-bubble" :style="{ marginTop: chat.activeToolCalls.size ? '0.75rem' : '0' }" />
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
              <strong>Confirmation required:</strong> {{ chat.pendingConfirmation.permission }}
            </div>
            <pre v-if="chat.pendingConfirmation.code" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; background: var(--p-surface-50); padding: 0.5rem; border-radius: 0.25rem; margin-bottom: 0.75rem">{{ chat.pendingConfirmation.code }}</pre>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end">
              <Button label="Reject" severity="secondary" size="small" @click="reject" />
              <Button label="Approve" severity="success" size="small" @click="approve" />
            </div>
          </Message>
        </div>
    </div>

    <!-- Attached files -->
    <div v-if="attachedFiles.length" style="display: flex; gap: 0.5rem; flex-wrap: wrap; padding-top: 0.5rem">
      <Chip
        v-for="(file, i) in attachedFiles"
        :key="file.path"
        :label="file.filename"
        removable
        @remove="removeFile(i)"
      />
    </div>

    <!-- Input area -->
    <div style="display: flex; gap: 0.5rem; padding-top: 0.75rem; border-top: 1px solid var(--p-surface-200)">
      <input ref="fileInput" type="file" multiple hidden @change="onFileSelect" />
      <Button
        icon="pi pi-paperclip"
        severity="secondary"
        text
        :disabled="chat.sending || uploading"
        :loading="uploading"
        @click="fileInput?.click()"
      />
      <Textarea
        v-model="messageInput"
        placeholder="Type a message..."
        :auto-resize="true"
        rows="1"
        style="flex: 1"
        :disabled="chat.sending"
        @keydown="onKeydown"
      />
      <Button
        icon="pi pi-send"
        :disabled="!messageInput.trim() || chat.sending"
        @click="send"
      />
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
</style>

<style scoped>
.chat-root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
}

.msg-bubble {
  max-width: 70%;
  min-width: 0;
  overflow-wrap: break-word;
  padding: 0.5rem 0.75rem;
  border-radius: 0.75rem;
}

.msg-user {
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
}

.msg-assistant {
  background-color: var(--p-content-hover-background);
  color: var(--p-text-color);
}

.msg-tool {
  background-color: var(--p-surface-100);
  color: var(--p-text-color);
  font-size: 0.85rem;
  border: 1px solid var(--p-surface-200);
}

:root.dark .msg-tool {
  background-color: var(--p-surface-800);
  border-color: var(--p-surface-700);
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
  padding: 1rem 0;
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
</style>
