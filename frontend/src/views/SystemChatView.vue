<script setup lang="ts">
import { ref, computed, nextTick, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useSystemChatStore, type DisplayMessage } from '@/stores/systemChat'
import MessageParts from '@/components/chat/MessageParts.vue'
import ToolBadge from '@/components/chat/ToolBadge.vue'
import type { MsgBlock } from '@/utils/messageGroup'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const sys = useSystemChatStore()
const conversationId = computed(() => route.params.conversationId as string)

const composer = ref('')
const messagesEl = ref<HTMLElement | null>(null)

function scrollToBottom() {
  nextTick(() => {
    const el = messagesEl.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

async function load() {
  if (!conversationId.value) return
  try {
    await sys.refreshConversations()
    await sys.loadConversation(conversationId.value)
    scrollToBottom()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Failed to load chat', detail: err?.message, life: 5000 })
  }
}

onMounted(() => {
  sys.initListeners()
  load()
})

onUnmounted(() => {
  // Listeners survive — the store is a singleton; we don't tear them
  // down between view mounts because the user may flip back to this
  // surface and we'd lose in-flight events.
})

watch(conversationId, () => load())
watch(
  () => [sys.messages.length, sys.streamingBlocks.length, sys.activeToolCalls.size, sys.pendingConfirmation],
  () => scrollToBottom(),
)

async function send() {
  const text = composer.value.trim()
  if (!text || sys.sending) return
  composer.value = ''
  try {
    await sys.sendPrompt(text)
  } catch (err: any) {
    composer.value = text
    toast.add({ severity: 'error', summary: 'Send failed', detail: err?.message, life: 5000 })
  }
}

async function approve() {
  try {
    await sys.sendPrompt('', true)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Approve failed', detail: err?.message, life: 5000 })
  }
}

async function reject() {
  sys.pendingConfirmation = null
  try {
    await sys.sendPrompt('Rejected by user.', false)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Reject failed', detail: err?.message, life: 5000 })
  }
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    send()
  }
}

async function newChat() {
  try {
    const t = await sys.createConversation()
    router.push(`/system/chat/${t.id}`)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'New chat failed', detail: err?.message, life: 5000 })
  }
}

function openConversation(id: string) {
  if (id === conversationId.value) return
  router.push(`/system/chat/${id}`)
}

function blocksFor(m: DisplayMessage): MsgBlock[] {
  return m.blocks ?? (m.content ? [{ kind: 'text', text: m.content }] : [])
}
</script>

<template>
  <div style="display: flex; gap: 1rem; height: calc(100vh - 6rem)">
    <!-- Sidebar: conversation list -->
    <Card style="width: 16rem; flex-shrink: 0; overflow: hidden">
      <template #content>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem">
          <strong>Chats</strong>
          <Button icon="pi pi-plus" text rounded size="small" aria-label="New chat" v-tooltip.bottom="'New chat'" @click="newChat" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem; overflow-y: auto; max-height: calc(100vh - 12rem)">
          <button
            v-for="t in sys.conversations"
            :key="t.id"
            @click="openConversation(t.id)"
            :style="{
              textAlign: 'left',
              padding: '0.5rem',
              border: 'none',
              borderRadius: '0.25rem',
              cursor: 'pointer',
              background: t.id === conversationId ? 'var(--p-primary-100)' : 'transparent',
              color: 'var(--p-text-color)',
              fontSize: '0.875rem',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }"
          >
            <i v-if="t.status === 'awaiting_confirmation'" class="pi pi-exclamation-circle" style="color: var(--p-yellow-500); margin-right: 0.25rem" />
            {{ t.title }}
          </button>
        </div>
      </template>
    </Card>

    <!-- Main: messages + composer -->
    <Card style="flex: 1; overflow: hidden; display: flex; flex-direction: column">
      <template #content>
        <div style="display: flex; flex-direction: column; height: 100%">
          <!-- Breadcrumb-y header -->
          <div style="margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--p-surface-border)">
            <router-link to="/system" style="color: var(--p-primary-color); font-size: 0.875rem; text-decoration: none">
              ← System Agent
            </router-link>
            <h2 v-if="sys.conversation" style="margin: 0.25rem 0 0; font-size: 1.25rem">{{ sys.conversation.title }}</h2>
          </div>

          <!-- Messages -->
          <div ref="messagesEl" style="flex: 1; overflow-y: auto; padding: 0.5rem 0">
            <div v-if="sys.loading" style="display: flex; flex-direction: column; gap: 1rem; padding: 1rem">
              <Skeleton width="60%" height="2rem" />
              <Skeleton width="80%" height="3rem" />
            </div>

            <div v-else-if="sys.messages.length === 0 && !sys.streamingText && sys.streamingBlocks.length === 0" style="text-align: center; padding: 3rem 1rem; color: var(--p-text-muted-color)">
              <i class="pi pi-comment" style="font-size: 2.5rem; margin-bottom: 0.5rem" />
              <p style="margin: 0">Ask me anything — list your agents, trigger an upgrade, manage bridges, inspect runs.</p>
            </div>

            <div v-else style="display: flex; flex-direction: column; gap: 0.75rem">
              <div
                v-for="msg in sys.messages"
                :key="msg.id"
                :style="{
                  alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                  background: msg.source === 'error'
                    ? 'var(--p-red-50)'
                    : msg.source === 'upgrade'
                      ? 'var(--p-blue-50)'
                      : msg.role === 'user'
                        ? 'var(--p-primary-50)'
                        : 'var(--p-surface-50)',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '0.5rem',
                  opacity: msg._cancelled ? 0.6 : 1,
                }"
              >
                <MessageParts
                  v-if="blocksFor(msg).length > 0"
                  :blocks="blocksFor(msg)"
                  :role="msg.role"
                />
                <div v-if="msg._cancelled" style="font-size: 0.75rem; color: var(--p-text-muted-color); margin-top: 0.25rem">(cancelled)</div>
              </div>

              <!-- Live streaming bubble -->
              <div
                v-if="sys.sending && (sys.streamingText || sys.streamingBlocks.length > 0)"
                style="align-self: flex-start; max-width: 85%; background: var(--p-surface-50); padding: 0.5rem 0.75rem; border-radius: 0.5rem; border-left: 3px solid var(--p-primary-500)"
              >
                <div v-for="(block, i) in sys.streamingBlocks" :key="i">
                  <div v-if="block.kind === 'text'" style="white-space: pre-wrap">{{ block.text }}</div>
                  <ToolBadge
                    v-else
                    :tool-call="sys.activeToolCalls.get(block.toolCallId)!"
                  />
                </div>
              </div>

              <!-- Pending confirmation card (when the call has no assistant-msg anchor) -->
              <div
                v-if="sys.pendingConfirmation"
                style="align-self: flex-start; max-width: 85%; background: var(--p-yellow-50); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--p-yellow-300)"
              >
                <div style="font-weight: 600; margin-bottom: 0.5rem">
                  <i class="pi pi-exclamation-triangle" style="margin-right: 0.25rem" />
                  Confirmation required: <code>{{ sys.pendingConfirmation.toolName }}</code>
                </div>
                <pre
                  v-if="sys.pendingConfirmation.argsJson"
                  style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; background: var(--p-surface-50); padding: 0.5rem; border-radius: 0.25rem; margin: 0 0 0.75rem"
                >{{ sys.pendingConfirmation.argsJson }}</pre>
                <div style="display: flex; gap: 0.5rem">
                  <Button label="Approve" severity="success" size="small" :loading="sys.sending" @click="approve" />
                  <Button label="Reject" severity="danger" size="small" outlined :loading="sys.sending" @click="reject" />
                </div>
              </div>
            </div>
          </div>

          <!-- Composer -->
          <div style="border-top: 1px solid var(--p-surface-border); padding-top: 0.75rem; display: flex; gap: 0.5rem">
            <Textarea
              v-model="composer"
              :disabled="sys.sending || !!sys.pendingConfirmation"
              :placeholder="sys.pendingConfirmation ? 'Approve or reject the pending tool call above first.' : 'Ask me anything…'"
              autoResize
              rows="2"
              style="flex: 1; resize: none"
              @keydown="onKeydown"
            />
            <Button
              icon="pi pi-send"
              :disabled="!composer.trim() || sys.sending || !!sys.pendingConfirmation"
              @click="send"
            />
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
