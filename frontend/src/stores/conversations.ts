import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ListConversationsResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { ConversationInfo } from '@/gen/airlock/v1/types_pb'

// Global, cross-agent conversation list backing the app sidebar. Distinct
// from the chat store, which owns the single *active* thread's messages —
// this store only holds the flat list (newest first, server-ordered) and
// is refreshed whenever a conversation is created or deleted.
export const useConversationsStore = defineStore('conversations', () => {
  const list = ref<ConversationInfo[]>([])
  const loaded = ref(false)

  async function load() {
    const { data } = await api.get('/api/v1/conversations')
    list.value = fromJson(ListConversationsResponseSchema, data).conversations
    loaded.value = true
  }

  // Best-effort refresh — callers fire this after create/delete and don't
  // want a failure to surface as a thrown error in the chat flow.
  async function refresh() {
    try {
      await load()
    } catch {
      /* sidebar will catch up on next navigation/load */
    }
  }

  // Delete a conversation (any agent) and drop it from the list. The
  // server cascade also removes its messages + topic subscriptions.
  async function remove(convId: string) {
    await api.delete(`/api/v1/conversations/${convId}`)
    list.value = list.value.filter(c => c.id !== convId)
  }

  return { list, loaded, load, refresh, remove }
})
