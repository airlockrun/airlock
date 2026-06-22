import { defineStore } from 'pinia'
import api from '@/api/client'

// Delete capability for agent web conversations. The sidebar list itself is
// served by the windowed conversationFeed store; this exists only so the
// delete goes through one place (the server cascade also removes the
// conversation's messages + topic subscriptions).
export const useConversationsStore = defineStore('conversations', () => {
  async function remove(convId: string) {
    await api.delete(`/api/v1/conversations/${convId}`)
  }

  return { remove }
})
