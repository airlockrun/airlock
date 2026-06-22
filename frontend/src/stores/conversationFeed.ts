import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ListConversationFeedResponseSchema } from '@/gen/airlock/v1/api_pb'

// FeedItem is one sidebar row — an agent web conversation or a system
// conversation — flattened from the merged backend feed.
export interface FeedItem {
  kind: 'agent' | 'system'
  id: string
  agentId: string
  title: string
  updatedAtSec: number
  status: string
}

// A loaded page plus the cursor that fetches the NEXT (older) page. Empty
// `next` means this page is the end of the feed.
interface Page {
  items: FeedItem[]
  next: string
}

// The sidebar conversation feed: a windowed, keyset-paginated merge of agent +
// system web conversations (newest first). Pages are appended as the user
// scrolls down and popped as they scroll back up, so a long history never all
// lives in memory at once. The backend (GET /conversations/feed) does the merge
// + ordering; each page carries the cursor to resume from, so dropping a page is
// just a pop (re-fetched on the way back down).
export const useConversationFeedStore = defineStore('conversationFeed', () => {
  const pages = ref<Page[]>([])
  const loading = ref(false)
  const loadingMore = ref(false)

  const items = computed<FeedItem[]>(() => pages.value.flatMap((p) => p.items))
  const reachedEnd = computed(() => pages.value.length > 0 && pages.value[pages.value.length - 1].next === '')

  function mapItems(raw: { kind: string; id: string; agentId: string; title: string; updatedAt?: { seconds?: bigint }; status: string }[]): FeedItem[] {
    return raw.map((c) => ({
      kind: c.kind === 'system' ? 'system' : 'agent',
      id: c.id,
      agentId: c.agentId,
      title: c.title || (c.kind === 'system' ? 'New chat' : 'Untitled conversation'),
      updatedAtSec: Number(c.updatedAt?.seconds ?? 0n),
      status: c.status,
    }))
  }

  async function fetchPage(cursor: string): Promise<Page> {
    const { data } = await api.get('/api/v1/conversations/feed', { params: cursor ? { cursor } : {} })
    const resp = fromJson(ListConversationFeedResponseSchema, data)
    return { items: mapItems(resp.items as any), next: resp.nextCursor }
  }

  // loadFirst (re)loads page 1, resetting the window. Also the freshness path:
  // after a new/bumped conversation the most-recent page reflects it, and the
  // user is at the top of the list when they act anyway.
  async function loadFirst() {
    loading.value = true
    try {
      pages.value = [await fetchPage('')]
    } finally {
      loading.value = false
    }
  }

  async function loadMore() {
    if (loadingMore.value || loading.value || pages.value.length === 0) return
    const last = pages.value[pages.value.length - 1]
    if (!last.next) return
    loadingMore.value = true
    try {
      pages.value = [...pages.value, await fetchPage(last.next)]
    } finally {
      loadingMore.value = false
    }
  }

  // Drop the last page (scroll-up windowing). Keeps page 1; the popped page's
  // items re-load on the next loadMore via the now-last page's cursor.
  function dropLastPage() {
    if (pages.value.length > 1) pages.value = pages.value.slice(0, -1)
  }

  function removeItem(id: string) {
    pages.value = pages.value.map((p) => ({ ...p, items: p.items.filter((i) => i.id !== id) }))
  }

  function reset() {
    pages.value = []
  }

  return { items, loading, loadingMore, reachedEnd, loadFirst, loadMore, dropLastPage, removeItem, reset }
})
