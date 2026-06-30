<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useAuthStore } from '@/stores/auth'
import { useAgentsStore } from '@/stores/agents'
import { useConversationsStore } from '@/stores/conversations'
import { useConversationFeedStore } from '@/stores/conversationFeed'
import { useChatStore } from '@/stores/chat'
import { useSystemChatStore } from '@/stores/systemChat'
import { useConfirm } from 'primevue/useconfirm'
import { useTheme } from '@/composables/useTheme'
import type { ConversationInfo } from '@/gen/airlock/v1/types_pb'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const { isDark } = useTheme()
const agentsStore = useAgentsStore()
const conversationsStore = useConversationsStore()
const feed = useConversationFeedStore()
const chat = useChatStore()
const systemChat = useSystemChatStore()
const confirm = useConfirm()
const toast = useToast()

// The vanity-URL router layer bounces a stale (renamed) agent slug here
// with ?staleAgent=<slug>. Surface it once, then strip the query so a
// refresh/bookmark of the cleaned URL doesn't re-toast.
watch(
  () => route.query.staleAgent,
  (slug) => {
    if (!slug) return
    toast.add({
      severity: 'warn',
      summary: 'Link out of date',
      detail: `No agent “${slug}” — it may have been renamed. Pick it from the list.`,
      life: 6000,
    })
    const q = { ...route.query }
    delete q.staleAgent
    router.replace({ query: q })
  },
  { immediate: true },
)

const drawerVisible = ref(false)

// Settings is its own context: the sidebar swaps the chat list for these
// sections (each an existing route), gated by role. Security/Resources/Bridges
// are universal; the rest are admin.
const settingsSections = computed(() => {
  const items: { label: string; icon: string; route: string }[] = [
    { label: 'Security', icon: 'pi pi-shield', route: '/settings/security' },
    { label: 'Resources', icon: 'pi pi-key', route: '/settings/resources' },
    { label: 'Bridges', icon: 'pi pi-link', route: '/bridges' },
  ]
  if (auth.can('tenant.provider.manage')) {
    items.push(
      { label: 'Providers', icon: 'pi pi-server', route: '/providers' },
      { label: 'Models', icon: 'pi pi-sparkles', route: '/models' },
      { label: 'System defaults', icon: 'pi pi-cog', route: '/settings' },
    )
  }
  if (auth.can('tenant.usage.view')) {
    items.push({ label: 'Usage', icon: 'pi pi-chart-bar', route: '/usage' })
  }
  if (auth.can('tenant.user.manage')) {
    items.push({ label: 'Users', icon: 'pi pi-users', route: '/users' })
  }
  if (auth.can('tenant.agent.list_all')) {
    items.push({ label: 'Manage agents', icon: 'pi pi-th-large', route: '/settings/agents' })
  }
  return items
})

// Routes that live under the Settings context (so the sidebar shows sections +
// the top bar shows a back arrow). '/settings' covers /settings/{security,
// resources}.
const settingsPaths = ['/providers', '/models', '/usage', '/bridges', '/users', '/settings']
const inSettings = computed(() =>
  settingsPaths.some((p) => route.path === p || route.path.startsWith(p + '/')),
)

// Remember where we were before entering Settings, so the back arrow returns to
// the main (chat) view rather than always /agents.
const lastAppRoute = ref('/agents')
watch(
  () => route.fullPath,
  (p) => {
    if (!inSettings.value) lastAppRoute.value = p
  },
  { immediate: true },
)

const userMenuRef = ref()
// Computed so the theme row's label/icon track the current mode. The Settings
// entry lands on Security — the first universal Settings section.
const userMenuItems = computed(() => [
  {
    label: 'Settings',
    icon: 'pi pi-cog',
    command: () => navigateTo('/settings/security'),
  },
  {
    label: isDark.value ? 'Light mode' : 'Dark mode',
    icon: isDark.value ? 'pi pi-sun' : 'pi pi-moon',
    command: () => { isDark.value = !isDark.value },
  },
  {
    label: 'Logout',
    icon: 'pi pi-sign-out',
    command: () => {
      auth.logout()
      router.push('/login')
    },
  },
])

function toggleUserMenu(event: Event) {
  userMenuRef.value.toggle(event)
}

const userLabel = computed(() => auth.user?.displayName || auth.user?.email || 'Account')

function isActive(path: string) {
  return route.path.startsWith(path)
}

// "New chat" picks an agent first (a conversation always belongs to one).
// The freshly-opened chat starts in its empty "new thread" state; the
// row appears in the sidebar only once the first message is sent.
// Same shape for the system agent — /system/chat opens an empty
// conversation view that's persisted server-side on first send.
const newMenuRef = ref()
function startSystemChat() {
  router.push('/system/chat')
  drawerVisible.value = false
}
// Most-recent web-conversation time per agent, derived from the loaded
// conversation list. Orders the New-chat menu by last use (recent first);
// agents never chatted with fall back to their existing created-desc order.
const agentLastUsedSec = computed(() => {
  const m = new Map<string, number>()
  for (const c of feed.items) {
    if (c.kind !== 'agent') continue
    if (c.updatedAtSec > (m.get(c.agentId) ?? 0)) m.set(c.agentId, c.updatedAtSec)
  }
  return m
})
const agentMenuItems = computed(() => {
  const items: any[] = [
    {
      label: 'System Agent',
      icon: 'pi pi-cog',
      command: startSystemChat,
    },
  ]
  if (agentsStore.agents.length === 0) {
    items.push({ label: 'No agents yet', disabled: true })
    return items
  }
  const ranked = [...agentsStore.agents].sort(
    (a, b) => (agentLastUsedSec.value.get(b.id) ?? 0) - (agentLastUsedSec.value.get(a.id) ?? 0),
  )
  for (const a of ranked) {
    items.push({
      label: a.name,
      icon: 'pi pi-box',
      command: () => {
        router.push({ path: `/agents/${a.id}/chat` })
        drawerVisible.value = false
      },
    })
  }
  // Shortcut to the full agents page (and any agents past what's handy to
  // scroll here).
  items.push({ label: 'All agents', icon: 'pi pi-th-large', command: () => navigateTo('/agents') })
  return items
})
function openNewMenu(event: Event) {
  newMenuRef.value.toggle(event)
}

// Surface the (thin) scrollbar only while the list is actively scrolling:
// tag the element on scroll, clear the tag after a short idle.
const scrollHideTimers = new WeakMap<HTMLElement, number>()
const lastScrollTop = new WeakMap<HTMLElement, number>()
function onListScroll(e: Event) {
  const el = e.target as HTMLElement
  el.classList.add('scrolling')
  const prev = scrollHideTimers.get(el)
  if (prev) clearTimeout(prev)
  scrollHideTimers.set(el, window.setTimeout(() => el.classList.remove('scrolling'), 700))

  // Windowed infinite scroll over the conversation feed. Near the bottom →
  // page in older conversations; scrolled well back up → drop the last page so
  // a long history never all lives in memory (it re-pages on the way down).
  const top = el.scrollTop
  const goingUp = top < (lastScrollTop.get(el) ?? top)
  lastScrollTop.set(el, top)
  const distanceFromBottom = el.scrollHeight - top - el.clientHeight
  if (distanceFromBottom < 240) {
    void feed.loadMore()
  } else if (goingUp && distanceFromBottom > el.clientHeight * 2) {
    feed.dropLastPage()
  }
}

const agentNameById = computed(() => {
  const m = new Map<string, string>()
  for (const a of agentsStore.agents) m.set(a.id, a.name)
  return m
})
function agentName(agentId: string): string {
  return agentNameById.value.get(agentId) || 'Agent'
}
const agentEmojiById = computed(() => {
  const m = new Map<string, string>()
  for (const a of agentsStore.agents) if (a.emoji) m.set(a.id, a.emoji)
  return m
})
function agentEmoji(agentId: string): string {
  return agentEmojiById.value.get(agentId) || ''
}

function isActiveConv(c: ConversationInfo): boolean {
  return route.path === `/agents/${c.agentId}/chat` && chat.conversationId === c.id
}

function deleteConversation(c: ConversationInfo, event: Event) {
  event.stopPropagation()
  confirm.require({
    message: `Delete "${c.title?.trim() || 'Untitled conversation'}"? This removes its history permanently.`,
    header: 'Delete conversation',
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: 'Delete' },
    accept: async () => {
      const wasActive = isActiveConv(c)
      try {
        await conversationsStore.remove(c.id)
      } catch {
        return
      }
      feed.removeItem(c.id)
      // If the open thread was just deleted, drop ?c= so the chat view
      // reloads into the agent's next thread (or empty state).
      if (wasActive) {
        router.replace({ path: `/agents/${c.agentId}/chat` })
      }
    },
  })
}

// Unified sidebar: agent web conversations + sysagent conversations
// share one list, sorted by recency. Each entry carries its kind so
// click + delete dispatch correctly without per-row branching in the
// template.
interface SidebarItem {
  kind: 'agent' | 'system'
  id: string
  agentId?: string                // 'agent' only
  title: string
  updatedAtSec: number
  status?: string                 // 'system': 'active' | 'awaiting_confirmation'
}
// Backed by the windowed feed store — already merged (agent + system) and
// sorted newest-first by the backend, paged in/out as the user scrolls.
const sidebarItems = computed<SidebarItem[]>(() => feed.items)

function isActiveItem(item: SidebarItem): boolean {
  if (item.kind === 'agent') {
    return route.path === `/agents/${item.agentId}/chat` && chat.conversationId === item.id
  }
  return route.path === `/system/chat/${item.id}`
}

function openSidebarItem(item: SidebarItem) {
  if (item.kind === 'agent') {
    router.push({ path: `/agents/${item.agentId}/chat`, query: { c: item.id } })
  } else {
    router.push(`/system/chat/${item.id}`)
  }
  drawerVisible.value = false
}

function deleteSidebarItem(item: SidebarItem, event: Event) {
  event.stopPropagation()
  if (item.kind === 'agent') {
    deleteConversation({ id: item.id, agentId: item.agentId!, title: item.title } as ConversationInfo, event)
    return
  }
  confirm.require({
    message: `Delete "${item.title}"? This removes its history permanently.`,
    header: 'Delete conversation',
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: 'Delete' },
    accept: async () => {
      const wasActive = isActiveItem(item)
      try {
        await systemChat.deleteConversation(item.id)
      } catch {
        return
      }
      feed.removeItem(item.id)
      if (wasActive) router.replace('/system')
    },
  })
}

// On /agents/:id/chat (and the sysagent equivalent /system/chat/:id) we
// hoist the back affordance into the top bar so the chat view itself
// doesn't need a header row. backTarget is null on every other route —
// the button doesn't render.
const backTarget = computed<string | null>(() => {
  const m = /^\/agents\/([^/]+)\/chat$/.exec(route.path)
  if (m) return `/agents/${m[1]}`
  if (/^\/system\/chat(?:\/[^/]+)?$/.test(route.path)) return '/system'
  return null
})

// Single back affordance for the top bar: leaving Settings returns to wherever
// we came from (the chat/app view); inside chat it returns to the agent; a
// run/build detail page returns to its agent. Kept separate from backTarget so
// the chat-only app-content-flush padding doesn't apply to those detail pages.
const back = computed<string | null>(() => {
  if (inSettings.value) return lastAppRoute.value || '/agents'
  if (backTarget.value) return backTarget.value
  const m = /^\/agents\/([^/]+)\/(?:runs|builds)\/[^/]+$/.exec(route.path)
  if (m) return `/agents/${m[1]}`
  return null
})

// AgentDetailView (/agents/:id) renders a sticky section nav at the top.
// Drop the main scroll container's top padding so the nav sits flush
// against the page top once it sticks, instead of leaving a 1.5rem gap.
const isAgentDetail = computed<boolean>(() =>
  /^\/agents\/[^/]+$/.test(route.path),
)

// True on the chat routes (agent + system) — backTarget is non-null exactly
// there. Drives the desktop two-part header: "Airlock" on the left, the
// agent/chat title aligned with the message column.
const isChat = computed<boolean>(() => backTarget.value !== null)

// Top-bar title. In a chat it reads "Agent name: chat title" (or just the
// agent / "System Agent" name for a brand-new thread); elsewhere it's the
// context name. Truncated to the available width by CSS (ellipsis).
const headerTitle = computed<string>(() => {
  const activeTitle = () => sidebarItems.value.find(isActiveItem)?.title || ''
  const agentChat = /^\/agents\/([^/]+)\/chat$/.exec(route.path)
  if (agentChat) {
    const name = agentName(agentChat[1])
    const title = activeTitle()
    return title ? `${name}: ${title}` : name
  }
  if (/^\/system\/chat(?:\/[^/]+)?$/.test(route.path)) {
    const title = activeTitle()
    return title ? `System: ${title}` : 'System'
  }
  return inSettings.value ? 'Settings' : 'Airlock'
})

function navigateTo(path: string) {
  router.push(path)
  drawerVisible.value = false
}

onMounted(() => {
  // Agents back the New-chat menu + row labels; the feed backs the sidebar
  // list (its first page). Failures are non-fatal and self-heal on the next
  // navigation/action.
  agentsStore.fetchAgents().catch(() => {})
  feed.loadFirst().catch(() => {})
})
</script>

<template>
  <div class="app-layout" :class="{ 'in-settings': inSettings }">
    <!-- Top Toolbar -->
    <Toolbar class="app-toolbar" :class="{ 'app-toolbar-chat': isChat }">
      <template #start>
        <div class="bar-start" :class="{ 'is-chat': isChat }">
          <!-- Left zone: hamburger + back + brand. On desktop in a chat this
               zone is exactly the sidebar width so the title beside it lines up
               with the message column. -->
          <div class="bar-left">
            <Button
              icon="pi pi-bars"
              text
              severity="secondary"
              class="mobile-menu-btn"
              @click="drawerVisible = true"
            />
            <Button
              v-if="back"
              icon="pi pi-arrow-left"
              text
              severity="secondary"
              aria-label="Back"
              @click="router.push(back)"
            />
            <span class="bar-brand">{{ isChat ? 'Airlock' : headerTitle }}</span>
          </div>
          <!-- Chat title, aligned with the message column on desktop. -->
          <span v-if="isChat" class="bar-chat-title" :title="headerTitle">{{ headerTitle }}</span>
        </div>
      </template>
    </Toolbar>

    <!-- User menu popup (triggered from the sidebar/drawer "User" item). -->
    <Menu ref="userMenuRef" :model="userMenuItems" :popup="true" />

    <div class="app-body">
      <!-- Desktop Sidebar: chats + Agents/User, or the Settings sections. -->
      <nav class="app-sidebar">
        <!-- Settings context: section list -->
        <div v-if="inSettings" class="conv-list settings-list">
          <a
            v-for="s in settingsSections"
            :key="s.route"
            :class="['sidebar-item', { active: route.path === s.route }]"
            :title="s.label"
            @click.prevent="navigateTo(s.route)"
          >
            <span :class="s.icon" />
            <span>{{ s.label }}</span>
          </a>
        </div>

        <!-- App context: conversations + slim nav (Agents, User) -->
        <template v-else>
          <div class="sidebar-conv">
            <button class="sidebar-new" @click="openNewMenu">
              <span class="pi pi-plus" />
              <span>New chat</span>
            </button>
            <Menu
              ref="newMenuRef"
              :model="agentMenuItems"
              :popup="true"
              class="newchat-menu"
              :pt="{ root: { style: 'max-height: 66vh; overflow-y: auto' } }"
            />

            <div class="conv-list" @scroll="onListScroll">
              <div
                v-for="item in sidebarItems"
                :key="`${item.kind}-${item.id}`"
                :class="['conv-item', { active: isActiveItem(item) }]"
                @click="openSidebarItem(item)"
              >
                <div class="conv-text">
                  <span class="conv-agent">
                    <template v-if="item.kind === 'agent'">
                      <span v-if="agentEmoji(item.agentId!)">{{ agentEmoji(item.agentId!) }} </span>{{ agentName(item.agentId!) }}
                    </template>
                    <template v-else>
                      <span>⚙️ System Agent</span>
                      <i v-if="item.status === 'awaiting_confirmation'" class="pi pi-exclamation-circle" style="color: var(--p-yellow-500); margin-left: 0.25rem" />
                    </template>
                  </span>
                  <span class="conv-title">{{ item.title }}</span>
                </div>
                <button
                  class="conv-del"
                  aria-label="Delete conversation"
                  @click="deleteSidebarItem(item, $event)"
                >
                  <span class="pi pi-trash" />
                </button>
              </div>
              <p v-if="sidebarItems.length === 0" class="conv-empty">
                No conversations yet
              </p>
            </div>
          </div>

          <div class="sidebar-nav">
            <a
              :class="['sidebar-item', { active: isActive('/agents') }]"
              @click.prevent="navigateTo('/agents')"
            >
              <span class="pi pi-box" />
              <span>Agents</span>
            </a>
            <a class="sidebar-item" @click="toggleUserMenu">
              <span class="pi pi-user" />
              <span>{{ userLabel }}</span>
              <span class="pi pi-ellipsis-v sidebar-item-more" />
            </a>
          </div>
        </template>
      </nav>

      <!-- Mobile Drawer: opened by the hamburger. In Settings it shows the
           section list (with names); otherwise the chat list + app nav. -->
      <Drawer
        v-model:visible="drawerVisible"
        :header="inSettings ? 'Settings' : 'Airlock'"
        :pt="{
          header: { style: 'padding:0.6rem 1rem' },
          content: { style: 'display:flex;flex-direction:column;min-height:0;padding:0' },
        }"
      >
        <!-- Settings context: section list with full labels. -->
        <div v-if="inSettings" class="conv-list settings-list">
          <a
            v-for="s in settingsSections"
            :key="s.route"
            :class="['sidebar-item', { active: route.path === s.route }]"
            @click.prevent="navigateTo(s.route)"
          >
            <span :class="s.icon" />
            <span>{{ s.label }}</span>
          </a>
        </div>

        <!-- App context: conversations + slim nav. -->
        <template v-else>
          <div class="sidebar-conv drawer-conv">
            <button class="sidebar-new" @click="openNewMenu">
              <span class="pi pi-plus" />
              <span>New chat</span>
            </button>
            <div class="conv-list" @scroll="onListScroll">
              <div
                v-for="item in sidebarItems"
                :key="`${item.kind}-${item.id}`"
                :class="['conv-item', { active: isActiveItem(item) }]"
                @click="openSidebarItem(item)"
              >
                <div class="conv-text">
                  <span class="conv-agent">
                    <template v-if="item.kind === 'agent'">
                      <span v-if="agentEmoji(item.agentId!)">{{ agentEmoji(item.agentId!) }} </span>{{ agentName(item.agentId!) }}
                    </template>
                    <template v-else>
                      <span>⚙️ System Agent</span>
                      <i v-if="item.status === 'awaiting_confirmation'" class="pi pi-exclamation-circle" style="color: var(--p-yellow-500); margin-left: 0.25rem" />
                    </template>
                  </span>
                  <span class="conv-title">{{ item.title }}</span>
                </div>
                <button
                  class="conv-del"
                  aria-label="Delete conversation"
                  @click="deleteSidebarItem(item, $event)"
                >
                  <span class="pi pi-trash" />
                </button>
              </div>
            </div>
          </div>
          <div class="sidebar-nav">
            <a
              :class="['sidebar-item', { active: isActive('/agents') }]"
              @click.prevent="navigateTo('/agents')"
            >
              <span class="pi pi-box" />
              <span>Agents</span>
            </a>
            <a class="sidebar-item" @click="toggleUserMenu">
              <span class="pi pi-user" />
              <span>{{ userLabel }}</span>
              <span class="pi pi-ellipsis-v sidebar-item-more" />
            </a>
          </div>
        </template>
      </Drawer>

      <!-- Content -->
      <main :class="['app-content', { 'app-content-flush': backTarget, 'app-content-flush-top': isAgentDetail }]">
        <!-- Key on $route.path forces a fresh component instance whenever a
             path param changes (/agents/:id, .../runs/:runId, .../builds/
             :buildId). Views that capture route.params in setup() — like
             AgentDetailView's `const agentId = route.params.id` — would
             otherwise hold the previous agent's id when the user navigates
             between siblings, breaking WS handler filters and refetches.
             Keyed on path (not fullPath) so query-string-only navigations
             (chat's ?c=convId switcher) still hit each view's in-place
             watcher and don't pay the remount cost. Pinia stores survive.
             A route may set meta.viewKey to pin a constant key across an
             otherwise-remounting transition — system chat does this so the
             new→saved URL change (/system/chat → /system/chat/:id, which
             flips the route name) doesn't remount mid-stream. -->
        <router-view :key="($route.meta.viewKey as string) ?? $route.params.id ?? $route.name" />
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  flex-direction: column;
  /* dvh tracks the visible viewport as the mobile browser's address/tab bars
     show and hide, so the bottom-pinned chat input always sits inside the
     window — no scroll-to-reveal. vh first as a fallback for old engines. */
  height: 100vh;
  height: 100dvh;
  overflow: hidden;
}

.app-toolbar {
  border: 0;
  border-radius: 0;
  /* Compact header — default Toolbar padding (~1rem) is too tall. */
  padding: 0.45rem 0.85rem;
  /* A soft drop-shadow splitter instead of a hard border line. position +
     z-index keep the shadow painted over the scrolling content below. */
  position: relative;
  z-index: 1;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

:root.dark .app-toolbar {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
}

/* Let the start section span the bar so the title zones lay out and ellipsize. */
.app-toolbar :deep(.p-toolbar-start) {
  flex: 1;
  min-width: 0;
}

.bar-start {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
  flex: 1;
  /* Consistent height even on pages with no button (the agents list hides the
     hamburger on desktop) — otherwise the bar collapses to the text line and
     reads shorter than the chat/detail pages. */
  min-height: 2.25rem;
}

.bar-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
  flex: 1;
}

/* Single-line title/brand, truncated with "…" when it outgrows its zone. */
.bar-brand,
.bar-chat-title {
  min-width: 0;
  font-size: 1.15rem;
  font-weight: 700;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.bar-chat-title {
  flex: 1;
}

/* Trim the icon buttons + avatar so they don't re-inflate the bar. */
.app-toolbar :deep(.p-button) {
  width: 2.25rem;
  height: 2.25rem;
}

.app-toolbar :deep(.p-avatar) {
  width: 2rem;
  height: 2rem;
  font-size: 0.85rem;
}

.app-body {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.app-sidebar {
  width: 240px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  min-height: 0;
  /* Separate from the content with a subtle background tint rather than a
     border or shadow — a faint overlay that reads a touch darker than the
     content canvas. Overlay (not a surface token) so it holds up on any
     theme background. */
  background: rgba(0, 0, 0, 0.025);
}

:root.dark .app-sidebar {
  /* Lighter than the dark canvas, mirroring the light-mode tint. */
  background: rgba(255, 255, 255, 0.03);
}

/* Conversation list takes all the slack; nav stays pinned below it. */
.sidebar-conv {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.sidebar-new {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0.6rem;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--p-surface-300);
  border-radius: 0.5rem;
  background: transparent;
  color: inherit;
  font: inherit;
  cursor: pointer;
}

.sidebar-new:hover {
  background: var(--p-surface-100);
}

:root.dark .sidebar-new {
  border-color: var(--p-surface-700);
}

:root.dark .sidebar-new:hover {
  background: var(--p-surface-800);
}

.conv-list {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 0 0.4rem 0.4rem;
  /* Thin, arrow-less scrollbar that only surfaces while scrolling (the
     .scrolling class is toggled by onListScroll) or on hover. */
  scrollbar-width: thin;
  scrollbar-color: transparent transparent;
}

.conv-list.scrolling,
.conv-list:hover {
  scrollbar-color: var(--p-surface-400) transparent;
}

.conv-list::-webkit-scrollbar {
  width: 6px;
}

.conv-list::-webkit-scrollbar-button {
  display: none; /* no up/down arrows */
}

.conv-list::-webkit-scrollbar-thumb {
  background: transparent;
  border-radius: 3px;
}

.conv-list.scrolling::-webkit-scrollbar-thumb,
.conv-list:hover::-webkit-scrollbar-thumb {
  background: var(--p-surface-400);
}

:root.dark .conv-list.scrolling::-webkit-scrollbar-thumb,
:root.dark .conv-list:hover::-webkit-scrollbar-thumb {
  background: var(--p-surface-600);
}

.conv-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.45rem 0.6rem;
  border-radius: 0.5rem;
  cursor: pointer;
  text-decoration: none;
  color: inherit;
}

.conv-text {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.conv-item:hover {
  background: var(--p-surface-100);
}

:root.dark .conv-item:hover {
  background: var(--p-surface-800);
}

.conv-item.active {
  background: var(--p-highlight-background);
  color: var(--p-highlight-color);
}

.conv-del {
  flex-shrink: 0;
  border: 0;
  background: transparent;
  color: inherit;
  opacity: 0;
  cursor: pointer;
  padding: 0.25rem;
  border-radius: 0.35rem;
  font-size: 0.8rem;
}

.conv-item:hover .conv-del {
  opacity: 0.55;
}

.conv-del:hover {
  opacity: 1 !important;
  background: var(--p-surface-200);
}

:root.dark .conv-del:hover {
  background: var(--p-surface-700);
}

.conv-agent {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  opacity: 0.6;
}

.conv-title {
  font-size: 0.9rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.conv-empty {
  padding: 1rem 0.75rem;
  font-size: 0.85rem;
  color: var(--p-text-muted-color);
  text-align: center;
}

.sidebar-nav {
  flex-shrink: 0;
  /* Pin to the bottom of the sidebar even if the conversation list is short. */
  margin-top: auto;
  padding: 0.25rem 0;
}

.sidebar-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 1rem;
  text-decoration: none;
  color: inherit;
  cursor: pointer;
}

.sidebar-item.active {
  font-weight: 600;
  color: var(--p-primary-color);
}

/* Trailing 3-dots on a row that opens a popup menu (e.g. User). */
.sidebar-item-more {
  margin-left: auto;
  font-size: 0.8rem;
  opacity: 0.55;
}

/* Settings context: the section list reads like a nav, with a highlighted
   active row (rather than the bottom-pinned app nav's bare bold). */
.settings-list {
  padding-top: 0.5rem;
}
.settings-list .sidebar-item {
  margin: 0 0.4rem;
  border-radius: 0.5rem;
}
.settings-list .sidebar-item:hover {
  background: var(--p-surface-100);
}
:root.dark .settings-list .sidebar-item:hover {
  background: var(--p-surface-800);
}
.settings-list .sidebar-item.active {
  background: var(--p-highlight-background);
  color: var(--p-highlight-color);
  font-weight: 500;
}

/* The drawer content is a flex column (set via the Drawer's pt, since it's
   teleported out of this scoped tree): the conversation list fills the slack
   and the Agents/User nav pins to the bottom (via sidebar-nav margin-top:auto)
   rather than trailing the list mid-drawer. */
.drawer-conv {
  flex: 1;
  min-height: 0;
}

.app-content {
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
  /* Pin the horizontal axis. overflow-y:auto alone forces overflow-x from
     visible to auto (CSS spec), making this a horizontal scroll container —
     which turns AgentDetailView's full-bleed sticky nav (negative side
     margins) into a phantom horizontal scrollbar once the vertical scrollbar
     claims its width. We never want horizontal page scroll; inner content
     (tables, code) scrolls within itself. */
  overflow-x: hidden;
  min-height: 0;
}

/* Chat manages its own internal padding (input row, messages, etc.) and
   wants to fill the column edge-to-edge so the message list scrolls
   right up to the top bar. Top drops to 0 to butt against the bar; the
   bottom keeps a small gutter so the input row doesn't sit on the
   viewport edge. */
/* Chat fills the content area edge-to-edge — no gutter revealing the page
   background around it. The composer and message list own their own insets. */
.app-content-flush {
  padding: 0;
}

/* AgentDetailView's sticky section nav wants top: 0 to actually be at the
 * top of the visible scroll area. Drop just the top padding; the side
 * padding stays standard. */
.app-content-flush-top {
  padding-top: 0;
}

/* Hide sidebar on mobile, show hamburger */
.mobile-menu-btn {
  display: none;
}

@media (max-width: 768px) {
  .app-sidebar {
    display: none;
  }
  .mobile-menu-btn {
    display: inline-flex;
  }
  /* Settings on mobile uses the same hamburger → drawer as the rest of the
     app; the drawer renders the section list (with names) when in Settings. */

  /* No room for the "Airlock" brand next to the chat title on mobile — show
     just the chat title (the hamburger + back still sit to its left). */
  .bar-start.is-chat .bar-brand {
    display: none;
  }
  .bar-start.is-chat .bar-left {
    flex: 0 0 auto;
  }
}

/* Desktop chat: split the bar into a sidebar-width brand zone + a title that
   lines up with the message column. The left padding is dropped from the
   toolbar and restored inside the brand zone so 240px lands exactly on the
   sidebar edge; the title's 2.5rem inset matches .chat-messages on desktop. */
@media (min-width: 769px) {
  .app-toolbar-chat {
    padding-left: 0;
  }
  .bar-start.is-chat {
    gap: 0;
  }
  .bar-start.is-chat .bar-left {
    flex: 0 0 240px;
    padding-left: 0.85rem;
    box-sizing: border-box;
  }
  .bar-start.is-chat .bar-chat-title {
    padding-left: 2.5rem;
  }
}
</style>

<!-- Non-scoped: the New-chat Menu is a popup teleported to <body>, so scoped
     styles can't reach it. Keep its scrollbar thin + arrow-less to match. -->
<style>
.newchat-menu {
  scrollbar-width: thin;
}
.newchat-menu::-webkit-scrollbar {
  width: 6px;
}
.newchat-menu::-webkit-scrollbar-button {
  display: none;
}
.newchat-menu::-webkit-scrollbar-thumb {
  background: var(--p-surface-400);
  border-radius: 3px;
}
</style>
