<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useAuthStore } from '@/stores/auth'
import { useAgentsStore } from '@/stores/agents'
import { useConversationsStore } from '@/stores/conversations'
import { useChatStore } from '@/stores/chat'
import { useConfirm } from 'primevue/useconfirm'
import { useTheme } from '@/composables/useTheme'
import type { ConversationInfo } from '@/gen/airlock/v1/types_pb'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const agentsStore = useAgentsStore()
const conversationsStore = useConversationsStore()
const chat = useChatStore()
const confirm = useConfirm()
const toast = useToast()
const { isDark, toggle: toggleTheme } = useTheme()

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

const menuItems = computed(() => {
  const items = [
    { label: 'Agents', icon: 'pi pi-box', route: '/agents' },
  ]
  if (auth.isAdmin) {
    items.push(
      { label: 'Providers', icon: 'pi pi-server', route: '/providers' },
      { label: 'Bridges', icon: 'pi pi-link', route: '/bridges' },
      { label: 'Users', icon: 'pi pi-users', route: '/users' },
    )
  }
  items.push(
    { label: 'Git Credentials', icon: 'pi pi-key', route: '/settings/git-credentials' },
    { label: 'Settings', icon: 'pi pi-cog', route: '/settings' },
  )
  return items
})

const userMenuRef = ref()
const userMenuItems = ref([
  {
    label: 'Settings',
    icon: 'pi pi-cog',
    command: () => router.push('/settings'),
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

function isActive(path: string) {
  return route.path.startsWith(path)
}

// "New chat" picks an agent first (a conversation always belongs to one).
// The freshly-opened chat starts in its empty "new thread" state; the row
// appears in the sidebar once the first message is sent.
const newMenuRef = ref()
const agentMenuItems = computed(() => {
  if (agentsStore.agents.length === 0) {
    return [{ label: 'No agents yet', disabled: true }]
  }
  return agentsStore.agents.map(a => ({
    label: a.name,
    icon: 'pi pi-box',
    command: () => {
      router.push({ path: `/agents/${a.id}/chat` })
      drawerVisible.value = false
    },
  }))
})
function openNewMenu(event: Event) {
  newMenuRef.value.toggle(event)
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

function openConversation(c: ConversationInfo) {
  router.push({ path: `/agents/${c.agentId}/chat`, query: { c: c.id } })
  drawerVisible.value = false
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
      // If the open thread was just deleted, drop ?c= so the chat view
      // reloads into the agent's next thread (or empty state).
      if (wasActive) {
        router.replace({ path: `/agents/${c.agentId}/chat` })
      }
    },
  })
}

// On /agents/:id/chat we hoist the back affordance into the top bar so
// the chat view itself doesn't need a header row. backTarget is null on
// every other route — the button doesn't render.
const backTarget = computed<string | null>(() => {
  const m = /^\/agents\/([^/]+)\/chat$/.exec(route.path)
  return m ? `/agents/${m[1]}` : null
})

function navigateTo(path: string) {
  router.push(path)
  drawerVisible.value = false
}

const userInitial = computed(() => {
  const name = auth.user?.displayName || auth.user?.email || '?'
  return name.charAt(0).toUpperCase()
})

onMounted(() => {
  // Both back the sidebar; failures are non-fatal (empty list / 'Agent'
  // fallback) and self-heal on the next navigation.
  agentsStore.fetchAgents().catch(() => {})
  conversationsStore.load().catch(() => {})
})
</script>

<template>
  <div class="app-layout">
    <!-- Top Toolbar -->
    <Toolbar class="app-toolbar">
      <template #start>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <Button
            icon="pi pi-bars"
            text
            severity="secondary"
            class="mobile-menu-btn"
            @click="drawerVisible = true"
          />
          <Button
            v-if="backTarget"
            icon="pi pi-arrow-left"
            text
            severity="secondary"
            aria-label="Back"
            @click="router.push(backTarget)"
          />
          <span style="font-size: 1.15rem; font-weight: 700">Airlock</span>
        </div>
      </template>
      <template #end>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <ToggleSwitch v-model="isDark" />
          <i :class="isDark ? 'pi pi-moon' : 'pi pi-sun'" style="font-size: 0.875rem" />
          <Avatar
            :label="userInitial"
            shape="circle"
            style="cursor: pointer"
            @click="toggleUserMenu"
          />
          <Menu ref="userMenuRef" :model="userMenuItems" :popup="true" />
        </div>
      </template>
    </Toolbar>

    <div class="app-body">
      <!-- Desktop Sidebar: conversations on top, app nav pinned bottom -->
      <nav class="app-sidebar">
        <div class="sidebar-conv">
          <button class="sidebar-new" @click="openNewMenu">
            <span class="pi pi-plus" />
            <span>New chat</span>
          </button>
          <Menu ref="newMenuRef" :model="agentMenuItems" :popup="true" />

          <div class="conv-list">
            <div
              v-for="c in conversationsStore.list"
              :key="c.id"
              :class="['conv-item', { active: isActiveConv(c) }]"
              @click="openConversation(c)"
            >
              <div class="conv-text">
                <span class="conv-agent"><span v-if="agentEmoji(c.agentId)">{{ agentEmoji(c.agentId) }} </span>{{ agentName(c.agentId) }}</span>
                <span class="conv-title">{{ c.title || 'Untitled conversation' }}</span>
              </div>
              <button
                class="conv-del"
                aria-label="Delete conversation"
                @click="deleteConversation(c, $event)"
              >
                <span class="pi pi-trash" />
              </button>
            </div>
            <p v-if="conversationsStore.list.length === 0" class="conv-empty">
              No conversations yet
            </p>
          </div>
        </div>

        <div class="sidebar-nav">
          <a
            v-for="item in menuItems"
            :key="item.route"
            :class="['sidebar-item', { active: isActive(item.route) }]"
            @click.prevent="navigateTo(item.route)"
          >
            <span :class="item.icon" />
            <span>{{ item.label }}</span>
          </a>
        </div>
      </nav>

      <!-- Mobile Drawer: same content -->
      <Drawer v-model:visible="drawerVisible" header="Airlock">
        <div class="sidebar-conv drawer-conv">
          <button class="sidebar-new" @click="openNewMenu">
            <span class="pi pi-plus" />
            <span>New chat</span>
          </button>
          <div class="conv-list">
            <div
              v-for="c in conversationsStore.list"
              :key="c.id"
              :class="['conv-item', { active: isActiveConv(c) }]"
              @click="openConversation(c)"
            >
              <div class="conv-text">
                <span class="conv-agent"><span v-if="agentEmoji(c.agentId)">{{ agentEmoji(c.agentId) }} </span>{{ agentName(c.agentId) }}</span>
                <span class="conv-title">{{ c.title || 'Untitled conversation' }}</span>
              </div>
              <button
                class="conv-del"
                aria-label="Delete conversation"
                @click="deleteConversation(c, $event)"
              >
                <span class="pi pi-trash" />
              </button>
            </div>
          </div>
        </div>
        <div class="sidebar-nav">
          <a
            v-for="item in menuItems"
            :key="item.route"
            :class="['sidebar-item', { active: isActive(item.route) }]"
            @click.prevent="navigateTo(item.route)"
          >
            <span :class="item.icon" />
            <span>{{ item.label }}</span>
          </a>
        </div>
      </Drawer>

      <!-- Content -->
      <main :class="['app-content', { 'app-content-flush': backTarget }]">
        <!-- Key on $route.path forces a fresh component instance whenever a
             path param changes (/agents/:id, .../runs/:runId, .../builds/
             :buildId). Views that capture route.params in setup() — like
             AgentDetailView's `const agentId = route.params.id` — would
             otherwise hold the previous agent's id when the user navigates
             between siblings, breaking WS handler filters and refetches.
             Keyed on path (not fullPath) so query-string-only navigations
             (chat's ?c=convId switcher) still hit each view's in-place
             watcher and don't pay the remount cost. Pinia stores survive. -->
        <router-view :key="$route.path" />
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

.app-toolbar {
  border-radius: 0;
  border-left: 0;
  border-right: 0;
  border-top: 0;
  /* Compact header — default Toolbar padding (~1rem) is too tall. */
  padding: 0.45rem 0.85rem;
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
  border-right: 1px solid var(--p-surface-200);
}

:root.dark .app-sidebar {
  border-right-color: var(--p-surface-700);
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
  border-top: 1px solid var(--p-surface-200);
  padding: 0.25rem 0;
}

:root.dark .sidebar-nav {
  border-top-color: var(--p-surface-700);
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

.drawer-conv {
  height: 60vh;
}

.app-content {
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
  min-height: 0;
}

/* Chat manages its own internal padding (input row, messages, etc.) and
   wants to fill the column edge-to-edge so the message list scrolls
   right up to the top bar. Top drops to 0 to butt against the bar; the
   bottom keeps a small gutter so the input row doesn't sit on the
   viewport edge. */
.app-content-flush {
  padding: 0 1rem 1rem;
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
}
</style>
