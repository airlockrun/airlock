<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useTheme } from '@/composables/useTheme'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const { isDark, toggle: toggleTheme } = useTheme()

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
  items.push({ label: 'Settings', icon: 'pi pi-cog', route: '/settings' })
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
          <span style="font-size: 1.25rem; font-weight: 700">Airlock</span>
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
      <!-- Desktop Sidebar -->
      <nav class="app-sidebar">
        <Menu :model="menuItems" class="sidebar-menu">
          <template #item="{ item, props }">
            <a
              v-bind="props.action"
              :class="['sidebar-item', { active: isActive(item.route) }]"
              @click.prevent="navigateTo(item.route)"
            >
              <span :class="item.icon" />
              <span>{{ item.label }}</span>
            </a>
          </template>
        </Menu>
      </nav>

      <!-- Mobile Drawer -->
      <Drawer v-model:visible="drawerVisible" header="Airlock">
        <Menu :model="menuItems">
          <template #item="{ item, props }">
            <a
              v-bind="props.action"
              :class="['sidebar-item', { active: isActive(item.route) }]"
              @click.prevent="navigateTo(item.route)"
            >
              <span :class="item.icon" />
              <span>{{ item.label }}</span>
            </a>
          </template>
        </Menu>
      </Drawer>

      <!-- Content -->
      <main :class="['app-content', { 'app-content-flush': backTarget }]">
        <router-view />
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
}

.app-body {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.app-sidebar {
  width: 220px;
  border-right: 1px solid var(--p-surface-200);
  flex-shrink: 0;
}

:root.dark .app-sidebar {
  border-right-color: var(--p-surface-700);
}

.sidebar-menu {
  border: none;
  border-radius: 0;
  width: 100%;
}

.sidebar-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  text-decoration: none;
  color: inherit;
  cursor: pointer;
}

.sidebar-item.active {
  font-weight: 600;
  color: var(--p-primary-color);
}

.app-content {
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
  min-height: 0;
}

/* Chat manages its own internal padding (input row, messages, etc.) and
   wants to fill the column edge-to-edge so the message list scrolls
   right up to the top bar. Side padding is kept as a small breathing
   gutter; top/bottom drop to 0. */
.app-content-flush {
  padding: 0 1rem;
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
