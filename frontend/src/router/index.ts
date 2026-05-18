import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useAgentsStore } from '@/stores/agents'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    // Public auth routes
    {
      path: '/login',
      component: () => import('@/layouts/AuthLayout.vue'),
      children: [
        { path: '', name: 'login', component: () => import('@/views/LoginView.vue') },
      ],
    },
    {
      path: '/activate',
      component: () => import('@/layouts/AuthLayout.vue'),
      children: [
        { path: '', name: 'activate', component: () => import('@/views/ActivateView.vue') },
      ],
    },
    {
      path: '/change-password',
      component: () => import('@/layouts/AuthLayout.vue'),
      children: [
        { path: '', name: 'change-password', component: () => import('@/views/ChangePasswordView.vue') },
      ],
    },
    {
      path: '/auth/relay',
      component: () => import('@/layouts/AuthLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', name: 'auth-relay', component: () => import('@/views/AuthRelayView.vue') },
      ],
    },

    // Authenticated routes
    {
      path: '/',
      component: () => import('@/layouts/AppLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', redirect: '/agents' },
        { path: 'agents', name: 'agents', component: () => import('@/views/AgentListView.vue') },
        { path: 'agents/create', name: 'agent-create', component: () => import('@/views/AgentCreateView.vue') },
        { path: 'agents/:id', name: 'agent-detail', component: () => import('@/views/AgentDetailView.vue') },
        { path: 'agents/:id/chat', name: 'agent-chat', component: () => import('@/views/AgentChatView.vue') },
        { path: 'agents/:id/runs/:runId', name: 'run-detail', component: () => import('@/views/RunDetailView.vue') },
        { path: 'agents/:id/builds/:buildId', name: 'build-detail', component: () => import('@/views/BuildDetailView.vue') },
        { path: 'providers', name: 'providers', component: () => import('@/views/ProvidersView.vue'), meta: { requiresAdmin: true } },
        { path: 'bridges', name: 'bridges', component: () => import('@/views/BridgesView.vue'), meta: { requiresAdmin: true } },
        { path: 'users', name: 'users', component: () => import('@/views/UsersView.vue'), meta: { requiresAdmin: true } },
        { path: 'settings', name: 'settings', component: () => import('@/views/SettingsView.vue') },
        { path: 'link-identity', name: 'link-identity', component: () => import('@/views/LinkIdentityView.vue') },
        // OAuth consent — landing page for /oauth/authorize when the
        // user is logged in and a fresh grant is required. Auth guard
        // bounces unauthed users to /login?redirect=...
        { path: 'oauth/consent', name: 'oauth-consent', component: () => import('@/views/ConsentView.vue') },
      ],
    },

    // 404
    { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('@/views/NotFoundView.vue') },
  ],
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.matched.some((record) => record.meta.requiresAuth) && !auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  // Redirect away from login if already authenticated.
  // Don't redirect from activate — user may be on step 2 (provider setup) after creating account.
  if (auth.isAuthenticated && to.name === 'login') {
    return { name: 'agents' }
  }

  if (to.meta.requiresAdmin && !auth.isAdmin) {
    return { name: 'agents' }
  }

  // Force password change.
  if (auth.isAuthenticated && auth.mustChangePassword && to.name !== 'change-password') {
    return { name: 'change-password' }
  }
})

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function isUuid(v: unknown): v is string {
  return typeof v === 'string' && UUID_RE.test(v)
}

// Vanity-URL layer. Routes and every view operate on the agent UUID
// (route.params.id stays a UUID — no view code changes). The address
// bar, however, shows the agent's *current* slug:
//   - a slug in the URL (cold deep-link or post-rename) is resolved to
//     its UUID here and the navigation re-entered canonically;
//   - an unknown slug (agent renamed since the link was shared) bounces
//     to the agent list with a notice instead of a hard 404.
router.beforeEach(async (to) => {
  const raw = to.params.id
  if (typeof raw !== 'string' || !raw) return

  // Ensure the slug↔id map is available for both the resolve below and
  // the afterEach repaint (covers a cold uuid deep-link too).
  const agentsStore = useAgentsStore()
  if (agentsStore.agents.length === 0) {
    try {
      await agentsStore.fetchAgents()
    } catch {
      /* unauth/⁠offline — fall through; isUuid passes or redirect below */
    }
  }

  if (isUuid(raw)) return // canonical already; afterEach paints the slug

  const match = agentsStore.agents.find((a) => a.slug === raw)
  if (!match) {
    return { name: 'agents', query: { staleAgent: raw } }
  }
  // Re-enter the same route with the canonical UUID so all existing
  // route.params.id (UUID) view logic keeps working untouched.
  return { ...to, params: { ...to.params, id: match.id } }
})

// Cosmetic repaint: on the canonical UUID route, swap the UUID segment
// for the agent's current slug WITHOUT a router navigation, so
// route.params.id stays the UUID for view logic. history.state is
// preserved so vue-router's scroll/nav bookkeeping is intact.
router.afterEach((to) => {
  const id = to.params.id
  if (!isUuid(id)) return
  const match = useAgentsStore().agents.find((a) => a.id === id)
  if (!match || !match.slug) return
  const pretty = to.fullPath.replace(id, match.slug)
  if (pretty !== to.fullPath) {
    history.replaceState(history.state, '', pretty)
  }
})

export default router
