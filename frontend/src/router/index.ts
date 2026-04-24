import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

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

export default router
