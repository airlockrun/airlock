import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api, { clearAccessToken, isAuthRejection, refreshAccessToken, setAccessToken } from '@/api/client'
import { passkeyLogin, registerPasskey } from '@/api/passkeys'
import { ws } from '@/api/ws'
import type { User } from '@/gen/airlock/v1/types_pb'
import { TenantRole } from '@/gen/airlock/v1/types_pb'
import {
  LoginResponseSchema,
  MeResponseSchema,
  RegisterResponseSchema,
  ChangePasswordResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  // Tenant-axis Actions the current user satisfies, mirrored from
  // GET /api/v1/me. Populated on fetchMe; replace per-component role
  // checks with auth.can('tenant.bridge.create') etc. Empty until the
  // first /me round-trip, so call fetchMe right after login/activate.
  const tenantPermissions = ref<Set<string>>(new Set())
  const isAuthenticated = computed(() => user.value !== null)
  const isAdmin = computed(
    () => user.value?.tenantRole === TenantRole.ADMIN,
  )
  // Manager OR admin — i.e. anyone allowed to create agents and bridges.
  // Plain users are read-only on those surfaces.
  const isManagerOrAdmin = computed(
    () =>
      user.value?.tenantRole === TenantRole.ADMIN ||
      user.value?.tenantRole === TenantRole.MANAGER,
  )
  const mustChangePassword = computed(() => user.value?.mustChangePassword === true)

  function can(action: string): boolean {
    return tenantPermissions.value.has(action)
  }

  async function init() {
    // Token material belongs in memory or HttpOnly cookies, never persistent
    // browser storage.
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    try {
      await refresh()
      await fetchMe()
      connectWS()
    } catch (err) {
      // Only evict credentials when the server actively rejected the
      // refresh token (401/403). A transport error or 5xx is a server
      // restart / Caddy upstream-down. The HttpOnly refresh cookie remains
      // available for the next initialization or request after recovery.
      if (isAuthRejection(err)) {
        clearAccessToken()
      }
    }
  }

  async function login(email: string, password: string) {
    const { data } = await api.post('/auth/login', { email, password })
    const response = fromJson(LoginResponseSchema, data)
    setAccessToken(response.accessToken)
    user.value = response.user ?? null
    // LoginResponse doesn't carry permissions; pull them so nav/route
    // guards work on the first navigation after login.
    await fetchMe()
    connectWS()
  }

  // loginWithPasskey runs the WebAuthn assertion ceremony. An empty email is a
  // usernameless (discoverable) login; a provided email scopes to that account.
  async function loginWithPasskey(email?: string) {
    const response = await passkeyLogin(email)
    setAccessToken(response.accessToken)
    user.value = response.user ?? null
    await fetchMe()
    connectWS()
  }

  // registerPasskeyAndSecure enrolls a passkey for the signed-in user. When the
  // account is in the forced-secure state, registering a passkey clears the
  // flag on the backend; refresh + fetchMe pull the cleared state so the route
  // guard releases.
  async function registerPasskeyAndSecure(name: string) {
    await registerPasskey(name)
    await refresh()
    await fetchMe()
  }

  async function activate(email: string, password: string, displayName: string, activationCode?: string) {
    const { data } = await api.post('/auth/activate', { email, password, displayName, activationCode })
    const response = fromJson(RegisterResponseSchema, data)
    setAccessToken(response.accessToken)
    user.value = response.user ?? null
    await fetchMe()
    connectWS()
  }

  async function refresh() {
    await refreshAccessToken()
  }

  async function fetchMe() {
    const { data } = await api.get('/api/v1/me')
    const me = fromJson(MeResponseSchema, data)
    user.value = me.user ?? null
    tenantPermissions.value = new Set(me.tenantPermissions)
  }

  async function changePassword(currentPassword: string, newPassword: string) {
    const { data } = await api.post('/auth/change-password', { currentPassword, newPassword })
    const response = fromJson(ChangePasswordResponseSchema, data)
    setAccessToken(response.accessToken)
    if (user.value) {
      user.value.mustChangePassword = false
    }
  }

  async function logout() {
    await api.post('/auth/logout', {})
    user.value = null
    tenantPermissions.value = new Set()
    clearAccessToken()
    ws.disconnect()
  }

  function connectWS() {
    ws.connect()
  }

  return {
    user,
    tenantPermissions,
    isAuthenticated,
    isAdmin,
    isManagerOrAdmin,
    mustChangePassword,
    can,
    init,
    login,
    loginWithPasskey,
    registerPasskeyAndSecure,
    activate,
    refresh,
    fetchMe,
    changePassword,
    logout,
  }
})
