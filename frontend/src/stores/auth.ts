import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import type { User } from '@/gen/airlock/v1/types_pb'
import { TenantRole, UserSchema } from '@/gen/airlock/v1/types_pb'
import {
  LoginResponseSchema,
  RegisterResponseSchema,
  RefreshResponseSchema,
  ChangePasswordResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
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

  async function init() {
    const refreshToken = localStorage.getItem('refresh_token')
    if (!refreshToken) return
    try {
      await refresh()
      await fetchMe()
      connectWS()
    } catch {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
    }
  }

  async function login(email: string, password: string) {
    const { data } = await api.post('/auth/login', { email, password })
    const response = fromJson(LoginResponseSchema, data)
    localStorage.setItem('access_token', response.accessToken)
    localStorage.setItem('refresh_token', response.refreshToken)
    user.value = response.user ?? null
    connectWS()
  }

  async function activate(email: string, password: string, displayName: string, activationCode?: string) {
    const { data } = await api.post('/auth/activate', { email, password, displayName, activationCode })
    const response = fromJson(RegisterResponseSchema, data)
    localStorage.setItem('access_token', response.accessToken)
    localStorage.setItem('refresh_token', response.refreshToken)
    user.value = response.user ?? null
    connectWS()
  }

  async function refresh() {
    const refreshToken = localStorage.getItem('refresh_token')
    if (!refreshToken) throw new Error('no refresh token')
    const { data } = await api.post('/auth/refresh', { refreshToken })
    const response = fromJson(RefreshResponseSchema, data)
    localStorage.setItem('access_token', response.accessToken)
  }

  async function fetchMe() {
    const { data } = await api.get('/api/v1/me')
    user.value = fromJson(UserSchema, data)
  }

  async function changePassword(currentPassword: string, newPassword: string) {
    const { data } = await api.post('/auth/change-password', { currentPassword, newPassword })
    const response = fromJson(ChangePasswordResponseSchema, data)
    localStorage.setItem('access_token', response.accessToken)
    localStorage.setItem('refresh_token', response.refreshToken)
    if (user.value) {
      user.value.mustChangePassword = false
    }
  }

  function logout() {
    user.value = null
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    ws.disconnect()
  }

  function connectWS() {
    const token = localStorage.getItem('access_token')
    if (token) {
      ws.connect(token)
    }
  }

  return {
    user,
    isAuthenticated,
    isAdmin,
    isManagerOrAdmin,
    mustChangePassword,
    init,
    login,
    activate,
    refresh,
    fetchMe,
    changePassword,
    logout,
  }
})
