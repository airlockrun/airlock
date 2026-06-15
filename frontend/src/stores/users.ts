import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { User, UserSummary } from '@/gen/airlock/v1/types_pb'
import {
  ListUsersResponseSchema,
  ListSelectableUsersResponseSchema,
  CreateUserResponseSchema,
} from '@/gen/airlock/v1/api_pb'

export const useUsersStore = defineStore('users', () => {
  const users = ref<User[]>([])
  const selectable = ref<UserSummary[]>([])
  const loading = ref(false)

  async function fetchUsers() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/users')
      users.value = fromJson(ListUsersResponseSchema, data).users
    } finally {
      loading.value = false
    }
  }

  async function fetchSelectable() {
    const { data } = await api.get('/api/v1/users/selectable')
    selectable.value = fromJson(ListSelectableUsersResponseSchema, data).users
  }

  // createUser provisions a user. The backend generates a one-time temporary
  // password and returns it once (the user must change it or register a passkey
  // on first login); surface it to the admin to hand off.
  async function createUser(payload: { email: string; displayName: string; tenantRole: string }): Promise<string> {
    const { data } = await api.post('/api/v1/users', payload)
    const resp = fromJson(CreateUserResponseSchema, data)
    users.value.unshift(resp.user!)
    return resp.tempPassword
  }

  async function updateUserRole(id: string, role: string) {
    await api.patch(`/api/v1/users/${id}`, { tenantRole: role })
    // Re-fetch to get updated proto
    await fetchUsers()
  }

  async function deleteUser(id: string) {
    await api.delete(`/api/v1/users/${id}`)
    users.value = users.value.filter((u) => u.id !== id)
  }

  return { users, selectable, loading, fetchUsers, fetchSelectable, createUser, updateUserRole, deleteUser }
})
