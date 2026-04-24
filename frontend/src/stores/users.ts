import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { User } from '@/gen/airlock/v1/types_pb'
import { ListUsersResponseSchema, CreateUserResponseSchema } from '@/gen/airlock/v1/api_pb'

export const useUsersStore = defineStore('users', () => {
  const users = ref<User[]>([])
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

  async function createUser(payload: { email: string; password: string; displayName: string; tenantRole: string }) {
    const { data } = await api.post('/api/v1/users', payload)
    users.value.unshift(fromJson(CreateUserResponseSchema, data).user!)
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

  return { users, loading, fetchUsers, createUser, updateUserRole, deleteUser }
})
