import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson, create } from '@bufbuild/protobuf'
import api from '@/api/client'
import { registerPasskey as registerPasskeyCeremony } from '@/api/passkeys'
import type { Passkey } from '@/gen/airlock/v1/types_pb'
import {
  ListPasskeysResponseSchema,
  RenamePasskeyRequestSchema,
  SetPasswordRequestSchema,
} from '@/gen/airlock/v1/api_pb'

export const usePasskeysStore = defineStore('passkeys', () => {
  const passkeys = ref<Passkey[]>([])
  const loading = ref(false)

  async function fetchPasskeys() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/me/passkeys')
      passkeys.value = fromJson(ListPasskeysResponseSchema, data).passkeys
    } finally {
      loading.value = false
    }
  }

  async function addPasskey(name: string): Promise<Passkey> {
    const pk = await registerPasskeyCeremony(name)
    passkeys.value.push(pk)
    return pk
  }

  async function renamePasskey(id: string, friendlyName: string) {
    const req = create(RenamePasskeyRequestSchema, { friendlyName })
    await api.patch(`/api/v1/me/passkeys/${id}`, toJson(RenamePasskeyRequestSchema, req))
    const pk = passkeys.value.find((p) => p.id === id)
    if (pk) pk.friendlyName = friendlyName
  }

  async function deletePasskey(id: string) {
    await api.delete(`/api/v1/me/passkeys/${id}`)
    passkeys.value = passkeys.value.filter((p) => p.id !== id)
  }

  async function setPassword(password: string) {
    const req = create(SetPasswordRequestSchema, { password })
    await api.post('/api/v1/me/password', toJson(SetPasswordRequestSchema, req))
  }

  async function removePassword() {
    await api.delete('/api/v1/me/password')
  }

  return {
    passkeys,
    loading,
    fetchPasskeys,
    addPasskey,
    renamePasskey,
    deletePasskey,
    setPassword,
    removePassword,
  }
})
