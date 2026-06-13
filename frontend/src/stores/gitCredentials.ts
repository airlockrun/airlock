import { ref } from 'vue'
import { defineStore } from 'pinia'
import { fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { GitCredential } from '@/gen/airlock/v1/types_pb'
import {
  CreateGitCredentialRequestSchema,
  CreateGitCredentialResponseSchema,
  ListGitCredentialsResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import { create } from '@bufbuild/protobuf'

export const useGitCredentialsStore = defineStore('gitCredentials', () => {
  const credentials = ref<GitCredential[]>([])
  const loading = ref(false)

  async function fetchCredentials() {
    loading.value = true
    try {
      const { data } = await api.get('/api/v1/me/git/credentials')
      credentials.value = fromJson(ListGitCredentialsResponseSchema, data).credentials
    } finally {
      loading.value = false
    }
  }

  async function createCredential(name: string, token: string): Promise<GitCredential> {
    const req = create(CreateGitCredentialRequestSchema, { type: 'pat', name, token })
    const { data } = await api.post(
      '/api/v1/me/git/credentials',
      toJson(CreateGitCredentialRequestSchema, req),
    )
    const cred = fromJson(CreateGitCredentialResponseSchema, data).credential!
    credentials.value.push(cred)
    return cred
  }

  async function deleteCredential(id: string) {
    await api.delete(`/api/v1/me/git/credentials/${id}`)
    credentials.value = credentials.value.filter((c) => c.id !== id)
  }

  return { credentials, loading, fetchCredentials, createCredential, deleteCredential }
})
