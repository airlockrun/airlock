<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import type { GitCredential } from '@/gen/airlock/v1/types_pb'

const store = useGitCredentialsStore()
const confirm = useConfirm()
const toast = useToast()

const dialogVisible = ref(false)
const newName = ref('')
const newToken = ref('')
const saving = ref(false)

function openCreate() {
  newName.value = ''
  newToken.value = ''
  dialogVisible.value = true
}

async function save() {
  if (!newName.value.trim() || !newToken.value.trim()) return
  saving.value = true
  try {
    await store.createCredential(newName.value.trim(), newToken.value.trim())
    toast.add({
      severity: 'success',
      summary: 'Credential saved',
      detail: 'Airlock does not store the plaintext token. Keep your own copy if you need this PAT elsewhere.',
      life: 7000,
    })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({
      severity: 'error',
      summary: err.response?.data?.error || 'Failed to save credential',
      life: 5000,
    })
  } finally {
    saving.value = false
  }
}

function onDelete(c: GitCredential) {
  confirm.require({
    header: `Delete "${c.name}"?`,
    message: 'Agents using this credential will lose access to their git remote until you attach a different one.',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Delete',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteCredential(c.id)
        toast.add({ severity: 'info', summary: 'Credential deleted', life: 3000 })
      } catch (err: any) {
        toast.add({
          severity: 'error',
          summary: err.response?.data?.error || 'Failed to delete credential',
          life: 5000,
        })
      }
    },
  })
}

function formatTimestamp(ts: any): string {
  if (!ts) return '—'
  if (ts.seconds !== undefined) {
    return new Date(Number(ts.seconds) * 1000).toLocaleString()
  }
  return '—'
}

onMounted(() => {
  store.fetchCredentials()
})
</script>

<template>
  <div style="padding: 1.5rem; max-width: 60rem">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem">
      <div>
        <h2 style="margin: 0">Git Credentials</h2>
        <p style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">
          Personal access tokens for connecting agents to external git remotes (GitHub, GitLab, Bitbucket, self-hosted).
        </p>
      </div>
      <Button label="Add PAT" icon="pi pi-plus" @click="openCreate" />
    </div>

    <DataTable v-if="!store.loading || store.credentials.length > 0" :value="store.credentials" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No git credentials yet. Add a PAT to connect an agent to an external repo.
        </div>
      </template>
      <Column field="name" header="Name" />
      <Column field="type" header="Type">
        <template #body="{ data }">
          <Tag :value="data.type" severity="secondary" />
        </template>
      </Column>
      <Column header="Created">
        <template #body="{ data }">{{ formatTimestamp(data.createdAt) }}</template>
      </Column>
      <Column header="Last used">
        <template #body="{ data }">{{ formatTimestamp(data.lastUsedAt) }}</template>
      </Column>
      <Column header="">
        <template #body="{ data }">
          <Button icon="pi pi-trash" severity="danger" size="small" text @click="onDelete(data)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}]">
      <Column header="Name"><template #body><Skeleton /></template></Column>
      <Column header="Type"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header="Created"><template #body><Skeleton /></template></Column>
      <Column header="Last used"><template #body><Skeleton /></template></Column>
      <Column header=""><template #body><Skeleton width="2rem" /></template></Column>
    </DataTable>

    <Dialog v-model:visible="dialogVisible" header="Add Personal Access Token" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <Message severity="info" :closable="false" style="font-size: 0.8rem">
          Create a fine-scoped PAT on your git provider (e.g. GitHub → Settings → Developer Settings → Tokens) with permission to read and write to the repos you want to attach.
          Airlock encrypts the token at rest and does not store the plaintext.
        </Message>
        <FloatLabel>
          <InputText id="cred-name" v-model="newName" style="width: 100%" autocomplete="off" />
          <label for="cred-name">Name (e.g. "GitHub Personal")</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="cred-token" v-model="newToken" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="cred-token">Token</label>
        </FloatLabel>
        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
          <Button
            label="Save"
            :loading="saving"
            :disabled="!newName.trim() || !newToken.trim()"
            @click="save"
          />
        </div>
      </div>
    </Dialog>
  </div>
</template>
