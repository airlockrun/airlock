<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useResourcesStore } from '@/stores/resources'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import type { GitCredential } from '@/gen/airlock/v1/types_pb'

const resources = useResourcesStore()
const git = useGitCredentialsStore()
const confirm = useConfirm()
const toast = useToast()

const typeMeta: Record<string, { label: string; icon: string }> = {
  connection: { label: 'Connection', icon: 'pi pi-link' },
  mcp_server: { label: 'MCP server', icon: 'pi pi-bolt' },
  exec_endpoint: { label: 'Exec endpoint', icon: 'pi pi-desktop' },
}

const sortedResources = computed(() =>
  [...resources.resources].sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name)),
)

// --- git credential create/delete ---
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
    await git.createCredential(newName.value.trim(), newToken.value.trim())
    toast.add({
      severity: 'success',
      summary: 'Credential saved',
      detail: 'Airlock does not store the plaintext token. Keep your own copy if you need this PAT elsewhere.',
      life: 7000,
    })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to save credential', life: 5000 })
  } finally {
    saving.value = false
  }
}

function onDeleteGit(c: GitCredential) {
  confirm.require({
    header: `Delete "${c.name}"?`,
    message: 'Agents using this credential will lose access to their git remote until you attach a different one.',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Delete',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await git.deleteCredential(c.id)
        toast.add({ severity: 'info', summary: 'Credential deleted', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to delete credential', life: 5000 })
      }
    },
  })
}

function formatTimestamp(ts: any): string {
  if (ts && ts.seconds !== undefined) return new Date(Number(ts.seconds) * 1000).toLocaleString()
  return '—'
}

function usageNote(n: number): string {
  if (n === 0) return ''
  return ` ${n} agent${n === 1 ? '' : 's'} using it will need to be reconfigured.`
}

function onRevoke(res: any) {
  confirm.require({
    header: `Revoke credentials for "${res.name}"?`,
    message: `The stored credentials will be cleared.${usageNote(res.agentCount)}`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Revoke',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.revoke(res.type, res.id)
        toast.add({ severity: 'info', summary: 'Credentials revoked', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to revoke', life: 5000 })
      }
    },
  })
}

function onDeleteResource(res: any) {
  confirm.require({
    header: `Delete "${res.name}"?`,
    message: `This removes the resource and its sharing.${usageNote(res.agentCount)}`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Delete',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await resources.remove(res.type, res.id)
        toast.add({ severity: 'info', summary: 'Resource deleted', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to delete', life: 5000 })
      }
    },
  })
}

onMounted(() => {
  resources.fetchResources()
  git.fetchCredentials()
})
</script>

<template>
  <div style="padding: 1.5rem; max-width: 64rem">
    <div style="margin-bottom: 1.5rem">
      <h2 style="margin: 0">Resources</h2>
      <p style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem; max-width: 48rem">
        Credentials and integrations you own. One resource can back several of your agents — an agent
        binds it from its own configuration. Set up and reauthorize connections, MCP servers, and exec
        endpoints from each agent's detail page; this is your inventory across all of them.
      </p>
    </div>

    <!-- Connections / MCP / Exec inventory -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>Connections, MCP servers &amp; exec endpoints</template>
      <template #content>
        <DataTable
          v-if="!resources.loading || sortedResources.length > 0"
          :value="sortedResources"
          stripedRows
          size="small"
        >
          <template #empty>
            <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
              You don't own any connections, MCP servers, or exec endpoints yet. They're created when you
              configure an agent's credentials.
            </div>
          </template>
          <Column header="Type" style="width: 12rem">
            <template #body="{ data }">
              <span style="display: inline-flex; align-items: center; gap: 0.4rem">
                <i :class="(typeMeta[data.type]?.icon) || 'pi pi-box'" style="color: var(--p-text-muted-color)" />
                {{ typeMeta[data.type]?.label || data.type }}
              </span>
            </template>
          </Column>
          <Column header="Name">
            <template #body="{ data }">
              <div style="display: flex; flex-direction: column">
                <span style="font-weight: 500">{{ data.name }}</span>
                <span style="font-size: 0.75rem; color: var(--p-text-muted-color)">{{ data.slug }}</span>
              </div>
            </template>
          </Column>
          <Column header="Status" style="width: 9rem">
            <template #body="{ data }">
              <Tag
                :value="data.authorized ? 'Ready' : 'Needs setup'"
                :severity="data.authorized ? 'success' : 'warn'"
              />
            </template>
          </Column>
          <Column header="Used by" style="width: 9rem">
            <template #body="{ data }">
              <span v-if="data.agentCount > 0">{{ data.agentCount }} agent{{ data.agentCount === 1 ? '' : 's' }}</span>
              <span v-else style="color: var(--p-text-muted-color); font-style: italic">unused</span>
            </template>
          </Column>
          <Column header="" style="width: 6rem">
            <template #body="{ data }">
              <div style="display: flex; gap: 0.25rem; justify-content: flex-end">
                <Button
                  v-if="data.type !== 'exec_endpoint' && data.authorized"
                  v-tooltip.top="'Revoke credentials'"
                  icon="pi pi-ban"
                  severity="secondary"
                  size="small"
                  text
                  @click="onRevoke(data)"
                />
                <Button
                  v-tooltip.top="'Delete resource'"
                  icon="pi pi-trash"
                  severity="danger"
                  size="small"
                  text
                  @click="onDeleteResource(data)"
                />
              </div>
            </template>
          </Column>
        </DataTable>
        <div v-else style="display: flex; flex-direction: column; gap: 0.5rem">
          <Skeleton v-for="i in 3" :key="i" height="2.25rem" />
        </div>
      </template>
    </Card>

    <!-- Git credentials -->
    <Card>
      <template #title>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>Git credentials</span>
          <Button label="Add PAT" icon="pi pi-plus" size="small" @click="openCreate" />
        </div>
      </template>
      <template #subtitle>
        Personal access tokens for connecting agents to external git remotes (GitHub, GitLab, Bitbucket, self-hosted).
      </template>
      <template #content>
        <DataTable v-if="!git.loading || git.credentials.length > 0" :value="git.credentials" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
              No git credentials yet. Add a PAT to connect an agent to an external repo.
            </div>
          </template>
          <Column field="name" header="Name" />
          <Column header="Type" style="width: 7rem">
            <template #body="{ data }"><Tag :value="data.type" severity="secondary" /></template>
          </Column>
          <Column header="Created"><template #body="{ data }">{{ formatTimestamp(data.createdAt) }}</template></Column>
          <Column header="Last used"><template #body="{ data }">{{ formatTimestamp(data.lastUsedAt) }}</template></Column>
          <Column header="" style="width: 3rem">
            <template #body="{ data }">
              <Button icon="pi pi-trash" severity="danger" size="small" text @click="onDeleteGit(data)" />
            </template>
          </Column>
        </DataTable>
        <div v-else style="display: flex; flex-direction: column; gap: 0.5rem">
          <Skeleton v-for="i in 2" :key="i" height="2.25rem" />
        </div>
      </template>
    </Card>

    <Dialog v-model:visible="dialogVisible" header="Add Personal Access Token" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <Message severity="info" :closable="false" style="font-size: 0.8rem">
          Create a fine-scoped PAT on your git provider with permission to read and write the repos you want to attach.
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
          <Button label="Save" :loading="saving" :disabled="!newName.trim() || !newToken.trim()" @click="save" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
