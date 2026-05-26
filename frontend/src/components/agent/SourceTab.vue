<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { fromJson, toJson, create } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import {
  ConnectAgentGitRequestSchema,
  ConnectAgentGitResponseSchema,
  GetAgentGitConfigResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import type { AgentGitConfig } from '@/gen/airlock/v1/types_pb'

const props = defineProps<{ agentId: string }>()

const credsStore = useGitCredentialsStore()
const confirm = useConfirm()
const toast = useToast()

const cfg = ref<AgentGitConfig | null>(null)
const loading = ref(true)
const connecting = ref(false)
const dialogVisible = ref(false)
const remoteUrl = ref('')
const credentialId = ref('')
const branch = ref('main')

const isConnected = computed(() => !!cfg.value?.gitRemoteUrl)

async function reload() {
  loading.value = true
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/git`)
    cfg.value = fromJson(GetAgentGitConfigResponseSchema, data).config ?? null
  } finally {
    loading.value = false
  }
}

function openConnect() {
  remoteUrl.value = ''
  credentialId.value = credsStore.credentials[0]?.id ?? ''
  branch.value = 'main'
  dialogVisible.value = true
}

async function connect() {
  if (!remoteUrl.value.trim() || !credentialId.value) return
  connecting.value = true
  try {
    const req = create(ConnectAgentGitRequestSchema, {
      gitRemoteUrl: remoteUrl.value.trim(),
      gitCredentialId: credentialId.value,
      defaultBranch: branch.value.trim() || 'main',
    })
    const { data } = await api.post(
      `/api/v1/agents/${props.agentId}/git/connect`,
      toJson(ConnectAgentGitRequestSchema, req),
    )
    cfg.value = fromJson(ConnectAgentGitResponseSchema, data).config ?? null
    toast.add({ severity: 'success', summary: 'Remote connected', life: 4000 })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({
      severity: 'error',
      summary: err.response?.data?.error || 'Failed to connect remote',
      life: 6000,
    })
  } finally {
    connecting.value = false
  }
}

function disconnect() {
  confirm.require({
    header: 'Disconnect remote?',
    message:
      'The agent returns to internal-only mode. Future codegen commits stay local; ' +
      'webhook pushes from your remote are ignored. The local repo + image are untouched.',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: 'Disconnect',
    rejectLabel: 'Cancel',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${props.agentId}/git/disconnect`)
        await reload()
        toast.add({ severity: 'info', summary: 'Remote disconnected', life: 3000 })
      } catch (err: any) {
        toast.add({
          severity: 'error',
          summary: err.response?.data?.error || 'Failed to disconnect',
          life: 5000,
        })
      }
    },
  })
}

async function copyToClipboard(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ severity: 'success', summary: `${label} copied`, life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: `Copy failed — select and copy ${label} manually`, life: 4000 })
  }
}

const cloneCmd = computed(() => (cfg.value ? `git clone ${cfg.value.gitRemoteUrl}` : ''))

onMounted(async () => {
  await Promise.all([reload(), credsStore.fetchCredentials()])
})
</script>

<template>
  <div v-if="!loading" style="padding-top: 0.5rem">
    <!-- Internal mode -->
    <div v-if="!isConnected" style="display: flex; flex-direction: column; gap: 1rem">
      <Message severity="info" :closable="false">
        This agent has no git remote. Connect one to clone the source to your laptop, edit there, and push changes back — airlock will rebuild on every push.
      </Message>
      <div v-if="credsStore.credentials.length === 0">
        <p style="margin: 0 0 0.5rem">You don't have any git credentials yet.</p>
        <router-link to="/settings/git-credentials">
          <Button label="Add a PAT in Settings" icon="pi pi-plus" outlined size="small" />
        </router-link>
      </div>
      <div v-else>
        <Button label="Connect a repo" icon="pi pi-link" @click="openConnect" />
      </div>
    </div>

    <!-- External mode -->
    <div v-else style="display: flex; flex-direction: column; gap: 1rem">
      <div>
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Remote</label>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code style="flex: 1; padding: 0.4rem 0.6rem; background: var(--p-surface-100); border-radius: 0.3rem; word-break: break-all">{{ cfg!.gitRemoteUrl }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.gitRemoteUrl, 'URL')" />
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem">
        <div>
          <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Branch</label>
          <div>{{ cfg!.defaultBranch }}</div>
        </div>
        <div>
          <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Credential</label>
          <div>{{ cfg!.gitCredentialName || '—' }}</div>
        </div>
      </div>

      <div v-if="cfg!.lastSyncedRef">
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Last synced ref</label>
        <code style="font-size: 0.8rem">{{ cfg!.lastSyncedRef }}</code>
      </div>

      <div>
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Clone command</label>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code style="flex: 1; padding: 0.4rem 0.6rem; background: var(--p-surface-100); border-radius: 0.3rem; word-break: break-all">{{ cloneCmd }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cloneCmd, 'Command')" />
        </div>
      </div>

      <details>
        <summary style="cursor: pointer; font-size: 0.85rem; color: var(--p-text-muted-color)">Webhook setup (paste these into your git provider's webhook settings)</summary>
        <div style="display: flex; flex-direction: column; gap: 0.75rem; margin-top: 0.75rem">
          <div>
            <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Payload URL</label>
            <div style="display: flex; align-items: center; gap: 0.5rem">
              <code style="flex: 1; padding: 0.4rem 0.6rem; background: var(--p-surface-100); border-radius: 0.3rem; word-break: break-all">{{ cfg!.webhookUrl }}</code>
              <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.webhookUrl, 'Webhook URL')" />
            </div>
          </div>
          <div>
            <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">Secret</label>
            <div style="display: flex; align-items: center; gap: 0.5rem">
              <code style="flex: 1; padding: 0.4rem 0.6rem; background: var(--p-surface-100); border-radius: 0.3rem; word-break: break-all">{{ cfg!.webhookSecret }}</code>
              <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.webhookSecret, 'Secret')" />
            </div>
          </div>
          <small style="color: var(--p-text-muted-color)">
            Content type: <code>application/json</code>. Event: just the <strong>push</strong> event (GitHub/GitLab/etc).
            Other providers (Bitbucket, Gitea) aren't wired for signature verification yet — the polling fallback picks up pushes every 5 minutes.
          </small>
        </div>
      </details>

      <div>
        <Button label="Disconnect remote" icon="pi pi-times" severity="warn" outlined @click="disconnect" />
      </div>
    </div>

    <!-- Connect dialog -->
    <Dialog v-model:visible="dialogVisible" header="Connect a git remote" modal style="width: 32rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <Message severity="info" :closable="false" style="font-size: 0.8rem">
          Create an empty repo on your git provider, paste its HTTPS clone URL below, and pick a credential. Airlock will push the agent's current state to it and use that repo as the source of truth.
        </Message>
        <FloatLabel>
          <InputText id="remote-url" v-model="remoteUrl" style="width: 100%" placeholder="https://github.com/your-org/your-agent.git" autocomplete="off" />
          <label for="remote-url">Remote URL</label>
        </FloatLabel>
        <FloatLabel>
          <Select
            id="cred-select"
            v-model="credentialId"
            :options="credsStore.credentials"
            option-label="name"
            option-value="id"
            style="width: 100%"
          />
          <label for="cred-select">Credential</label>
        </FloatLabel>
        <FloatLabel>
          <InputText id="branch" v-model="branch" style="width: 100%" />
          <label for="branch">Default branch</label>
        </FloatLabel>
        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
          <Button
            label="Connect"
            :loading="connecting"
            :disabled="!remoteUrl.trim() || !credentialId"
            @click="connect"
          />
        </div>
      </div>
    </Dialog>

    <ConfirmDialog />
  </div>
  <div v-else style="padding: 1rem">
    <Skeleton width="60%" height="1.5rem" />
    <Skeleton width="100%" height="3rem" style="margin-top: 1rem" />
  </div>
</template>
