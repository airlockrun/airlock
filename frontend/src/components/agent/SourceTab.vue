<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { fromJson, toJson, create } from '@bufbuild/protobuf'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useGitCredentialsStore } from '@/stores/gitCredentials'
import { airlockCloneCommand, airlockInstallCommand } from '@/utils/airCommands'
import {
  ConnectAgentGitRequestSchema,
  ConnectAgentGitResponseSchema,
  GetAgentSDKInfoResponseSchema,
  GetAgentGitConfigResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import type { AgentGitConfig } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string; agentSlug: string }>()
const emit = defineEmits<{ populated: [count: number]; mutated: [gitMode: string] }>()

const credsStore = useGitCredentialsStore()
const confirm = useConfirm()
const toast = useToast()
const { t } = useAirlockI18n()

const cfg = ref<AgentGitConfig | null>(null)
// Source counts as populated only when a remote is actually connected;
// internal-only agents hide the section. Reconnecting comes from elsewhere.
watch(cfg, (v) => emit('populated', v?.gitRemoteUrl ? 1 : 0), { immediate: true })
const loading = ref(true)
const connecting = ref(false)
const dialogVisible = ref(false)
const airlockURL = ref('')
const sdkVersion = ref('')
const launcherImport = ref('')
const remoteUrl = ref('')
const credentialId = ref('')
const branch = ref('main')
const gitMode = ref<'read_write' | 'read_only'>('read_write')
const gitModeOptions = computed(() => [
  { label: t('agents.source.mode.readWriteDescription'), value: 'read_write' },
  { label: t('agents.source.mode.readOnlyDescription'), value: 'read_only' },
])

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
  gitMode.value = 'read_write'
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
      gitMode: gitMode.value,
    })
    const { data } = await api.post(
      `/api/v1/agents/${props.agentId}/git/connect`,
      toJson(ConnectAgentGitRequestSchema, req),
    )
    cfg.value = fromJson(ConnectAgentGitResponseSchema, data).config ?? null
    emit('mutated', cfg.value?.gitMode ?? '')
    toast.add({ severity: 'success', summary: t('agents.source.connected'), life: 4000 })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({
      severity: 'error',
      summary: err.response?.data?.error || t('agents.source.connectFailed'),
      life: 6000,
    })
  } finally {
    connecting.value = false
  }
}

function disconnect() {
  confirm.require({
    header: t('agents.source.disconnectTitle'),
    message: t('agents.source.disconnectConfirm'),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('agents.source.disconnectAction'),
    rejectLabel: t('agents.action.cancel'),
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${props.agentId}/git/disconnect`)
        await reload()
        emit('mutated', '')
        toast.add({ severity: 'info', summary: t('agents.source.disconnected'), life: 3000 })
      } catch (err: any) {
        toast.add({
          severity: 'error',
          summary: err.response?.data?.error || t('agents.source.disconnectFailed'),
          life: 5000,
        })
      }
    },
  })
}

async function copyToClipboard(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ severity: 'success', summary: t('agents.copy.copied', { label }), life: 2000 })
  } catch {
    toast.add({ severity: 'warn', summary: t('agents.copy.failed', { label }), life: 4000 })
  }
}

const cloneCmd = computed(() => (cfg.value ? `git clone ${cfg.value.gitRemoteUrl}` : ''))
const airInstallCmd = computed(() => airlockInstallCommand(launcherImport.value, sdkVersion.value))
const airCloneCmd = computed(() =>
  airlockCloneCommand(props.agentSlug, props.agentSlug, airlockURL.value),
)
const airDeployCmd = computed(() =>
  `cd ${props.agentSlug}\ngo tool air deploy -m "Describe this deployment"`,
)

async function loadAgentSDKInfo() {
  const { data } = await api.get('/api/v1/agent-sdk')
  const info = fromJson(GetAgentSDKInfoResponseSchema, data)
  airlockURL.value = info.airlockUrl
  sdkVersion.value = info.version
  launcherImport.value = info.launcherImport
}

onMounted(async () => {
  void credsStore.fetchCredentials().catch(() => {})
  await Promise.all([reload(), loadAgentSDKInfo()])
})
</script>

<template>
  <div v-if="!loading" style="padding-top: 0.5rem">
    <!-- Internal mode -->
    <div v-if="!isConnected" style="display: flex; flex-direction: column; gap: 1rem">
      <Message severity="info" :closable="false">
        {{ t('agents.source.internalDescription') }}
      </Message>
      <div v-if="agentSlug && airlockURL && sdkVersion && launcherImport" style="display: flex; flex-direction: column; gap: 0.5rem">
        <strong>{{ t('agents.source.airCli') }}</strong>
        <p style="margin: 0; color: var(--p-text-muted-color)">
          {{ t('agents.source.airCliDescriptionBeforeCommand') }} <code>go tool air</code> {{ t('agents.source.airCliDescriptionAfterCommand') }}
        </p>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code class="code-chip">{{ airInstallCmd }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(airInstallCmd, t('agents.source.installCommand'))" />
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code class="code-chip">{{ airCloneCmd }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(airCloneCmd, t('agents.source.cloneCommand'))" />
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code class="code-chip" style="white-space: pre-wrap">{{ airDeployCmd }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(airDeployCmd, t('agents.source.deployCommand'))" />
        </div>
      </div>
      <Skeleton v-if="credsStore.loading" height="2.5rem" />
      <Message v-else-if="credsStore.error" severity="error" :closable="false">
        <div class="load-error">
          <span>{{ credsStore.error }}</span>
          <Button :label="t('agents.action.retry')" icon="pi pi-refresh" size="small" outlined @click="credsStore.fetchCredentials().catch(() => {})" />
        </div>
      </Message>
      <div v-else-if="credsStore.credentials.length === 0">
        <p style="margin: 0 0 0.5rem">{{ t('agents.source.noCredentials') }}</p>
        <router-link to="/settings/git-credentials">
          <Button :label="t('agents.source.addPat')" icon="pi pi-plus" outlined size="small" />
        </router-link>
      </div>
      <div v-else>
        <Button :label="t('agents.source.connectRepo')" icon="pi pi-link" @click="openConnect" />
      </div>
    </div>

    <!-- External mode -->
    <div v-else style="display: flex; flex-direction: column; gap: 1rem">
      <div>
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.remote') }}</label>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code class="code-chip">{{ cfg!.gitRemoteUrl }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.gitRemoteUrl, t('agents.source.url'))" />
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem">
        <div>
          <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.branch') }}</label>
          <div>{{ cfg!.defaultBranch }}</div>
        </div>
        <div>
          <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.credential') }}</label>
          <div>{{ cfg!.gitCredentialName || '-' }}</div>
        </div>
      </div>

      <div v-if="cfg!.lastSyncedRef">
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.lastSyncedRef') }}</label>
        <code style="font-size: 0.8rem">{{ cfg!.lastSyncedRef }}</code>
      </div>

      <div>
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.mode.label') }}</label>
        <div>{{ cfg!.gitMode === 'read_only' ? t('agents.source.mode.readOnly') : t('agents.source.mode.readWrite') }}</div>
      </div>

      <div>
        <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.cloneCommand') }}</label>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <code class="code-chip">{{ cloneCmd }}</code>
          <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cloneCmd, t('agents.source.command'))" />
        </div>
      </div>

      <details>
        <summary style="cursor: pointer; font-size: 0.85rem; color: var(--p-text-muted-color)">{{ t('agents.source.webhookSetup') }}</summary>
        <div style="display: flex; flex-direction: column; gap: 0.75rem; margin-top: 0.75rem">
          <div>
            <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.payloadUrl') }}</label>
            <div style="display: flex; align-items: center; gap: 0.5rem">
              <code class="code-chip">{{ cfg!.webhookUrl }}</code>
              <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.webhookUrl, t('agents.source.webhookUrl'))" />
            </div>
          </div>
          <div>
            <label style="display: block; font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">{{ t('agents.source.secret') }}</label>
            <div style="display: flex; align-items: center; gap: 0.5rem">
              <code class="code-chip">{{ cfg!.webhookSecret }}</code>
              <Button icon="pi pi-copy" text size="small" @click="copyToClipboard(cfg!.webhookSecret, t('agents.source.secret'))" />
            </div>
          </div>
          <small style="color: var(--p-text-muted-color)">
            {{ t('agents.source.webhookContentType') }} <code>application/json</code>. {{ t('agents.source.webhookEventBeforePush') }} <strong>push</strong> {{ t('agents.source.webhookEventAfterPush') }}
            {{ t('agents.source.webhookProviderFallback') }}
          </small>
        </div>
      </details>

      <div>
        <Button :label="t('agents.source.disconnectRemote')" icon="pi pi-times" severity="warn" outlined @click="disconnect" />
      </div>
    </div>

    <!-- Connect dialog -->
    <Dialog v-model:visible="dialogVisible" :header="t('agents.source.connectTitle')" modal style="width: 32rem">
      <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <Message severity="info" :closable="false" style="font-size: 0.8rem">
          {{ t('agents.source.connectDescription') }}
        </Message>
        <FloatLabel variant="on">
          <InputText id="remote-url" v-model="remoteUrl" style="width: 100%" :placeholder="t('agents.source.remoteUrlPlaceholder')" autocomplete="off" />
          <label for="remote-url">{{ t('agents.source.remoteUrl') }}</label>
        </FloatLabel>
        <FloatLabel variant="on">
          <Select
            id="cred-select"
            v-model="credentialId"
            :options="credsStore.credentials"
            option-label="name"
            option-value="id"
            style="width: 100%"
          />
          <label for="cred-select">{{ t('agents.source.credential') }}</label>
        </FloatLabel>
        <FloatLabel variant="on">
          <InputText id="branch" v-model="branch" style="width: 100%" />
          <label for="branch">{{ t('agents.source.defaultBranch') }}</label>
        </FloatLabel>
        <FloatLabel variant="on">
          <Select
            id="git-mode"
            v-model="gitMode"
            :options="gitModeOptions"
            option-label="label"
            option-value="value"
            style="width: 100%"
          />
          <label for="git-mode">{{ t('agents.source.sourceMode') }}</label>
        </FloatLabel>
        <Message v-if="gitMode === 'read_only'" severity="warn" :closable="false" style="font-size: 0.8rem">
          {{ t('agents.source.readOnlyWarning') }}
        </Message>
        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button :label="t('agents.action.cancel')" severity="secondary" text @click="dialogVisible = false" />
          <Button
            :label="t('agents.source.connectAction')"
            :loading="connecting"
            :disabled="!remoteUrl.trim() || !credentialId"
            @click="connect"
          />
        </div>
      </div>
    </Dialog>
  </div>
  <div v-else style="padding: 1rem">
    <Skeleton width="60%" height="1.5rem" />
    <Skeleton width="100%" height="3rem" style="margin-top: 1rem" />
  </div>
</template>

<style scoped>
/* Layout for the inline value chips; the theme-adaptive background and dark
   override come from the global .code-chip utility in style.css. */
.code-chip {
  flex: 1;
  padding: 0.4rem 0.6rem;
}

.load-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}
</style>
