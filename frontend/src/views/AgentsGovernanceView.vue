<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useAgentGovernanceStore } from '@/stores/agentGovernance'
import { useAuthStore } from '@/stores/auth'
import { useAgentStatus } from '@/composables/useAgentStatus'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'

const store = useAgentGovernanceStore()
const auth = useAuthStore()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()
const { t, formatNumber } = useAirlockI18n()
const agentStatus = useAgentStatus()

const search = ref('')

onMounted(() => store.fetchAll())

const canDelete = computed(() => auth.can('tenant.agent.delete_any'))
const canLifecycle = computed(() => auth.can('tenant.agent.lifecycle_any'))

// A member (or owner) already has normal access — they open the agent rather
// than claim it. Everyone else is a non-member the admin can claim into.
function isMember(a: AgentInfo): boolean {
  return a.isOwner || a.yourAccess === 'admin' || a.yourAccess === 'user'
}

const rows = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return store.agents
  return store.agents.filter((a) =>
    [a.name, a.slug, a.ownerName].join(' ').toLowerCase().includes(q),
  )
})

async function act(fn: () => Promise<void>, fail: string) {
  try {
    await fn()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || fail, life: 5000 })
  }
}

function claim(a: AgentInfo) {
  const uid = auth.user?.id
  if (!uid) return
  act(async () => {
    await store.claim(a.id, uid)
    toast.add({ severity: 'success', summary: t('agents.governance.claimed', { name: a.name }), life: 4000 })
  }, t('agents.governance.claimFailed'))
}

function confirmDelete(a: AgentInfo) {
  confirm.require({
    header: t('agents.governance.deleteTitle'),
    message: t('agents.governance.deleteConfirm', {
      name: a.name,
      owner: a.ownerName || t('agents.governance.unknownOwner'),
    }),
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: t('agents.action.delete') },
    rejectLabel: t('agents.action.cancel'),
    accept: () => act(() => store.remove(a.id), t('agents.detail.deleteFailed')),
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">{{ t('agents.governance.title') }}</h1>
      <Tag :value="t('agents.governance.total', { count: store.agents.length, formattedCount: formatNumber(store.agents.length) })" severity="secondary" />
    </div>
    <p style="margin: 0 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem">
      {{ t('agents.governance.descriptionBeforeClaim') }}
      <b>{{ t('agents.action.claim') }}</b>
      {{ t('agents.governance.descriptionAfterClaim') }}
    </p>

    <div style="margin-bottom: 1rem; max-width: 24rem">
      <IconField>
        <InputIcon class="pi pi-search" />
        <InputText v-model="search" :placeholder="t('agents.governance.filterPlaceholder')" style="width: 100%" />
      </IconField>
    </div>

    <div v-if="store.loading" style="display: flex; flex-direction: column; gap: 0.75rem">
      <Skeleton v-for="i in 4" :key="i" height="2.5rem" />
    </div>

    <Message v-else-if="store.agents.length === 0" severity="info" :closable="false">
      {{ t('agents.governance.empty') }}
    </Message>

    <DataTable v-else :value="rows" stripedRows size="small">
      <Column :header="t('agents.governance.column.app')">
        <template #body="{ data }">
          <div style="display: flex; align-items: center; gap: 0.5rem">
            <span v-if="data.emoji" style="font-size: 1.1rem; line-height: 1">{{ data.emoji }}</span>
            <i v-else class="pi pi-box" style="color: var(--p-text-muted-color)" />
            <div style="display: flex; flex-direction: column">
              <span style="font-weight: 500">{{ data.name }}</span>
              <span style="font-size: 0.75rem; color: var(--p-text-muted-color)">{{ data.slug }}</span>
            </div>
          </div>
        </template>
      </Column>
      <Column :header="t('agents.governance.column.owner')">
        <template #body="{ data }">
          <span v-if="data.isOwner"><i class="pi pi-user" style="font-size: 0.7rem" /> {{ t('agents.governance.you') }}</span>
          <span v-else style="color: var(--p-text-muted-color)">{{ data.ownerName || '-' }}</span>
        </template>
      </Column>
      <Column :header="t('agents.governance.column.status')">
        <template #body="{ data }">
          <Tag
            :value="agentStatus(data.status, data.running).label"
            :severity="agentStatus(data.status, data.running).severity"
          />
        </template>
      </Column>
      <Column :header="t('agents.governance.column.yourAccess')">
        <template #body="{ data }">
          <Tag v-if="data.isOwner" :value="t('agents.governance.access.owner')" severity="success" style="font-size: 0.7rem" />
          <Tag v-else-if="data.yourAccess === 'admin'" :value="t('agents.governance.access.admin')" severity="info" style="font-size: 0.7rem" />
          <Tag v-else-if="data.yourAccess === 'user'" :value="t('agents.governance.access.member')" severity="info" style="font-size: 0.7rem" />
          <span v-else style="color: var(--p-text-muted-color); font-size: 0.8rem">{{ t('agents.governance.access.notMember') }}</span>
        </template>
      </Column>
      <Column :header="t('agents.detail.actions')" style="width: 1%; white-space: nowrap">
        <template #body="{ data }">
          <div style="display: flex; gap: 0.4rem; justify-content: flex-end">
            <Button
              v-if="isMember(data)"
              :label="t('agents.action.open')" icon="pi pi-arrow-up-right" size="small" text
              @click="router.push(`/agents/${data.id}`)"
            />
            <Button
              v-else
              :label="t('agents.action.claim')" icon="pi pi-sign-in" size="small" outlined
              @click="claim(data)"
            />
            <Button
              v-if="canLifecycle && data.status === 'active'"
              :label="t('agents.action.stop')" icon="pi pi-stop" size="small" severity="secondary" outlined
              @click="act(() => store.stop(data.id), t('agents.detail.stopFailed'))"
            />
            <Button
              v-else-if="canLifecycle && data.status === 'stopped'"
              :label="t('agents.action.start')" icon="pi pi-play" size="small" severity="secondary" outlined
              @click="act(() => store.start(data.id), t('agents.detail.startFailed'))"
            />
            <Button
              v-if="canDelete"
              icon="pi pi-trash" size="small" severity="danger" text
              :aria-label="t('agents.governance.deleteAria')" @click="confirmDelete(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>
  </div>
</template>
