<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useAgentGovernanceStore } from '@/stores/agentGovernance'
import { useAuthStore } from '@/stores/auth'
import { useAgentStatus } from '@/composables/useAgentStatus'
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'

const store = useAgentGovernanceStore()
const auth = useAuthStore()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()

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
    toast.add({ severity: 'success', summary: `Claimed ${a.name} — you're now an admin`, life: 4000 })
  }, 'Claim failed')
}

function confirmDelete(a: AgentInfo) {
  confirm.require({
    header: 'Delete agent',
    message: `Permanently delete "${a.name}" (owned by ${a.ownerName || 'unknown'})? This removes its container, image, data, and history. This cannot be undone.`,
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: 'Delete' },
    rejectLabel: 'Cancel',
    accept: () => act(() => store.remove(a.id), 'Delete failed'),
  })
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Manage agents</h1>
      <Tag :value="`${store.agents.length} total`" severity="secondary" />
    </div>
    <p style="margin: 0 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem">
      Every agent in this workspace, including ones you're not a member of. As an
      admin you can stop, start, or delete any agent here for governance. Reading
      an agent's conversations or configuration still requires access — use
      <b>Claim</b> to add yourself as an admin first.
    </p>

    <div style="margin-bottom: 1rem; max-width: 24rem">
      <IconField>
        <InputIcon class="pi pi-search" />
        <InputText v-model="search" placeholder="Filter by name, slug, or owner" style="width: 100%" />
      </IconField>
    </div>

    <div v-if="store.loading" style="display: flex; flex-direction: column; gap: 0.75rem">
      <Skeleton v-for="i in 4" :key="i" height="2.5rem" />
    </div>

    <Message v-else-if="store.agents.length === 0" severity="info" :closable="false">
      No agents in this workspace yet.
    </Message>

    <DataTable v-else :value="rows" stripedRows size="small">
      <Column header="Agent">
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
      <Column header="Owner">
        <template #body="{ data }">
          <span v-if="data.isOwner"><i class="pi pi-user" style="font-size: 0.7rem" /> You</span>
          <span v-else style="color: var(--p-text-muted-color)">{{ data.ownerName || '—' }}</span>
        </template>
      </Column>
      <Column header="Status">
        <template #body="{ data }">
          <Tag
            :value="useAgentStatus(data.status, data.running).label"
            :severity="useAgentStatus(data.status, data.running).severity"
          />
        </template>
      </Column>
      <Column header="Your access">
        <template #body="{ data }">
          <Tag v-if="data.isOwner" value="owner" severity="success" style="font-size: 0.7rem" />
          <Tag v-else-if="data.yourAccess === 'admin'" value="admin" severity="info" style="font-size: 0.7rem" />
          <Tag v-else-if="data.yourAccess === 'user'" value="member" severity="info" style="font-size: 0.7rem" />
          <span v-else style="color: var(--p-text-muted-color); font-size: 0.8rem">not a member</span>
        </template>
      </Column>
      <Column header="Actions" style="width: 1%; white-space: nowrap">
        <template #body="{ data }">
          <div style="display: flex; gap: 0.4rem; justify-content: flex-end">
            <Button
              v-if="isMember(data)"
              label="Open" icon="pi pi-arrow-up-right" size="small" text
              @click="router.push(`/agents/${data.id}`)"
            />
            <Button
              v-else
              label="Claim" icon="pi pi-sign-in" size="small" outlined
              @click="claim(data)"
            />
            <Button
              v-if="canLifecycle && data.status === 'active'"
              label="Stop" icon="pi pi-stop" size="small" severity="secondary" outlined
              @click="act(() => store.stop(data.id), 'Stop failed')"
            />
            <Button
              v-else-if="canLifecycle && data.status === 'stopped'"
              label="Start" icon="pi pi-play" size="small" severity="secondary" outlined
              @click="act(() => store.start(data.id), 'Start failed')"
            />
            <Button
              v-if="canDelete"
              icon="pi pi-trash" size="small" severity="danger" text
              aria-label="Delete agent" @click="confirmDelete(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>
  </div>
</template>
