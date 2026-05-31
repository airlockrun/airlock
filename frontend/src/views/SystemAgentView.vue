<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useSystemChatStore } from '@/stores/systemChat'
import type { SystemConversationInfo } from '@/gen/airlock/v1/system_agent_pb'

const router = useRouter()
const toast = useToast()
const confirm = useConfirm()
const sys = useSystemChatStore()
const loading = ref(false)

onMounted(async () => {
  loading.value = true
  try {
    await sys.refreshConversations()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Failed to load chats', detail: err?.message, life: 5000 })
  } finally {
    loading.value = false
  }
})

async function openNewChat() {
  try {
    const t = await sys.createConversation()
    router.push(`/system/chat/${t.id}`)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: 'Failed to start chat', detail: err?.message, life: 5000 })
  }
}

function openConversation(t: SystemConversationInfo) {
  router.push(`/system/chat/${t.id}`)
}

function confirmDelete(t: SystemConversationInfo, e: Event) {
  e.stopPropagation()
  confirm.require({
    target: e.currentTarget as HTMLElement,
    message: `Delete "${t.title}"? This can't be undone.`,
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger p-button-sm',
    rejectClass: 'p-button-text p-button-sm',
    accept: async () => {
      try {
        await sys.deleteConversation(t.id)
      } catch (err: any) {
        toast.add({ severity: 'error', summary: 'Delete failed', detail: err?.message, life: 5000 })
      }
    },
  })
}

function timeAgo(seconds?: bigint): string {
  if (!seconds) return ''
  const ms = Number(seconds) * 1000
  const diff = Date.now() - ms
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}
</script>

<template>
  <div>
    <Breadcrumb :model="[{ label: 'Agents', to: '/agents' }, { label: 'System' }]" style="margin-bottom: 1rem">
      <template #item="{ item }">
        <router-link v-if="item.to" :to="item.to" style="text-decoration: none; color: var(--p-primary-color)">
          {{ item.label }}
        </router-link>
        <span v-else>{{ item.label }}</span>
      </template>
    </Breadcrumb>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.75rem">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem">
          <h1 style="margin: 0; font-size: 1.875rem; font-weight: 700; line-height: 1.2">
            <span style="margin-right: 0.4rem">⚙️</span>System Agent
          </h1>
          <Tag value="Operator" severity="info" />
        </div>
        <p style="margin: 0.25rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">
          In-airlock chat for managing agents, bridges, connections, members, and runs through your own permissions.
        </p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button label="New chat" icon="pi pi-plus" @click="openNewChat" />
      </div>
    </div>

    <Card>
      <template #title>
        <div style="display: flex; align-items: center; gap: 0.5rem">
          <i class="pi pi-comments" />
          <span>Your chats</span>
        </div>
      </template>
      <template #content>
        <div v-if="loading" style="display: flex; flex-direction: column; gap: 0.5rem">
          <Skeleton v-for="i in 3" :key="i" width="100%" height="2.5rem" />
        </div>

        <div v-else-if="sys.conversations.length === 0" style="text-align: center; padding: 1.5rem 0">
          <i class="pi pi-comment" style="font-size: 2rem; color: var(--p-surface-400); margin-bottom: 0.5rem" />
          <p style="color: var(--p-text-muted-color); margin: 0.5rem 0 1rem">No chats yet. Start your first conversation.</p>
          <Button label="New chat" icon="pi pi-plus" @click="openNewChat" />
        </div>

        <DataTable
          v-else
          :value="sys.conversations"
          dataKey="id"
          rowHover
          @row-click="(e: any) => openConversation(e.data)"
          tableStyle="cursor: pointer"
        >
          <Column field="title" header="Title">
            <template #body="{ data }">
              <span style="font-weight: 500">{{ data.title }}</span>
              <Tag
                v-if="data.status === 'awaiting_confirmation'"
                value="Needs approval"
                severity="warn"
                style="margin-left: 0.5rem"
              />
            </template>
          </Column>
          <Column field="updatedAt" header="Last activity" style="width: 12rem">
            <template #body="{ data }">
              <span style="color: var(--p-text-muted-color); font-size: 0.875rem">
                {{ timeAgo(data.updatedAt?.seconds) }}
              </span>
            </template>
          </Column>
          <Column header="" style="width: 5rem; text-align: right">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                text
                rounded
                size="small"
                severity="secondary"
                aria-label="Delete chat"
                @click="(e: Event) => confirmDelete(data, e)"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>
