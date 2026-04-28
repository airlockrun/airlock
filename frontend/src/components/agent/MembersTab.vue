<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useUsersStore } from '@/stores/users'

interface Member {
  userId: string
  email: string
  displayName: string
  role: string
}

const props = defineProps<{ agentId: string }>()
const confirm = useConfirm()
const toast = useToast()
const usersStore = useUsersStore()

const members = ref<Member[]>([])
const loading = ref(true)

const showAddDialog = ref(false)
const selectedUserId = ref('')
const newRole = ref('user')
const roleOptions = [
  { label: 'Admin', value: 'admin' },
  { label: 'User', value: 'user' },
]

// Users not already members
const availableUsers = computed(() => {
  const memberIds = new Set(members.value.map(m => m.userId))
  return usersStore.selectable
    .filter(u => !memberIds.has(u.id))
    .map(u => ({ id: u.id, email: u.email, displayName: u.displayName, label: u.displayName ? `${u.displayName} (${u.email})` : u.email }))
})

function mapMember(raw: Record<string, any>): Member {
  return {
    userId: raw.userId ?? raw.user_id ?? '',
    email: raw.email ?? '',
    displayName: raw.displayName ?? raw.display_name ?? '',
    role: raw.role ?? '',
  }
}

function roleSeverity(role: string): string {
  switch (role) {
    case 'admin': return 'warn'
    case 'user': return 'info'
    default: return 'secondary'
  }
}

async function addMember() {
  const user = availableUsers.value.find(u => u.id === selectedUserId.value)
  if (!user) return
  try {
    await api.post(`/api/v1/agents/${props.agentId}/members`, {
      userId: user.id,
      role: newRole.value,
    })
    members.value.push({
      userId: user.id,
      email: user.email,
      displayName: user.displayName,
      role: newRole.value,
    })
    showAddDialog.value = false
    selectedUserId.value = ''
    newRole.value = 'user'
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to add member', life: 5000 })
  }
}

function confirmRemove(member: Member) {
  confirm.require({
    message: `Remove ${member.email} from this agent?`,
    header: 'Confirm Removal',
    acceptLabel: 'Remove',
    rejectLabel: 'Cancel',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/members/${member.userId}`)
        members.value = members.value.filter((m) => m.userId !== member.userId)
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to remove member', life: 5000 })
      }
    },
  })
}

onMounted(async () => {
  usersStore.fetchSelectable()
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/members`)
    members.value = (data.members || []).map(mapMember)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div class="flex justify-end mb-3">
      <Button label="Add Member" icon="pi pi-plus" size="small" @click="showAddDialog = true" />
    </div>

    <DataTable v-if="!loading" :value="members" stripedRows>
      <Column field="email" header="Email" />
      <Column field="displayName" header="Display Name" />
      <Column header="Role">
        <template #body="{ data: member }">
          <Tag :value="member.role" :severity="roleSeverity(member.role)" />
        </template>
      </Column>
      <Column header="Remove">
        <template #body="{ data: member }">
          <Button
            icon="pi pi-trash"
            size="small"
            severity="danger"
            text
            @click="confirmRemove(member)"
          />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Email">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Display Name">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Role">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column header="Remove">
        <template #body><Skeleton width="2rem" /></template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="showAddDialog" header="Add Member" modal :style="{ width: '28rem' }">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="member-user">User</label>
          <Select id="member-user" v-model="selectedUserId" :options="availableUsers" optionLabel="label" optionValue="id" placeholder="Select a user" style="width: 100%" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="member-role">Role</label>
          <Select id="member-role" v-model="newRole" :options="roleOptions" optionLabel="label" optionValue="value" style="width: 100%" />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showAddDialog = false" />
        <Button label="Add" :disabled="!selectedUserId" @click="addMember" />
      </template>
    </Dialog>
  </div>
</template>
