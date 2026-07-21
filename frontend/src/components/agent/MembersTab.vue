<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useUsersStore } from '@/stores/users'

interface Member {
  userId: string
  email: string
  displayName: string
  role: string
  kind: string // "user" | "group"
}

// Built-in `user` group principal — every registered user. Granting it shares
// the agent with everyone; it shows in the picker/list as "All users".
const GROUP_USER_ID = '00000000-0000-0000-0000-0000000000a3'
const ALL_USERS_LABEL = 'All users'

const props = withDefaults(defineProps<{ agentId: string; yourAccess?: string }>(), { yourAccess: '' })
const emit = defineEmits<{ populated: [count: number] }>()
const confirm = useConfirm()
const toast = useToast()
const usersStore = useUsersStore()

const members = ref<Member[]>([])
watch(members, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)
const canAdmin = computed(() => props.yourAccess === 'admin')

const showAddDialog = ref(false)
const selectedUserId = ref('')
const newRole = ref('user')
const roleOptions = [
  { label: 'Admin', value: 'admin' },
  { label: 'User', value: 'user' },
  // 'public' is the floor tier — most useful granted to the All-Users group
  // to open the agent to every registered user at public access.
  { label: 'Public', value: 'public' },
]

// "All users" (the built-in group) plus individual users not already granted.
const availableUsers = computed(() => {
  const memberIds = new Set(members.value.map(m => m.userId))
  const out: { id: string; email: string; displayName: string; label: string }[] = []
  if (!memberIds.has(GROUP_USER_ID)) {
    out.push({ id: GROUP_USER_ID, email: '', displayName: ALL_USERS_LABEL, label: ALL_USERS_LABEL })
  }
  for (const u of usersStore.selectable) {
    if (u.kind === 'group') continue
    if (memberIds.has(u.id)) continue
    out.push({ id: u.id, email: u.email, displayName: u.displayName, label: u.displayName ? `${u.displayName} (${u.email})` : u.email })
  }
  return out
})

function memberLabel(m: Member): string {
  if (m.userId === GROUP_USER_ID) return ALL_USERS_LABEL
  return m.email || m.displayName || m.userId
}

function mapMember(raw: Record<string, any>): Member {
  return {
    userId: raw.userId ?? raw.user_id ?? '',
    email: raw.email ?? '',
    displayName: raw.displayName ?? raw.display_name ?? '',
    role: raw.role ?? '',
    kind: raw.kind ?? 'user',
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
      kind: user.id === GROUP_USER_ID ? 'group' : 'user',
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
    message: `Remove ${memberLabel(member)} from this app?`,
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
  if (canAdmin.value) usersStore.fetchSelectable()
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
    <DataTable v-if="!loading" :value="members" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No members.
        </div>
      </template>
      <Column header="Member">
        <template #body="{ data: member }">
          <span v-if="member.kind === 'group'"><i class="pi pi-users" style="margin-right: 0.4rem" />{{ memberLabel(member) }}</span>
          <span v-else>{{ member.email }}</span>
        </template>
      </Column>
      <Column header="Display Name">
        <template #body="{ data: member }">{{ member.kind === 'group' ? '' : member.displayName }}</template>
      </Column>
      <Column header="Role">
        <template #body="{ data: member }">
          <Tag :value="member.role" :severity="roleSeverity(member.role)" />
        </template>
      </Column>
      <Column v-if="canAdmin" header="Remove">
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
      <Column header="Member">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Display Name">
        <template #body><Skeleton /></template>
      </Column>
      <Column header="Role">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column v-if="canAdmin" header="Remove">
        <template #body><Skeleton width="2rem" /></template>
      </Column>
    </DataTable>

    <div v-if="canAdmin" style="margin-top: 0.75rem">
      <Button label="Add Member" icon="pi pi-plus" size="small" @click="showAddDialog = true" />
    </div>

    <Dialog v-if="canAdmin" v-model:visible="showAddDialog" header="Add Member" modal :style="{ width: '28rem' }">
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
