<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useUsersStore } from '@/stores/users'
import { useAirlockI18n } from '@/i18n'

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

const props = withDefaults(defineProps<{ agentId: string; yourAccess?: string }>(), { yourAccess: '' })
const emit = defineEmits<{ populated: [count: number] }>()
const confirm = useConfirm()
const toast = useToast()
const usersStore = useUsersStore()
const { t } = useAirlockI18n()

const members = ref<Member[]>([])
watch(members, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)
const canAdmin = computed(() => props.yourAccess === 'admin')

const showAddDialog = ref(false)
const selectedUserId = ref('')
const newRole = ref('user')
const roleOptions = computed(() => [
  { label: t('agentConfig.members.roleAdmin'), value: 'admin' },
  { label: t('agentConfig.members.roleUser'), value: 'user' },
  // 'public' is the floor tier — most useful granted to the All-Users group
  // to open the agent to every registered user at public access.
  { label: t('agentConfig.members.rolePublic'), value: 'public' },
])

// "All users" (the built-in group) plus individual users not already granted.
const availableUsers = computed(() => {
  const memberIds = new Set(members.value.map(m => m.userId))
  const out: { id: string; email: string; displayName: string; label: string }[] = []
  if (!memberIds.has(GROUP_USER_ID)) {
    const allUsersLabel = t('agentConfig.members.allUsers')
    out.push({ id: GROUP_USER_ID, email: '', displayName: allUsersLabel, label: allUsersLabel })
  }
  for (const u of usersStore.selectable) {
    if (u.kind === 'group') continue
    if (memberIds.has(u.id)) continue
    out.push({ id: u.id, email: u.email, displayName: u.displayName, label: u.displayName ? `${u.displayName} (${u.email})` : u.email })
  }
  return out
})

function memberLabel(m: Member): string {
  if (m.userId === GROUP_USER_ID) return t('agentConfig.members.allUsers')
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

function roleLabel(role: string): string {
  if (role === 'public') return t('agentConfig.members.rolePublic')
  if (role === 'user') return t('agentConfig.members.roleUser')
  if (role === 'admin') return t('agentConfig.members.roleAdmin')
  return role
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
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.members.addFailed'), life: 5000 })
  }
}

function confirmRemove(member: Member) {
  confirm.require({
    message: t('agentConfig.members.removeConfirmation', { member: memberLabel(member) }),
    header: t('agentConfig.members.confirmRemoval'),
    acceptLabel: t('agentConfig.common.remove'),
    rejectLabel: t('agentConfig.common.cancel'),
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/members/${member.userId}`)
        members.value = members.value.filter((m) => m.userId !== member.userId)
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.members.removeFailed'), life: 5000 })
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
          {{ t('agentConfig.members.empty') }}
        </div>
      </template>
      <Column :header="t('agentConfig.members.member')">
        <template #body="{ data: member }">
          <span v-if="member.kind === 'group'"><i class="pi pi-users" style="margin-right: 0.4rem" />{{ memberLabel(member) }}</span>
          <span v-else>{{ member.email }}</span>
        </template>
      </Column>
      <Column :header="t('agentConfig.members.displayName')">
        <template #body="{ data: member }">{{ member.kind === 'group' ? '' : member.displayName }}</template>
      </Column>
      <Column :header="t('agentConfig.members.role')">
        <template #body="{ data: member }">
          <Tag :value="roleLabel(member.role)" :severity="roleSeverity(member.role)" />
        </template>
      </Column>
      <Column v-if="canAdmin" :header="t('agentConfig.common.remove')">
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
       <Column :header="t('agentConfig.members.member')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('agentConfig.members.displayName')">
        <template #body><Skeleton /></template>
      </Column>
      <Column :header="t('agentConfig.members.role')">
        <template #body><Skeleton width="4rem" /></template>
      </Column>
      <Column v-if="canAdmin" :header="t('agentConfig.common.remove')">
        <template #body><Skeleton width="2rem" /></template>
      </Column>
    </DataTable>

    <div v-if="canAdmin" style="margin-top: 0.75rem">
      <Button :label="t('agentConfig.members.addMember')" icon="pi pi-plus" size="small" @click="showAddDialog = true" />
    </div>

    <Dialog v-if="canAdmin" v-model:visible="showAddDialog" :header="t('agentConfig.members.addMember')" modal :style="{ width: '28rem' }">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="member-user">{{ t('agentConfig.members.user') }}</label>
          <Select id="member-user" v-model="selectedUserId" :options="availableUsers" optionLabel="label" optionValue="id" :placeholder="t('agentConfig.members.selectUser')" style="width: 100%" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="member-role">{{ t('agentConfig.members.role') }}</label>
          <Select id="member-role" v-model="newRole" :options="roleOptions" optionLabel="label" optionValue="value" style="width: 100%" />
        </div>
      </div>
      <template #footer>
        <Button :label="t('agentConfig.common.cancel')" severity="secondary" text @click="showAddDialog = false" />
        <Button :label="t('agentConfig.common.add')" :disabled="!selectedUserId" @click="addMember" />
      </template>
    </Dialog>
  </div>
</template>
