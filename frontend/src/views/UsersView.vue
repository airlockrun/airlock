<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useUsersStore } from '@/stores/users'
import { useAuthStore } from '@/stores/auth'

const store = useUsersStore()
const auth = useAuthStore()
const toast = useToast()
const confirm = useConfirm()

const dialogVisible = ref(false)
const form = ref({ email: '', displayName: '', password: '', tenantRole: 'user' })
const roleOptions = [
  { label: 'Admin', value: 'admin' },
  { label: 'Manager', value: 'manager' },
  { label: 'User', value: 'user' },
]

// Proto enum → API string
const roleEnumToStr: Record<number, string> = { 1: 'admin', 2: 'manager', 3: 'user' }

function formatDate(ts: { seconds?: bigint } | undefined): string {
  if (!ts?.seconds) return '—'
  return new Date(Number(ts.seconds) * 1000).toLocaleDateString()
}

onMounted(() => {
  store.fetchUsers()
})

function openCreate() {
  form.value = { email: '', displayName: '', password: '', tenantRole: 'user' }
  dialogVisible.value = true
}

async function onSubmit() {
  try {
    await store.createUser({
      email: form.value.email,
      password: form.value.password,
      displayName: form.value.displayName,
      tenantRole: form.value.tenantRole,
    })
    toast.add({ severity: 'success', summary: 'User created', life: 3000 })
    dialogVisible.value = false
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Create failed', life: 5000 })
  }
}

async function onRoleChange(userId: string, role: string) {
  try {
    await store.updateUserRole(userId, role)
    toast.add({ severity: 'success', summary: 'Role updated', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Update failed', life: 5000 })
    // Re-fetch to revert optimistic UI
    await store.fetchUsers()
  }
}

function confirmDelete(user: { id: string; email: string }) {
  confirm.require({
    message: `Delete user "${user.email}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteUser(user.id)
        toast.add({ severity: 'success', summary: 'User deleted', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}

function isSelf(userId: string): boolean {
  return auth.user?.id === userId
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Users</h1>
      <Button label="Add User" icon="pi pi-plus" @click="openCreate" />
    </div>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column header="Email"><template #body><Skeleton width="60%" /></template></Column>
      <Column header="Display Name"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Role"><template #body><Skeleton width="5rem" /></template></Column>
      <Column header="Created At"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Actions"><template #body><Skeleton width="3rem" /></template></Column>
    </DataTable>

    <!-- Data table -->
    <DataTable v-else :value="store.users" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No users found.
        </div>
      </template>
      <Column field="email" header="Email" />
      <Column field="displayName" header="Display Name" />
      <Column header="Role">
        <template #body="{ data }">
          <Select
            :modelValue="roleEnumToStr[data.tenantRole] || 'user'"
            :options="roleOptions"
            optionLabel="label"
            optionValue="value"
            :disabled="isSelf(data.id)"
            style="width: 8rem"
            @update:modelValue="(val: string) => onRoleChange(data.id, val)"
          />
        </template>
      </Column>
      <Column header="Created At">
        <template #body="{ data }">
          {{ formatDate(data.createdAt) }}
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-trash"
            severity="danger"
            text
            rounded
            :disabled="isSelf(data.id)"
            @click="confirmDelete(data)"
          />
        </template>
      </Column>
    </DataTable>

    <!-- Create dialog -->
    <Dialog v-model:visible="dialogVisible" header="Add User" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userEmail">Email</label>
          <InputText id="userEmail" v-model="form.email" placeholder="user@example.com" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userDisplayName">Display Name</label>
          <InputText id="userDisplayName" v-model="form.displayName" placeholder="Jane Doe" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userPassword">Password</label>
          <Password id="userPassword" v-model="form.password" :feedback="false" toggleMask />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userRole">Role</label>
          <Select
            id="userRole"
            v-model="form.tenantRole"
            :options="roleOptions"
            optionLabel="label"
            optionValue="value"
          />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button label="Create" @click="onSubmit" />
      </template>
    </Dialog>
  </div>
</template>
