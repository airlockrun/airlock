<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { useUsersStore } from '@/stores/users'
import { useAuthStore } from '@/stores/auth'
import { useAirlockI18n } from '@/i18n'

const store = useUsersStore()
const auth = useAuthStore()
const toast = useToast()
const confirm = useConfirm()
const { t, formatDate: formatLocaleDate } = useAirlockI18n()

const dialogVisible = ref(false)
const form = ref({ email: '', displayName: '', tenantRole: 'user' })

// One-time temp password shown after creating a user, for the admin to hand
// off. The user must change it (or register a passkey) on first login.
const tempPasswordDialog = ref(false)
const tempPassword = ref('')
const tempPasswordEmail = ref('')

async function copyTempPassword() {
  try {
    await navigator.clipboard.writeText(tempPassword.value)
    toast.add({ severity: 'success', summary: t('administration.users.copied'), life: 2000 })
  } catch { /* clipboard unavailable — user can select manually */ }
}
const roleOptions = computed(() => [
  { label: t('administration.users.role.admin'), value: 'admin' },
  { label: t('administration.users.role.manager'), value: 'manager' },
  { label: t('administration.users.role.user'), value: 'user' },
])

// Proto enum → API string
const roleEnumToStr: Record<number, string> = { 1: 'admin', 2: 'manager', 3: 'user' }

function formatDate(ts: { seconds?: bigint } | undefined): string {
  if (!ts?.seconds) return '-'
  return formatLocaleDate(Number(ts.seconds) * 1000)
}

onMounted(() => {
  store.fetchUsers()
})

function openCreate() {
  form.value = { email: '', displayName: '', tenantRole: 'user' }
  dialogVisible.value = true
}

async function onSubmit() {
  try {
    const temp = await store.createUser({
      email: form.value.email,
      displayName: form.value.displayName,
      tenantRole: form.value.tenantRole,
    })
    dialogVisible.value = false
    tempPassword.value = temp
    tempPasswordEmail.value = form.value.email
    tempPasswordDialog.value = true
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.users.createFailed'), life: 5000 })
  }
}

async function onRoleChange(userId: string, role: string) {
  try {
    await store.updateUserRole(userId, role)
    toast.add({ severity: 'success', summary: t('administration.users.roleUpdated'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.users.updateFailed'), life: 5000 })
    // Re-fetch to revert optimistic UI
    await store.fetchUsers()
  }
}

function confirmDelete(user: { id: string; email: string }) {
  confirm.require({
    message: t('administration.users.confirmDelete', { email: user.email }),
    header: t('administration.providers.confirmDeleteTitle'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await store.deleteUser(user.id)
        toast.add({ severity: 'success', summary: t('administration.users.deleted'), life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('administration.users.deleteFailed'), life: 5000 })
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
      <h1 style="margin: 0; font-size: 1.5rem">{{ t('administration.users.title') }}</h1>
      <Button :label="t('administration.users.action.add')" icon="pi pi-plus" @click="openCreate" />
    </div>

    <!-- Loading skeletons -->
    <DataTable v-if="store.loading" :value="Array(5)">
      <Column :header="t('administration.users.email')"><template #body><Skeleton width="60%" /></template></Column>
      <Column :header="t('administration.users.displayName')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('administration.users.role')"><template #body><Skeleton width="5rem" /></template></Column>
      <Column :header="t('administration.users.createdAt')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('administration.users.actions')"><template #body><Skeleton width="3rem" /></template></Column>
    </DataTable>

    <!-- Data table -->
    <DataTable v-else :value="store.users" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('administration.users.empty') }}
        </div>
      </template>
      <Column field="email" :header="t('administration.users.email')" />
      <Column field="displayName" :header="t('administration.users.displayName')" />
      <Column :header="t('administration.users.role')">
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
      <Column :header="t('administration.users.createdAt')">
        <template #body="{ data }">
          {{ formatDate(data.createdAt) }}
        </template>
      </Column>
      <Column :header="t('administration.users.actions')">
        <template #body="{ data }">
          <Button
            icon="pi pi-trash"
            severity="danger"
            text
            rounded
            :aria-label="t('administration.users.action.deleteAria')"
            :disabled="isSelf(data.id)"
            @click="confirmDelete(data)"
          />
        </template>
      </Column>
    </DataTable>

    <!-- Create dialog -->
    <Dialog v-model:visible="dialogVisible" :header="t('administration.users.action.add')" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userEmail">{{ t('administration.users.email') }}</label>
          <InputText id="userEmail" v-model="form.email" :placeholder="t('administration.users.emailExample')" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userDisplayName">{{ t('administration.users.displayName') }}</label>
          <InputText id="userDisplayName" v-model="form.displayName" :placeholder="t('administration.users.displayNameExample')" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.25rem">
          <label for="userRole">{{ t('administration.users.role') }}</label>
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
        <Button :label="t('administration.action.cancel')" severity="secondary" text @click="dialogVisible = false" />
        <Button :label="t('administration.action.create')" @click="onSubmit" />
      </template>
    </Dialog>

    <!-- One-time temp password handoff -->
    <Dialog v-model:visible="tempPasswordDialog" :header="t('administration.users.userCreated')" modal style="width: 30rem">
      <div style="display: flex; flex-direction: column; gap: 1rem">
        <p style="margin: 0">
          {{ t('administration.users.passwordHandoff', { email: tempPasswordEmail }) }}
        </p>
        <div style="display: flex; gap: 0.5rem; align-items: center">
          <InputText :value="tempPassword" readonly style="width: 100%; font-family: monospace" />
          <Button icon="pi pi-copy" severity="secondary" :aria-label="t('administration.users.copyPasswordAria')" @click="copyTempPassword" />
        </div>
      </div>
      <template #footer>
        <Button :label="t('administration.action.done')" @click="tempPasswordDialog = false" />
      </template>
    </Dialog>
  </div>
</template>
