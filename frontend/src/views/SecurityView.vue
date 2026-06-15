<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { usePasskeysStore } from '@/stores/passkeys'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import { scorePassword } from '@/composables/usePasswordStrength'
import type { Passkey } from '@/gen/airlock/v1/types_pb'

const auth = useAuthStore()
const store = usePasskeysStore()
const toast = useToast()
const confirm = useConfirm()

const adding = ref(false)
const error = ref('')

onMounted(() => {
  store.fetchPasskeys().catch((e: any) => {
    error.value = e.response?.data?.error || 'Failed to load passkeys.'
  })
})

function isCeremonyAbort(err: any): boolean {
  const name = err?.name
  return name === 'NotAllowedError' || name === 'AbortError'
}

function fmt(ts?: { seconds: bigint }): string {
  if (!ts || !ts.seconds) return '—'
  return new Date(Number(ts.seconds) * 1000).toLocaleDateString()
}

// --- Add passkey ---
const addDialog = ref(false)
const newName = ref('')

function openAdd() {
  newName.value = ''
  addDialog.value = true
}

async function confirmAdd() {
  adding.value = true
  error.value = ''
  try {
    await store.addPasskey(newName.value.trim() || 'Passkey')
    addDialog.value = false
    toast.add({ severity: 'success', summary: 'Passkey added', life: 3000 })
  } catch (err: any) {
    if (!isCeremonyAbort(err)) {
      error.value = err.response?.data?.error || 'Failed to add passkey.'
    }
  } finally {
    adding.value = false
  }
}

// --- Rename ---
const renameDialog = ref(false)
const renameTarget = ref<Passkey | null>(null)
const renameName = ref('')

function openRename(pk: Passkey) {
  renameTarget.value = pk
  renameName.value = pk.friendlyName
  renameDialog.value = true
}

async function confirmRename() {
  if (!renameTarget.value) return
  try {
    await store.renamePasskey(renameTarget.value.id, renameName.value.trim())
    renameDialog.value = false
    toast.add({ severity: 'success', summary: 'Passkey renamed', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Rename failed', life: 4000 })
  }
}

function remove(pk: Passkey) {
  confirm.require({
    message: `Delete passkey "${pk.friendlyName}"? You won't be able to sign in with it anymore.`,
    header: 'Delete passkey',
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: 'Delete' },
    accept: async () => {
      try {
        await store.deletePasskey(pk.id)
        toast.add({ severity: 'success', summary: 'Passkey deleted', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}

// --- Password ---
const password = ref('')
const confirmPassword = ref('')
const pwLoading = ref(false)
const pwError = ref('')

async function savePassword() {
  pwError.value = ''
  if (password.value !== confirmPassword.value) {
    pwError.value = 'Passwords do not match.'
    return
  }
  if (!scorePassword(password.value, [auth.user?.email ?? '']).ok) {
    pwError.value = 'Password is too weak — choose a longer or less predictable one.'
    return
  }
  pwLoading.value = true
  try {
    await store.setPassword(password.value)
    password.value = ''
    confirmPassword.value = ''
    toast.add({ severity: 'success', summary: 'Password saved', life: 3000 })
  } catch (err: any) {
    pwError.value = err.response?.data?.error || 'Failed to save password.'
  } finally {
    pwLoading.value = false
  }
}

function removePassword() {
  confirm.require({
    message: 'Remove your password? You will only be able to sign in with a passkey.',
    header: 'Remove password',
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: 'Remove' },
    accept: async () => {
      try {
        await store.removePassword()
        toast.add({ severity: 'success', summary: 'Password removed', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to remove password', life: 5000 })
      }
    },
  })
}
</script>

<template>
  <div style="max-width: 48rem; margin: 0 auto; display: flex; flex-direction: column; gap: 1.5rem">
    <h1 style="margin: 0">Security</h1>

    <Card>
      <template #title>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>Passkeys</span>
          <Button label="Add passkey" icon="pi pi-plus" size="small" @click="openAdd" />
        </div>
      </template>
      <template #subtitle>
        Passkeys are the primary, phishing-resistant way to sign in. Add one per device.
      </template>
      <template #content>
        <Message v-if="error" severity="error" :closable="false" style="margin-bottom: 1rem">{{ error }}</Message>
        <DataTable :value="store.passkeys" :loading="store.loading" dataKey="id">
          <template #empty>
            <span style="color: var(--p-text-muted-color)">No passkeys yet. Add one to enable passwordless sign-in.</span>
          </template>
          <Column header="Name">
            <template #body="{ data }">
              {{ data.friendlyName }}
              <Tag v-if="data.backupEligible" value="synced" severity="info" style="font-size: 0.7rem; margin-left: 0.5rem" />
            </template>
          </Column>
          <Column header="Added">
            <template #body="{ data }">{{ fmt(data.createdAt) }}</template>
          </Column>
          <Column header="Last used">
            <template #body="{ data }">{{ fmt(data.lastUsedAt) }}</template>
          </Column>
          <Column style="width: 6rem">
            <template #body="{ data }">
              <div style="display: flex; gap: 0.25rem; justify-content: flex-end">
                <Button icon="pi pi-pencil" text rounded size="small" @click="openRename(data)" />
                <Button icon="pi pi-trash" text rounded severity="danger" size="small" @click="remove(data)" />
              </div>
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <Card>
      <template #title>Password</template>
      <template #subtitle>
        Optional. A strong password is an alternative sign-in method; passkeys are preferred.
      </template>
      <template #content>
        <form @submit.prevent="savePassword" style="display: flex; flex-direction: column; gap: 1rem; max-width: 24rem">
          <Message v-if="pwError" severity="error" :closable="false">{{ pwError }}</Message>
          <FloatLabel>
            <Password id="sec-pass" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-pass">New password</label>
          </FloatLabel>
          <PasswordStrengthMeter :password="password" :user-inputs="[auth.user?.email ?? '']" />
          <FloatLabel>
            <Password id="sec-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-confirm">Confirm password</label>
          </FloatLabel>
          <div style="display: flex; gap: 0.5rem">
            <Button type="submit" label="Save password" :loading="pwLoading" :disabled="!password" />
            <Button type="button" label="Remove password" severity="secondary" outlined @click="removePassword" />
          </div>
        </form>
      </template>
    </Card>

    <Dialog v-model:visible="addDialog" header="Add a passkey" modal style="width: 24rem">
      <div style="display: flex; flex-direction: column; gap: 1rem">
        <p style="margin: 0; color: var(--p-text-muted-color); font-size: 0.875rem">
          Give this passkey a name so you can recognize the device later.
        </p>
        <FloatLabel>
          <InputText id="pk-name" v-model="newName" style="width: 100%" placeholder="e.g. MacBook Touch ID" />
          <label for="pk-name">Name</label>
        </FloatLabel>
      </div>
      <template #footer>
        <Button label="Cancel" text @click="addDialog = false" />
        <Button label="Continue" icon="pi pi-key" :loading="adding" @click="confirmAdd" />
      </template>
    </Dialog>

    <Dialog v-model:visible="renameDialog" header="Rename passkey" modal style="width: 24rem">
      <FloatLabel>
        <InputText id="pk-rename" v-model="renameName" style="width: 100%" />
        <label for="pk-rename">Name</label>
      </FloatLabel>
      <template #footer>
        <Button label="Cancel" text @click="renameDialog = false" />
        <Button label="Save" @click="confirmRename" />
      </template>
    </Dialog>
  </div>
</template>
