<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import { useAuthStore } from '@/stores/auth'
import { usePasskeysStore } from '@/stores/passkeys'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import { scorePassword } from '@/composables/usePasswordStrength'
import api from '@/api/client'
import { ListPlatformIdentitiesResponseSchema, ListUserSessionsResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { Passkey, PlatformIdentityInfo, UserSession } from '@/gen/airlock/v1/types_pb'

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
  loadSessions()
  loadGrants()
  loadIdentities()
})

function isCeremonyAbort(err: any): boolean {
  const name = err?.name
  return name === 'NotAllowedError' || name === 'AbortError'
}

function fmt(ts?: { seconds: bigint }): string {
  if (!ts || !ts.seconds) return '-'
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
    await auth.refresh()
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
        await auth.refresh()
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
    pwError.value = 'Password is too weak - choose a longer or less predictable one.'
    return
  }
  pwLoading.value = true
  try {
    await store.setPassword(password.value)
    await auth.refresh()
    if (auth.user) auth.user.hasPassword = true
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
        await auth.refresh()
        if (auth.user) auth.user.hasPassword = false
        toast.add({ severity: 'success', summary: 'Password removed', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to remove password', life: 5000 })
      }
    },
  })
}

// --- Authorized apps (inbound OAuth grants) ---
// External MCP clients the user authorized to reach their agents via the MCP
// server-side OAuth flow. The list + revoke buttons let the user yank consent.
interface GrantDTO {
  clientId: string
  clientName: string
  agentId: string
  agentSlug: string
  agentName: string
  scope: string
  grantedAt: string
  expiresAt: string
}
const grants = ref<GrantDTO[]>([])
const grantsLoading = ref(false)

async function loadGrants() {
  grantsLoading.value = true
  try {
    const { data } = await api.get('/api/v1/oauth/grants')
    grants.value = data || []
  } catch {
    grants.value = []
  } finally {
    grantsLoading.value = false
  }
}

async function revokeGrant(g: GrantDTO) {
  try {
    await api.delete(`/api/v1/oauth/grants/${encodeURIComponent(g.clientId)}/${encodeURIComponent(g.agentId)}`)
    grants.value = grants.value.filter(x => !(x.clientId === g.clientId && x.agentId === g.agentId))
    toast.add({ severity: 'success', summary: 'Access revoked', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || 'revoke failed', life: 5000 })
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString()
  } catch {
    return iso
  }
}

// --- Sessions (first-party web + CLI logins) ---
const sessions = ref<UserSession[]>([])
const sessionsLoading = ref(false)

async function loadSessions() {
  sessionsLoading.value = true
  try {
    const { data } = await api.get('/api/v1/sessions')
    sessions.value = fromJson(ListUserSessionsResponseSchema, data).sessions
  } catch {
    sessions.value = []
  } finally {
    sessionsLoading.value = false
  }
}

async function revokeSession(session: UserSession) {
  try {
    await api.delete(`/api/v1/sessions/${encodeURIComponent(session.id)}`)
    sessions.value = sessions.value.filter(x => x.id !== session.id)
    toast.add({ severity: 'success', summary: 'Session revoked', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || 'revoke failed', life: 5000 })
  }
}

// --- Linked accounts (platform_identities) ---
// External accounts (Telegram) linked to this user. Regular users see only
// their own; admins additionally see every link in the tenant with the owner
// column populated. Both can unlink — the backend scopes the delete by caller
// UserID, or by id alone when the caller holds tenant.identity.manage_all.
const identities = ref<PlatformIdentityInfo[]>([])
const identitiesLoading = ref(false)
const canManageAllIdentities = computed(() => auth.can('tenant.identity.manage_all'))

async function loadIdentities() {
  identitiesLoading.value = true
  try {
    const { data } = await api.get('/api/v1/identities')
    const resp = fromJson(ListPlatformIdentitiesResponseSchema, data)
    identities.value = resp.identities
  } catch {
    identities.value = []
  } finally {
    identitiesLoading.value = false
  }
}

async function unlinkIdentity(it: PlatformIdentityInfo) {
  try {
    await api.delete(`/api/v1/identities/${encodeURIComponent(it.id)}`)
    identities.value = identities.value.filter(x => x.id !== it.id)
    toast.add({ severity: 'success', summary: 'Identity unlinked', life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || 'unlink failed', life: 5000 })
  }
}

function formatDateTime(ts: any): string {
  if (!ts) return ''
  // protobuf-ts Timestamp → { seconds: bigint, nanos: number }
  const seconds = typeof ts.seconds === 'bigint' ? Number(ts.seconds) : ts.seconds
  if (!seconds) return ''
  try {
    return new Date(seconds * 1000).toLocaleString()
  } catch {
    return ''
  }
}
</script>

<template>
  <div style="display: flex; flex-direction: column; gap: 1.5rem; max-width: 48rem">
    <h1 style="margin: 0; font-size: 1.5rem">Security</h1>
    <Message severity="info" :closable="false">
      Credential changes require a sign-in within the last 10 minutes. Sign out and sign in again if Airlock asks for recent authentication.
    </Message>

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
          <FloatLabel variant="on">
            <Password id="sec-pass" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-pass">New password</label>
          </FloatLabel>
          <PasswordStrengthMeter :password="password" :user-inputs="[auth.user?.email ?? '']" />
          <FloatLabel variant="on">
            <Password id="sec-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-confirm">Confirm password</label>
          </FloatLabel>
          <div style="display: flex; gap: 0.5rem">
            <Button type="submit" :label="auth.user?.hasPassword ? 'Change password' : 'Set password'" :loading="pwLoading" :disabled="!password" />
            <Button v-if="auth.user?.hasPassword" type="button" label="Remove password" severity="secondary" outlined @click="removePassword" />
          </div>
        </form>
      </template>
    </Card>

    <Card>
      <template #title>Sessions</template>
      <template #subtitle>
        Web and CLI sign-ins for your account. Revoking a session invalidates its access and refresh credentials immediately.
      </template>
      <template #content>
        <div v-if="sessionsLoading" style="color: var(--p-text-muted-color)">Loading…</div>
        <div v-else-if="sessions.length === 0" style="color: var(--p-text-muted-color)">
          No active sessions.
        </div>
        <DataTable v-else :value="sessions" stripedRows size="small">
          <Column header="Session">
            <template #body="{ data }">
              <div>{{ data.clientName || (data.kind === 'cli' ? 'air CLI' : 'Airlock Web') }}</div>
              <small style="color: var(--p-text-muted-color)">{{ data.deviceName }}</small>
            </template>
          </Column>
          <Column header="Kind">
            <template #body="{ data }">
              <Tag :value="data.kind" :severity="data.kind === 'cli' ? 'info' : 'secondary'" />
            </template>
          </Column>
          <Column header="Last used">
            <template #body="{ data }">{{ formatDateTime(data.lastUsedAt) || formatDateTime(data.createdAt) }}</template>
          </Column>
          <Column header="Expires">
            <template #body="{ data }">{{ formatDateTime(data.expiresAt) }}</template>
          </Column>
          <Column header="">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                size="small"
                severity="danger"
                text
                @click="revokeSession(data)"
                v-tooltip.left="'Revoke session'"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Authorized apps (inbound OAuth grants) -->
    <Card>
      <template #title>Authorized apps</template>
      <template #subtitle>
        External MCP clients (Claude Desktop, VSCode, Codex, …) that you've authorized to talk to your apps.
        Revoking immediately stops future requests; tokens already issued may keep working for up to 15 minutes
        until their access token naturally expires.
      </template>
      <template #content>
        <div v-if="grantsLoading" style="color: var(--p-text-muted-color)">Loading…</div>
        <div v-else-if="grants.length === 0" style="color: var(--p-text-muted-color)">
          No external apps are connected.
        </div>
        <DataTable v-else :value="grants" stripedRows size="small">
          <Column field="clientName" header="App" />
          <Column header="App">
            <template #body="{ data }">
              <RouterLink :to="`/agents/${data.agentId}`">{{ data.agentName }}</RouterLink>
              <span style="color: var(--p-text-muted-color); margin-left: 0.5rem">
                ({{ data.agentSlug }})
              </span>
            </template>
          </Column>
          <Column header="Granted">
            <template #body="{ data }">{{ formatDate(data.grantedAt) }}</template>
          </Column>
          <Column header="Expires">
            <template #body="{ data }">{{ formatDate(data.expiresAt) }}</template>
          </Column>
          <Column header="">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                size="small"
                severity="danger"
                text
                @click="revokeGrant(data)"
                v-tooltip.left="'Revoke access'"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Linked accounts (platform_identities) -->
    <Card>
      <template #title>Linked accounts</template>
      <template #subtitle>
        <span v-if="canManageAllIdentities">
          Every Telegram identity linked to a user in this tenant. Unlinking forces the user to re-run <code>/auth</code> in their bot to regain access.
        </span>
        <span v-else>
          Your Telegram identities - used by bridge bots to recognise you. Unlinking forces you to re-run <code>/auth</code> in the bot the next time you DM it.
        </span>
      </template>
      <template #content>
        <div v-if="identitiesLoading" style="color: var(--p-text-muted-color)">Loading…</div>
        <div v-else-if="identities.length === 0" style="color: var(--p-text-muted-color)">
          {{ canManageAllIdentities ? 'No platform identities are linked in this tenant.' : 'You have no linked platform identities.' }}
        </div>
        <DataTable v-else :value="identities" stripedRows size="small">
          <Column v-if="canManageAllIdentities" field="ownerEmail" header="Owner">
            <template #body="{ data }">
              <div>{{ data.ownerEmail }}</div>
              <small v-if="data.ownerDisplayName" style="color: var(--p-text-muted-color)">
                {{ data.ownerDisplayName }}
              </small>
            </template>
          </Column>
          <Column field="platform" header="Platform" />
          <Column field="platformUserId" header="Platform user ID" />
          <Column header="Linked">
            <template #body="{ data }">{{ formatDateTime(data.createdAt) }}</template>
          </Column>
          <Column header="">
            <template #body="{ data }">
              <Button
                icon="pi pi-trash"
                size="small"
                severity="danger"
                text
                @click="unlinkIdentity(data)"
                v-tooltip.left="'Unlink'"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <Dialog v-model:visible="addDialog" header="Add a passkey" modal style="width: 24rem">
      <div style="display: flex; flex-direction: column; gap: 1rem">
        <p style="margin: 0; color: var(--p-text-muted-color); font-size: 0.875rem">
          Give this passkey a name so you can recognize the device later.
        </p>
        <FloatLabel variant="on">
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
      <FloatLabel variant="on">
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
