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
import { useAirlockI18n } from '@/i18n'
import { ListPlatformIdentitiesResponseSchema, ListUserSessionsResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { Passkey, PlatformIdentityInfo, UserSession } from '@/gen/airlock/v1/types_pb'

const auth = useAuthStore()
const store = usePasskeysStore()
const toast = useToast()
const confirm = useConfirm()
const { t, formatDate: formatLocaleDate } = useAirlockI18n()

const displayName = ref(auth.user?.displayName ?? '')
const profileSaving = ref(false)
const normalizedDisplayName = computed(() => displayName.value.trim())
const profileSaveDisabled = computed(() =>
  profileSaving.value ||
  normalizedDisplayName.value === '' ||
  normalizedDisplayName.value === auth.user?.displayName,
)

async function saveProfile() {
  profileSaving.value = true
  try {
    await auth.updateDisplayName(displayName.value)
    displayName.value = auth.user?.displayName ?? ''
    toast.add({ severity: 'success', summary: t('auth.security.displayNameUpdated'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('auth.security.displayNameFailed'), life: 4000 })
  } finally {
    profileSaving.value = false
  }
}

const adding = ref(false)
const error = ref('')

onMounted(() => {
  store.fetchPasskeys().catch((e: any) => {
    error.value = e.response?.data?.error || t('auth.security.passkeysLoadFailed')
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
  if (!ts || !ts.seconds) return t('auth.security.notAvailable')
  return formatLocaleDate(Number(ts.seconds) * 1000)
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
    await store.addPasskey(newName.value.trim() || t('auth.passkey.defaultName'))
    await auth.refresh()
    addDialog.value = false
    toast.add({ severity: 'success', summary: t('auth.security.passkeyAdded'), life: 3000 })
  } catch (err: any) {
    if (!isCeremonyAbort(err)) {
      error.value = err.response?.data?.error || t('auth.security.passkeyAddFailed')
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
    toast.add({ severity: 'success', summary: t('auth.security.passkeyRenamed'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('auth.security.renameFailed'), life: 4000 })
  }
}

function remove(pk: Passkey) {
  confirm.require({
    message: t('auth.security.deletePasskeyMessage', { name: pk.friendlyName }),
    header: t('auth.security.deletePasskey'),
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: t('auth.action.delete') },
    accept: async () => {
      try {
        await store.deletePasskey(pk.id)
        await auth.refresh()
        toast.add({ severity: 'success', summary: t('auth.security.passkeyDeleted'), life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('auth.security.deleteFailed'), life: 5000 })
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
    pwError.value = t('auth.security.passwordsMismatch')
    return
  }
  if (!scorePassword(password.value, [auth.user?.email ?? '']).ok) {
    pwError.value = t('auth.security.passwordWeak')
    return
  }
  pwLoading.value = true
  try {
    await store.setPassword(password.value)
    await auth.refresh()
    if (auth.user) auth.user.hasPassword = true
    password.value = ''
    confirmPassword.value = ''
    toast.add({ severity: 'success', summary: t('auth.security.passwordSaved'), life: 3000 })
  } catch (err: any) {
    pwError.value = err.response?.data?.error || t('auth.security.passwordSaveFailed')
  } finally {
    pwLoading.value = false
  }
}

function removePassword() {
  confirm.require({
    message: t('auth.security.removePasswordMessage'),
    header: t('auth.security.removePassword'),
    icon: 'pi pi-exclamation-triangle',
    acceptProps: { severity: 'danger', label: t('auth.action.remove') },
    accept: async () => {
      try {
        await store.removePassword()
        await auth.refresh()
        if (auth.user) auth.user.hasPassword = false
        toast.add({ severity: 'success', summary: t('auth.security.passwordRemoved'), life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('auth.security.passwordRemoveFailed'), life: 5000 })
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
    toast.add({ severity: 'success', summary: t('auth.security.accessRevoked'), life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || t('auth.security.revokeFailed'), life: 5000 })
  }
}

function formatDate(iso: string): string {
  try {
    return formatLocaleDate(new Date(iso))
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
    toast.add({ severity: 'success', summary: t('auth.security.sessionRevoked'), life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || t('auth.security.revokeFailed'), life: 5000 })
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
    toast.add({ severity: 'success', summary: t('auth.security.identityUnlinked'), life: 2000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err?.response?.data?.error || t('auth.security.unlinkFailed'), life: 5000 })
  }
}

function formatDateTime(ts: any): string {
  if (!ts) return ''
  // protobuf-ts Timestamp → { seconds: bigint, nanos: number }
  const seconds = typeof ts.seconds === 'bigint' ? Number(ts.seconds) : ts.seconds
  if (!seconds) return ''
  try {
    return formatLocaleDate(seconds * 1000, { dateStyle: 'short', timeStyle: 'short' })
  } catch {
    return ''
  }
}

function sessionKindLabel(kind: string): string {
  switch (kind) {
    case 'web': return t('auth.security.sessionKind.web')
    case 'cli': return t('auth.security.sessionKind.cli')
    case 'telegram': return t('auth.security.sessionKind.telegram')
    default: return kind
  }
}
</script>

<template>
  <div style="display: flex; flex-direction: column; gap: 1.5rem; max-width: 48rem">
    <h1 style="margin: 0; font-size: 1.5rem">{{ t('auth.shell.security') }}</h1>

    <Card>
      <template #title>{{ t('auth.security.profile') }}</template>
      <template #subtitle>
        {{ t('auth.security.profileDescription') }}
      </template>
      <template #content>
        <form @submit.prevent="saveProfile" style="display: flex; flex-wrap: wrap; align-items: flex-start; gap: 0.75rem; max-width: 30rem">
          <FloatLabel variant="on" style="flex: 1 1 16rem; min-width: 0">
            <InputText id="profile-display-name" v-model="displayName" autocomplete="name" style="width: 100%" />
            <label for="profile-display-name">{{ t('auth.security.displayName') }}</label>
          </FloatLabel>
          <Button type="submit" :label="t('auth.action.save')" :loading="profileSaving" :disabled="profileSaveDisabled" />
        </form>
      </template>
    </Card>

    <Message severity="info" :closable="false">
      {{ t('auth.security.recentAuthNotice') }}
    </Message>

    <Card>
      <template #title>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>{{ t('auth.security.passkeys') }}</span>
          <Button :label="t('auth.security.addPasskey')" icon="pi pi-plus" size="small" @click="openAdd" />
        </div>
      </template>
      <template #subtitle>
        {{ t('auth.security.passkeysDescription') }}
      </template>
      <template #content>
        <Message v-if="error" severity="error" :closable="false" style="margin-bottom: 1rem">{{ error }}</Message>
        <DataTable :value="store.passkeys" :loading="store.loading" dataKey="id">
          <template #empty>
            <span style="color: var(--p-text-muted-color)">{{ t('auth.security.noPasskeys') }}</span>
          </template>
          <Column :header="t('auth.security.name')">
            <template #body="{ data }">
              {{ data.friendlyName }}
              <Tag v-if="data.backupEligible" :value="t('auth.security.synced')" severity="info" style="font-size: 0.7rem; margin-left: 0.5rem" />
            </template>
          </Column>
          <Column :header="t('auth.security.added')">
            <template #body="{ data }">{{ fmt(data.createdAt) }}</template>
          </Column>
          <Column :header="t('auth.security.lastUsed')">
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
      <template #title>{{ t('auth.security.password') }}</template>
      <template #subtitle>
        {{ t('auth.security.passwordDescription') }}
      </template>
      <template #content>
        <form @submit.prevent="savePassword" style="display: flex; flex-direction: column; gap: 1rem; max-width: 24rem">
          <Message v-if="pwError" severity="error" :closable="false">{{ pwError }}</Message>
          <FloatLabel variant="on">
            <Password id="sec-pass" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-pass">{{ t('auth.security.newPassword') }}</label>
          </FloatLabel>
          <PasswordStrengthMeter :password="password" :user-inputs="[auth.user?.email ?? '']" />
          <FloatLabel variant="on">
            <Password id="sec-confirm" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="sec-confirm">{{ t('auth.security.confirmPassword') }}</label>
          </FloatLabel>
          <div style="display: flex; gap: 0.5rem">
            <Button type="submit" :label="auth.user?.hasPassword ? t('auth.security.changePassword') : t('auth.security.setPassword')" :loading="pwLoading" :disabled="!password" />
            <Button v-if="auth.user?.hasPassword" type="button" :label="t('auth.security.removePassword')" severity="secondary" outlined @click="removePassword" />
          </div>
        </form>
      </template>
    </Card>

    <Card>
      <template #title>{{ t('auth.security.sessions') }}</template>
      <template #subtitle>
        {{ t('auth.security.sessionsDescription') }}
      </template>
      <template #content>
        <div v-if="sessionsLoading" style="color: var(--p-text-muted-color)">{{ t('auth.security.loading') }}</div>
        <div v-else-if="sessions.length === 0" style="color: var(--p-text-muted-color)">
          {{ t('auth.security.noSessions') }}
        </div>
        <DataTable v-else :value="sessions" stripedRows size="small">
          <Column :header="t('auth.security.session')">
            <template #body="{ data }">
              <div>{{ data.clientName || (data.kind === 'cli' ? t('auth.product.airCli') : t('auth.product.web')) }}</div>
              <small style="color: var(--p-text-muted-color)">{{ data.deviceName }}</small>
            </template>
          </Column>
          <Column :header="t('auth.security.kind')">
            <template #body="{ data }">
              <Tag :value="sessionKindLabel(data.kind)" :severity="data.kind === 'cli' ? 'info' : 'secondary'" />
            </template>
          </Column>
          <Column :header="t('auth.security.lastUsed')">
            <template #body="{ data }">{{ formatDateTime(data.lastUsedAt) || formatDateTime(data.createdAt) }}</template>
          </Column>
          <Column :header="t('auth.security.expires')">
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
                v-tooltip.left="t('auth.security.revokeSession')"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Authorized apps (inbound OAuth grants) -->
    <Card>
      <template #title>{{ t('auth.security.authorizedApps') }}</template>
      <template #subtitle>
        {{ t('auth.security.authorizedAppsDescription') }}
      </template>
      <template #content>
        <div v-if="grantsLoading" style="color: var(--p-text-muted-color)">{{ t('auth.security.loading') }}</div>
        <div v-else-if="grants.length === 0" style="color: var(--p-text-muted-color)">
          {{ t('auth.security.noAuthorizedApps') }}
        </div>
        <DataTable v-else :value="grants" stripedRows size="small">
          <Column field="clientName" :header="t('auth.security.app')" />
          <Column :header="t('auth.security.app')">
            <template #body="{ data }">
              <RouterLink :to="`/agents/${data.agentId}`">{{ data.agentName }}</RouterLink>
              <span style="color: var(--p-text-muted-color); margin-left: 0.5rem">
                {{ t('auth.security.appSlug', { slug: data.agentSlug }) }}
              </span>
            </template>
          </Column>
          <Column :header="t('auth.security.granted')">
            <template #body="{ data }">{{ formatDate(data.grantedAt) }}</template>
          </Column>
          <Column :header="t('auth.security.expires')">
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
                v-tooltip.left="t('auth.security.revokeAccess')"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Linked accounts (platform_identities) -->
    <Card>
      <template #title>{{ t('auth.security.linkedAccounts') }}</template>
      <template #subtitle>
        <span v-if="canManageAllIdentities">
          {{ t('auth.security.allIdentitiesDescription') }}
        </span>
        <span v-else>
          {{ t('auth.security.ownIdentitiesDescription') }}
        </span>
      </template>
      <template #content>
        <div v-if="identitiesLoading" style="color: var(--p-text-muted-color)">{{ t('auth.security.loading') }}</div>
        <div v-else-if="identities.length === 0" style="color: var(--p-text-muted-color)">
          {{ canManageAllIdentities ? t('auth.security.noTenantIdentities') : t('auth.security.noOwnIdentities') }}
        </div>
        <DataTable v-else :value="identities" stripedRows size="small">
          <Column v-if="canManageAllIdentities" field="ownerEmail" :header="t('auth.security.owner')">
            <template #body="{ data }">
              <div>{{ data.ownerEmail }}</div>
              <small v-if="data.ownerDisplayName" style="color: var(--p-text-muted-color)">
                {{ data.ownerDisplayName }}
              </small>
            </template>
          </Column>
          <Column field="platform" :header="t('auth.security.platform')" />
          <Column field="platformUserId" :header="t('auth.security.platformUserId')" />
          <Column :header="t('auth.security.linked')">
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
                v-tooltip.left="t('auth.security.unlink')"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <Dialog v-model:visible="addDialog" :header="t('auth.security.addPasskeyDialog')" modal style="width: 24rem">
      <div style="display: flex; flex-direction: column; gap: 1rem">
        <p style="margin: 0; color: var(--p-text-muted-color); font-size: 0.875rem">
          {{ t('auth.security.passkeyNameHelp') }}
        </p>
        <FloatLabel variant="on">
          <InputText id="pk-name" v-model="newName" style="width: 100%" :placeholder="t('auth.security.passkeyNamePlaceholder')" />
          <label for="pk-name">{{ t('auth.security.name') }}</label>
        </FloatLabel>
      </div>
      <template #footer>
        <Button :label="t('auth.action.cancel')" text @click="addDialog = false" />
        <Button :label="t('auth.action.continue')" icon="pi pi-key" :loading="adding" @click="confirmAdd" />
      </template>
    </Dialog>

    <Dialog v-model:visible="renameDialog" :header="t('auth.security.renamePasskey')" modal style="width: 24rem">
      <FloatLabel variant="on">
        <InputText id="pk-rename" v-model="renameName" style="width: 100%" />
        <label for="pk-rename">{{ t('auth.security.name') }}</label>
      </FloatLabel>
      <template #footer>
        <Button :label="t('auth.action.cancel')" text @click="renameDialog = false" />
        <Button :label="t('auth.action.save')" @click="confirmRename" />
      </template>
    </Dialog>
  </div>
</template>
