<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const toast = useToast()
const { t } = useAirlockI18n()

const email = ref('')
const password = ref('')
const loading = ref(false)
const passkeyLoading = ref(false)
const error = ref('')
const showPassword = ref(false)
// Default to true so the activation link doesn't flash before /auth/status
// resolves; flips to false only on a confirmed not-yet-activated install.
const activated = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get('/auth/status')
    activated.value = !!data.activated
  } catch { /* leave activated=true; link stays hidden on transient errors */ }
})

function done() {
  toast.add({ severity: 'success', summary: t('auth.login.welcomeBack'), life: 3000 })
  router.push(safeRedirect(route.query.redirect))
}

// The OAuth consent flow sends ?redirect= as an absolute same-origin URL
// (e.g. https://host/oauth/consent?...); reduce it to a router path and reject
// cross-origin targets (no open redirect). Falls back to the dashboard.
function safeRedirect(raw: unknown): string {
  if (typeof raw !== 'string' || !raw) return '/'
  try {
    const u = new URL(raw, window.location.origin)
    if (u.origin === window.location.origin) return u.pathname + u.search + u.hash
  } catch { /* not a URL — fall through */ }
  return '/'
}

// Treat a user-cancelled / no-credential ceremony as a quiet no-op rather than
// an error banner — the browser already showed its own UI.
function isCeremonyAbort(err: any): boolean {
  const name = err?.name
  return name === 'NotAllowedError' || name === 'AbortError'
}

async function onPasskey() {
  error.value = ''
  passkeyLoading.value = true
  try {
    await auth.loginWithPasskey(email.value || undefined)
    done()
  } catch (err: any) {
    if (!isCeremonyAbort(err)) {
      error.value = err.response?.data?.error || t('auth.login.passkeyFailed')
    }
  } finally {
    passkeyLoading.value = false
  }
}

async function onSubmit() {
  error.value = ''
  if (!email.value || !password.value) {
    error.value = t('auth.login.credentialsRequired')
    return
  }
  loading.value = true
  try {
    await auth.login(email.value, password.value)
    done()
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.login.failed')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <Card style="width: 24rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">{{ t('auth.product.airlock') }}</div>
    </template>
    <template #content>
      <div style="display: flex; flex-direction: column; gap: 1.25rem">
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

        <!-- Passkeys are the primary sign-in. Usernameless when the email is
             blank; scoped to the typed email otherwise. -->
        <Button
          :label="t('auth.login.withPasskey')"
          icon="pi pi-key"
          :loading="passkeyLoading"
          style="width: 100%"
          @click="onPasskey"
        />

        <button type="button" class="pw-toggle" @click="showPassword = !showPassword">
          {{ showPassword ? t('auth.login.hidePassword') : t('auth.login.usePassword') }}
        </button>

        <form v-if="showPassword" @submit.prevent="onSubmit" style="display: flex; flex-direction: column; gap: 1.25rem">
          <FloatLabel variant="on">
            <InputText id="email" v-model="email" type="email" autocomplete="username webauthn" style="width: 100%" />
            <label for="email">{{ t('auth.login.email') }}</label>
          </FloatLabel>
          <FloatLabel variant="on">
            <Password id="password" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'current-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="password">{{ t('auth.login.password') }}</label>
          </FloatLabel>
          <Button type="submit" :label="t('auth.login.signIn')" :loading="loading" severity="secondary" style="width: 100%" />
        </form>
        <!-- Email field is also useful for email-first passkey login. -->
        <FloatLabel variant="on" v-else>
          <InputText id="email-passkey" v-model="email" type="email" autocomplete="username webauthn" style="width: 100%" />
          <label for="email-passkey">{{ t('auth.login.optionalEmail') }}</label>
        </FloatLabel>
      </div>
    </template>
    <template #footer>
      <div v-if="!activated" style="text-align: center">
        <router-link to="/activate" style="color: var(--p-primary-color); text-decoration: none; font-size: 0.875rem">
          {{ t('auth.login.firstTimeSetup') }}
        </router-link>
      </div>
    </template>
  </Card>
</template>

<style scoped>
.pw-toggle {
  background: none;
  border: none;
  color: var(--p-text-muted-color);
  font-size: 0.85rem;
  cursor: pointer;
  text-align: center;
  padding: 0;
}
.pw-toggle:hover {
  color: var(--p-primary-color);
}
</style>
