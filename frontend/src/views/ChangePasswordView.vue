<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useToast } from 'primevue/usetoast'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import { scorePassword } from '@/composables/usePasswordStrength'
import { useAirlockI18n } from '@/i18n'

const router = useRouter()
const auth = useAuthStore()
const toast = useToast()
const { t } = useAirlockI18n()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const passkeyLoading = ref(false)
const error = ref('')

function isCeremonyAbort(err: any): boolean {
  const name = err?.name
  return name === 'NotAllowedError' || name === 'AbortError'
}

async function onPasskey() {
  error.value = ''
  passkeyLoading.value = true
  try {
    await auth.registerPasskeyAndSecure(t('auth.passkey.defaultName'))
    toast.add({ severity: 'success', summary: t('auth.changePassword.passkeyAdded'), life: 3000 })
    router.push('/')
  } catch (err: any) {
    if (!isCeremonyAbort(err)) {
      error.value = err.response?.data?.error || t('auth.changePassword.passkeyRegistrationFailed')
    }
  } finally {
    passkeyLoading.value = false
  }
}

async function onSubmit() {
  error.value = ''
  if (!currentPassword.value || !newPassword.value || !confirmPassword.value) {
    error.value = t('auth.validation.allFieldsRequired')
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    error.value = t('auth.changePassword.newPasswordsMismatch')
    return
  }
  const email = auth.user?.email ?? ''
  if (!scorePassword(newPassword.value, [email]).ok) {
    error.value = t('auth.changePassword.weak')
    return
  }

  loading.value = true
  try {
    await auth.changePassword(currentPassword.value, newPassword.value)
    toast.add({ severity: 'success', summary: t('auth.changePassword.changed'), life: 3000 })
    router.push('/')
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.changePassword.failed')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <Card style="width: 26rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">{{ t('auth.changePassword.secureAccount') }}</div>
    </template>
    <template #subtitle>
      <div style="text-align: center">
        {{ t('auth.changePassword.instructions') }}
      </div>
    </template>
    <template #content>
      <div style="display: flex; flex-direction: column; gap: 1.25rem">
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

        <Button
          :label="t('auth.changePassword.registerPasskey')"
          icon="pi pi-key"
          :loading="passkeyLoading"
          style="width: 100%"
          @click="onPasskey"
        />

        <Divider align="center"><span style="color: var(--p-text-muted-color); font-size: 0.8rem">{{ t('auth.changePassword.orSetPassword') }}</span></Divider>

        <form @submit.prevent="onSubmit" style="display: flex; flex-direction: column; gap: 1.25rem">
          <FloatLabel variant="on">
            <Password id="current" v-model="currentPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'current-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="current">{{ t('auth.changePassword.currentPassword') }}</label>
          </FloatLabel>
          <FloatLabel variant="on">
            <Password id="new-pass" v-model="newPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="new-pass">{{ t('auth.changePassword.newPassword') }}</label>
          </FloatLabel>
          <PasswordStrengthMeter :password="newPassword" :user-inputs="[auth.user?.email ?? '']" />
          <FloatLabel variant="on">
            <Password id="confirm-pass" v-model="confirmPassword" :feedback="false" toggle-mask :input-props="{ autocomplete: 'new-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
            <label for="confirm-pass">{{ t('auth.changePassword.confirmNewPassword') }}</label>
          </FloatLabel>
          <Button type="submit" :label="t('auth.changePassword.action')" :loading="loading" severity="secondary" style="width: 100%" />
        </form>
      </div>
    </template>
  </Card>
</template>
