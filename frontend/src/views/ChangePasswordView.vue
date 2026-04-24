<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useToast } from 'primevue/usetoast'

const router = useRouter()
const auth = useAuthStore()
const toast = useToast()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const error = ref('')

async function onSubmit() {
  error.value = ''
  if (!currentPassword.value || !newPassword.value || !confirmPassword.value) {
    error.value = 'All fields are required.'
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    error.value = 'New passwords do not match.'
    return
  }
  if (newPassword.value.length < 8) {
    error.value = 'New password must be at least 8 characters.'
    return
  }

  loading.value = true
  try {
    await auth.changePassword(currentPassword.value, newPassword.value)
    toast.add({ severity: 'success', summary: 'Password changed', life: 3000 })
    router.push('/')
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to change password.'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <Card style="width: 24rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Change Password</div>
    </template>
    <template #subtitle>
      <div style="text-align: center">You must change your password before continuing.</div>
    </template>
    <template #content>
      <form @submit.prevent="onSubmit" style="display: flex; flex-direction: column; gap: 1.25rem">
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        <FloatLabel>
          <Password id="current" v-model="currentPassword" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="current">Current Password</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="new-pass" v-model="newPassword" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="new-pass">New Password</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="confirm-pass" v-model="confirmPassword" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="confirm-pass">Confirm New Password</label>
        </FloatLabel>
        <Button type="submit" label="Change Password" :loading="loading" style="width: 100%" />
      </form>
    </template>
  </Card>
</template>
