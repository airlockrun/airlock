<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const toast = useToast()

const email = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
// Default to true so the activation link doesn't flash before /auth/status
// resolves; flips to false only on a confirmed not-yet-activated install.
const activated = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get('/auth/status')
    activated.value = !!data.activated
  } catch { /* leave activated=true; link stays hidden on transient errors */ }
})

async function onSubmit() {
  error.value = ''
  if (!email.value || !password.value) {
    error.value = 'Email and password are required.'
    return
  }
  loading.value = true
  try {
    await auth.login(email.value, password.value)
    toast.add({ severity: 'success', summary: 'Welcome back', life: 3000 })
    const redirect = route.query.redirect as string
    router.push(redirect || '/')
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Login failed.'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <Card style="width: 24rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Airlock</div>
    </template>
    <template #content>
      <form @submit.prevent="onSubmit" style="display: flex; flex-direction: column; gap: 1.25rem">
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        <FloatLabel>
          <InputText id="email" v-model="email" type="email" autocomplete="username" style="width: 100%" />
          <label for="email">Email</label>
        </FloatLabel>
        <FloatLabel>
          <Password id="password" v-model="password" :feedback="false" toggle-mask :input-props="{ autocomplete: 'current-password' }" style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="password">Password</label>
        </FloatLabel>
        <Button type="submit" label="Sign In" :loading="loading" style="width: 100%" />
      </form>
    </template>
    <template #footer>
      <div v-if="!activated" style="text-align: center">
        <router-link to="/activate" style="color: var(--p-primary-color); text-decoration: none; font-size: 0.875rem">
          First time? Set up Airlock
        </router-link>
      </div>
    </template>
  </Card>
</template>
