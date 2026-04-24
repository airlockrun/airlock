<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api/client'

const route = useRoute()
const error = ref('')

onMounted(async () => {
  const returnUrl = route.query.return as string
  if (!returnUrl) {
    error.value = 'Missing return URL.'
    return
  }

  try {
    const { data } = await api.post('/auth/relay-code', { returnUrl })
    window.location.href = data.callbackUrl
  } catch (err: any) {
    error.value = err.response?.data?.error || 'Failed to authenticate.'
  }
})
</script>

<template>
  <Card style="width: 24rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">Airlock</div>
    </template>
    <template #content>
      <div v-if="error" style="text-align: center">
        <Message severity="error" :closable="false">{{ error }}</Message>
      </div>
      <div v-else style="text-align: center; padding: 2rem 0">
        <ProgressSpinner style="width: 2rem; height: 2rem" />
        <p style="margin-top: 1rem; color: var(--p-text-muted-color)">Authenticating...</p>
      </div>
    </template>
  </Card>
</template>
