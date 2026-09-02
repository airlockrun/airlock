<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'

const route = useRoute()
const { t } = useAirlockI18n()
const error = ref('')

onMounted(async () => {
  const returnUrl = route.query.return as string
  const nonce = route.query.nonce as string
  if (!returnUrl || !nonce) {
    error.value = t('auth.relay.missingParameters')
    return
  }

  try {
    const { data } = await api.post('/auth/relay-code', { returnUrl, nonce })
    window.location.replace(data.callbackUrl)
  } catch (err: any) {
    error.value = err.response?.data?.error || t('auth.relay.failed')
  }
})
</script>

<template>
  <Card style="width: 24rem">
    <template #title>
      <div style="text-align: center; font-size: 1.5rem">{{ t('auth.product.airlock') }}</div>
    </template>
    <template #content>
      <div v-if="error" style="text-align: center">
        <Message severity="error" :closable="false">{{ error }}</Message>
      </div>
      <div v-else style="text-align: center; padding: 2rem 0">
        <ProgressSpinner style="width: 2rem; height: 2rem" />
        <p style="margin-top: 1rem; color: var(--p-text-muted-color)">{{ t('auth.relay.authenticating') }}</p>
      </div>
    </template>
  </Card>
</template>
