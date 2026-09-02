<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAirlockI18n } from '@/i18n'

const router = useRouter()
const { t } = useAirlockI18n()
</script>

<template>
  <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; text-align: center">
    <i class="pi pi-exclamation-triangle" style="font-size: 4rem; color: var(--p-surface-400); margin-bottom: 1rem" />
    <h1 style="font-size: 2rem; margin-bottom: 0.5rem">{{ t('auth.notFound.code') }}</h1>
    <p style="color: var(--p-text-muted-color); margin-bottom: 1.5rem">{{ t('auth.notFound.message') }}</p>
    <Button :label="t('auth.identity.goToApps')" icon="pi pi-arrow-left" @click="router.push('/agents')" />
  </div>
</template>
