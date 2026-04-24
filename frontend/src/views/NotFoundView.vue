<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; text-align: center">
    <i class="pi pi-exclamation-triangle" style="font-size: 4rem; color: var(--p-surface-400); margin-bottom: 1rem" />
    <h1 style="font-size: 2rem; margin-bottom: 0.5rem">404</h1>
    <p style="color: var(--p-text-muted-color); margin-bottom: 1.5rem">The page you're looking for doesn't exist.</p>
    <Button label="Go to Agents" icon="pi pi-arrow-left" @click="router.push('/agents')" />
  </div>
</template>
