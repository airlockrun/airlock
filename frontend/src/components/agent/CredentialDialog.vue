<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'

const props = withDefaults(defineProps<{
  agentId: string
  slug: string
  name: string
  basePath?: string
}>(), {
  basePath: 'credentials',
})

const visible = defineModel<boolean>('visible', { default: false })
const toast = useToast()
const apiKey = ref('')
const loading = ref(false)
const testing = ref(false)

async function save() {
  if (!apiKey.value) return
  loading.value = true
  try {
    const path = props.basePath === 'credentials'
      ? `/api/v1/agents/${props.agentId}/credentials/${props.slug}`
      : `/api/v1/agents/${props.agentId}/${props.basePath}/${props.slug}/credentials`
    await api.post(path, {
      apiKey: apiKey.value,
    })
    toast.add({ severity: 'success', summary: `${props.name} configured`, life: 3000 })
    visible.value = false
    apiKey.value = ''
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Failed to save credential', life: 5000 })
  } finally {
    loading.value = false
  }
}

async function test() {
  testing.value = true
  try {
    const testPath = props.basePath === 'credentials'
      ? `/api/v1/agents/${props.agentId}/credentials/${props.slug}/test`
      : `/api/v1/agents/${props.agentId}/${props.basePath}/${props.slug}/credentials/test`
    await api.post(testPath)
    toast.add({ severity: 'success', summary: 'Connection test passed', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Connection test failed', life: 5000 })
  } finally {
    testing.value = false
  }
}
</script>

<template>
  <Dialog v-model:visible="visible" :header="`Configure ${name}`" modal style="width: 28rem">
    <div style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
      <FloatLabel>
        <Password id="cred-key" v-model="apiKey" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
        <label for="cred-key">API Key</label>
      </FloatLabel>
      <div style="display: flex; justify-content: space-between">
        <Button label="Test Connection" severity="secondary" size="small" :loading="testing" @click="test" />
        <Button label="Save" :loading="loading" @click="save" :disabled="!apiKey" />
      </div>
    </div>
  </Dialog>
</template>
