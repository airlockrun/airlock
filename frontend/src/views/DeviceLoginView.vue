<script setup lang="ts">
import { computed, ref } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { DeviceLoginInspectResponseSchema } from '@/gen/airlock/v1/api_pb'

const auth = useAuthStore()

const rawCode = ref('')
const inspecting = ref(false)
const deciding = ref<'approve' | 'deny' | null>(null)
const error = ref('')
const result = ref<any | null>(null)

const normalizedCode = computed(() => rawCode.value.replace(/[\s-]/g, '').toUpperCase())
const displayCode = computed(() => {
  const code = normalizedCode.value.slice(0, 8)
  return code.length > 4 ? `${code.slice(0, 4)}-${code.slice(4)}` : code
})
const canInspect = computed(() => normalizedCode.value.length === 8 && !inspecting.value)
const pending = computed(() => result.value?.status === 'pending')

function inputCode(value: string) {
  rawCode.value = value.replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 8)
  result.value = null
  error.value = ''
}

async function inspect() {
  if (!canInspect.value) return
  inspecting.value = true
  error.value = ''
  result.value = null
  try {
    const { data } = await api.post('/api/v1/device-login/inspect', { userCode: displayCode.value })
    result.value = fromJson(DeviceLoginInspectResponseSchema, data)
  } catch (err: any) {
    error.value = err?.response?.data?.error || err?.message || 'Code lookup failed'
  } finally {
    inspecting.value = false
  }
}

async function decide(decision: 'approve' | 'deny') {
  if (!pending.value || deciding.value) return
  deciding.value = decision
  error.value = ''
  try {
    const path = decision === 'approve' ? '/api/v1/device-login/approve' : '/api/v1/device-login/deny'
    const { data } = await api.post(path, { userCode: result.value?.userCode || displayCode.value })
    result.value = fromJson(DeviceLoginInspectResponseSchema, data)
  } catch (err: any) {
    error.value = err?.response?.data?.error || err?.message || 'Device login update failed'
  } finally {
    deciding.value = null
  }
}
</script>

<template>
  <div class="device-login-page">
    <Card class="device-login-card">
      <template #title>Sign in to Airlock CLI</template>
      <template #content>
        <Message severity="info" :closable="false" class="device-login-info">
          Enter the code shown in your terminal. For security, Airlock does not accept login codes from links.
        </Message>

        <Message v-if="error" severity="error" :closable="false" class="mb-4">{{ error }}</Message>

        <label class="code-label" for="device-code">Device code</label>
        <InputText
          id="device-code"
          :model-value="displayCode"
          placeholder="ABCD-EFGH"
          class="code-input"
          autocomplete="one-time-code"
          inputmode="text"
          @update:model-value="inputCode(String($event))"
          @keyup.enter="inspect"
        />

        <Button label="Check code" class="check-code-button" :disabled="!canInspect" :loading="inspecting" @click="inspect" />

        <div v-if="result" class="request-box">
          <div class="request-row">
            <span>Code</span>
            <strong>{{ result.userCode }}</strong>
          </div>
          <div class="request-row">
            <span>Requested by</span>
            <strong>{{ result.clientName || 'air CLI' }}</strong>
          </div>
          <div v-if="result.deviceName" class="request-row">
            <span>Device</span>
            <strong>{{ result.deviceName }}</strong>
          </div>
          <div class="request-row">
            <span>Account</span>
            <strong>{{ auth.user?.email }}</strong>
          </div>
          <div class="request-row">
            <span>Status</span>
            <Tag :severity="pending ? 'info' : result.status === 'approved' ? 'success' : 'warn'" :value="result.status" />
          </div>
        </div>
      </template>
      <template #footer>
        <div class="footer-actions">
          <Button label="Deny" severity="secondary" :disabled="!pending || !!deciding" :loading="deciding === 'deny'" @click="decide('deny')" />
          <Button label="Approve" :disabled="!pending || !!deciding" :loading="deciding === 'approve'" @click="decide('approve')" />
        </div>
      </template>
    </Card>
  </div>
</template>

<style scoped>
.device-login-page {
  display: flex;
  justify-content: center;
  padding: 3rem 1rem;
}
.device-login-card {
  max-width: 34rem;
  width: 100%;
}
.code-label {
  display: block;
  font-weight: 600;
  margin-bottom: 0.5rem;
}
.device-login-info {
  margin-bottom: 1rem;
}
.code-input {
  width: 100%;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 1.35rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.check-code-button {
  margin-top: 0.75rem;
}
.request-box {
  margin-top: 1.25rem;
  border: 1px solid var(--p-surface-200);
  border-radius: 12px;
  padding: 1rem;
}
.request-row {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.35rem 0;
}
.footer-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
:root.dark .request-box {
  border-color: var(--p-surface-700);
}
</style>
