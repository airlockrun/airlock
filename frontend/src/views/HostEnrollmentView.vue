<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { HostEnrollmentInfo } from '@/gen/airlock/v1/api_pb'
import { approveHostEnrollment, denyHostEnrollment, inspectHostEnrollment } from '@/api/hosts'
import { useAirlockI18n } from '@/i18n'

const toast = useToast()
const { t } = useAirlockI18n()
const code = ref('')
const enrollment = ref<HostEnrollmentInfo | null>(null)
const loading = ref(false)

async function inspect() {
  loading.value = true
  try { enrollment.value = await inspectHostEnrollment(code.value.trim()) }
  catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.enrollment.notFound')), life: 5000 }) }
  finally { loading.value = false }
}

async function approve() {
  loading.value = true
  try {
    enrollment.value = await approveHostEnrollment(code.value.trim())
    toast.add({ severity: 'success', summary: t('connectors.enrollment.approved'), life: 3000 })
  } catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.enrollment.approvalFailed')), life: 5000 }) }
  finally { loading.value = false }
}

async function deny() {
  loading.value = true
  try {
    await denyHostEnrollment(code.value.trim())
    if (enrollment.value) enrollment.value.status = 'denied'
  } catch (error: unknown) { toast.add({ severity: 'error', summary: apiError(error, t('connectors.enrollment.denialFailed')), life: 5000 }) }
  finally { loading.value = false }
}

const statusMessageIds = {
  pending: 'connectors.enrollment.status.pending',
  approved: 'connectors.enrollment.status.approved',
  denied: 'connectors.enrollment.status.denied',
  consumed: 'connectors.enrollment.status.consumed',
  expired: 'connectors.enrollment.status.expired',
} as const

function statusLabel(status: string): string {
  const id = statusMessageIds[status as keyof typeof statusMessageIds]
  return id ? t(id) : status
}

function accessModeLabel(mode: string): string {
  if (mode === 'full') return t('connectors.host.access.full')
  if (mode === 'update_only') return t('connectors.host.access.updateOnly')
  if (mode === 'none') return t('connectors.host.access.none')
  return mode
}

function apiError(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null) {
    const typed = error as { response?: { data?: { error?: unknown } } }
    if (typeof typed.response?.data?.error === 'string') return typed.response.data.error
  }
  return fallback
}
</script>

<template>
  <div class="enroll-page">
    <Card>
      <template #title>{{ t('connectors.enrollment.title') }}</template>
      <template #subtitle>{{ t('connectors.enrollment.subtitle') }}</template>
      <template #content>
        <div class="code-row"><InputText v-model="code" placeholder="ABCD-EFGH" maxlength="9" @keydown.enter="inspect" /><Button :label="t('connectors.enrollment.inspect')" :loading="loading" @click="inspect" /></div>
        <div v-if="enrollment" class="inspection">
          <Message :severity="enrollment.status === 'pending' ? 'info' : 'secondary'" :closable="false">{{ t('connectors.enrollment.status', { status: statusLabel(enrollment.status) }) }}</Message>
          <dl>
            <div><dt>{{ t('connectors.enrollment.name') }}</dt><dd>{{ enrollment.name }}</dd></div>
            <div><dt>{{ t('connectors.enrollment.platform') }}</dt><dd>{{ enrollment.platform }} / {{ enrollment.architecture }}</dd></div>
            <div><dt>{{ t('connectors.enrollment.reportedAccess') }}</dt><dd><Tag :value="accessModeLabel(enrollment.accessMode)" /></dd></div>
            <div><dt>{{ t('connectors.enrollment.version') }}</dt><dd>{{ enrollment.version }}</dd></div>
          </dl>
          <div v-if="enrollment.status === 'pending'" class="actions"><Button :label="t('connectors.enrollment.deny')" severity="danger" outlined @click="deny" /><Button :label="t('connectors.enrollment.approve')" @click="approve" /></div>
        </div>
      </template>
    </Card>
  </div>
</template>

<style scoped>
.enroll-page { max-width: 42rem; margin: 2rem auto; }
.code-row { display: flex; gap: .75rem; }
.code-row input { flex: 1; text-transform: uppercase; letter-spacing: .16em; }
.inspection { display: grid; gap: 1rem; margin-top: 1.25rem; }
dl { display: grid; gap: .7rem; margin: 0; }
dl div { display: grid; grid-template-columns: 9rem 1fr; gap: 1rem; }
dt { color: var(--p-text-muted-color); } dd { margin: 0; }
.actions { display: flex; justify-content: flex-end; gap: .75rem; }
</style>
