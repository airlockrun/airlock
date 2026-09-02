<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'

interface EnvVar {
  slug: string
  description: string
  isSecret: boolean
  configured: boolean
  defaultValue?: string
  pattern?: string
  value?: string  // only present for non-secret + configured
  updatedAt?: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()

const toast = useToast()
const confirm = useConfirm()
const { t } = useAirlockI18n()
const envVars = ref<EnvVar[]>([])
watch(envVars, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)

const dialogVisible = ref(false)
const selected = ref<EnvVar | null>(null)
const formValue = ref('')
const saving = ref(false)

async function load() {
  loading.value = true
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/env-vars`)
    envVars.value = data.envVars || []
  } finally {
    loading.value = false
  }
}

function openEdit(ev: EnvVar) {
  selected.value = ev
  // For secrets we never pre-fill — operator can only set a fresh value.
  formValue.value = ev.isSecret ? '' : (ev.value ?? ev.defaultValue ?? '')
  dialogVisible.value = true
}

// patternMatches checks the typed value against the slot's pattern (if any).
// JS RegExp's syntax is a near-superset of Go RE2 for the kinds of patterns
// builders write (character classes, anchors, repetitions); validation is
// intentionally also enforced server-side, so this is purely UX.
function patternMatches(): boolean {
  if (!selected.value?.pattern) return true
  try {
    const re = new RegExp(selected.value.pattern)
    return re.test(formValue.value)
  } catch {
    return true // bad pattern → don't block; server will reject
  }
}

const patternError = computed(() => {
  if (!selected.value?.pattern) return ''
  return patternMatches() ? '' : t('agentConfig.envVars.patternError', { pattern: selected.value.pattern })
})

async function save() {
  if (!selected.value) return
  if (!patternMatches()) {
    toast.add({ severity: 'error', summary: patternError.value, life: 5000 })
    return
  }
  saving.value = true
  try {
    await api.post(
      `/api/v1/agents/${props.agentId}/env-vars/${selected.value.slug}`,
      { value: formValue.value },
    )
    toast.add({ severity: 'success', summary: t('agentConfig.envVars.updated', { slug: selected.value.slug }), life: 3000 })
    dialogVisible.value = false
    formValue.value = ''
    await load()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.common.saveFailed'), life: 5000 })
  } finally {
    saving.value = false
  }
}

async function clearValue(ev: EnvVar) {
  confirm.require({
    message: ev.isSecret
      ? t('agentConfig.envVars.clearSecretConfirmation', { slug: ev.slug })
      : t('agentConfig.envVars.clearValueConfirmation', { slug: ev.slug, defaultValue: ev.defaultValue ?? '' }),
    header: t('agentConfig.envVars.clearValue'),
    icon: 'pi pi-exclamation-triangle',
    rejectProps: { label: t('agentConfig.common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('agentConfig.envVars.clear'), severity: 'danger' },
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/env-vars/${ev.slug}`)
        toast.add({ severity: 'success', summary: t('agentConfig.envVars.cleared', { slug: ev.slug }), life: 3000 })
        await load()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.envVars.clearFailed'), life: 5000 })
      }
    },
  })
}

onMounted(load)
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="envVars" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          {{ t('agentConfig.envVars.emptyBeforeIdentifier') }} <code>agent.RegisterEnvVar</code>{{ t('agentConfig.envVars.emptyAfterIdentifier') }}
        </div>
      </template>

      <Column field="slug" :header="t('agentConfig.envVars.slug')">
        <template #body="{ data: ev }">
          <strong>{{ ev.slug }}</strong>
          <Tag
            v-if="ev.isSecret"
            :value="t('agentConfig.envVars.secret')"
            severity="danger"
            style="margin-left: 0.5rem; vertical-align: middle"
          />
        </template>
      </Column>

      <Column field="description" :header="t('agentConfig.common.description')">
        <template #body="{ data: ev }">
          <span v-if="ev.description">{{ ev.description }}</span>
          <span v-else style="color: var(--p-text-muted-color)">-</span>
        </template>
      </Column>

      <Column :header="t('agentConfig.envVars.value')">
        <template #body="{ data: ev }">
          <code v-if="ev.isSecret && ev.configured" style="color: var(--p-text-muted-color)">••••••••</code>
          <span v-else-if="ev.isSecret" style="color: var(--p-text-muted-color)">{{ t('agentConfig.envVars.notSet') }}</span>
          <code v-else-if="ev.value" style="word-break: break-all">{{ ev.value }}</code>
          <code v-else-if="ev.defaultValue" style="color: var(--p-text-muted-color); font-style: italic">{{ t('agentConfig.envVars.defaultValue', { value: ev.defaultValue }) }}</code>
          <span v-else style="color: var(--p-text-muted-color)">{{ t('agentConfig.envVars.notSet') }}</span>
        </template>
      </Column>

      <Column :header="t('agentConfig.common.actions')">
        <template #body="{ data: ev }">
          <div style="display: flex; gap: 0.25rem">
            <Button
              :label="ev.configured ? (ev.isSecret ? t('agentConfig.envVars.rotate') : t('agentConfig.common.edit')) : t('agentConfig.envVars.set')"
              size="small"
              outlined
              @click="openEdit(ev)"
            />
            <Button
              v-if="ev.configured"
              icon="pi pi-times"
              size="small"
              text
              severity="danger"
              :aria-label="t('agentConfig.envVars.clearValue')"
              @click="clearValue(ev)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column :header="t('agentConfig.envVars.slug')"><template #body><Skeleton width="10rem" /></template></Column>
      <Column :header="t('agentConfig.common.description')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.envVars.value')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.common.actions')"><template #body><Skeleton width="6rem" /></template></Column>
    </DataTable>

    <Dialog
      v-model:visible="dialogVisible"
      :header="selected ? t(selected.configured ? 'agentConfig.envVars.updateDialogTitle' : 'agentConfig.envVars.setDialogTitle', { slug: selected.slug }) : ''"
      modal
      style="width: 32rem"
    >
      <div v-if="selected" style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <p v-if="selected.description" style="font-size: 0.85rem; color: var(--p-text-muted-color); margin: 0">
          {{ selected.description }}
        </p>

        <div v-if="selected.isSecret" class="code-chip" style="font-size: 0.8rem; color: var(--p-text-muted-color); padding: 0.5rem 0.75rem">
          {{ t('agentConfig.envVars.secretExplanation') }}
        </div>

        <FloatLabel variant="on" v-if="selected.isSecret">
          <Password id="env-value" v-model="formValue" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="env-value">{{ t('agentConfig.envVars.value') }}</label>
        </FloatLabel>
        <FloatLabel variant="on" v-else>
          <InputText id="env-value" v-model="formValue" :pattern="selected.pattern" style="width: 100%" />
          <label for="env-value">{{ t('agentConfig.envVars.value') }}</label>
        </FloatLabel>

        <div v-if="selected.pattern" style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">{{ t('agentConfig.envVars.patternLabel') }} </span>
          <code>{{ selected.pattern }}</code>
        </div>

        <Message v-if="patternError" severity="error" :closable="false" style="font-size: 0.8rem">{{ patternError }}</Message>

        <div v-if="!selected.isSecret && selected.defaultValue" style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">{{ t('agentConfig.envVars.defaultLabel') }} </span>
          <code>{{ selected.defaultValue }}</code>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button :label="t('agentConfig.common.save')" :loading="saving" :disabled="!!patternError" @click="save" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
