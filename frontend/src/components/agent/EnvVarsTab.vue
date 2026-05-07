<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import api from '@/api/client'

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

const toast = useToast()
const confirm = useConfirm()
const envVars = ref<EnvVar[]>([])
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
  return patternMatches() ? '' : `Value must match pattern: ${selected.value.pattern}`
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
    toast.add({ severity: 'success', summary: `${selected.value.slug} updated`, life: 3000 })
    dialogVisible.value = false
    formValue.value = ''
    await load()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Save failed', life: 5000 })
  } finally {
    saving.value = false
  }
}

async function clearValue(ev: EnvVar) {
  confirm.require({
    message: ev.isSecret
      ? `Clear the configured value for ${ev.slug}? The agent will fail to read this until you set a new value.`
      : `Clear the configured value for ${ev.slug}? The agent will fall back to the default ("${ev.defaultValue ?? ''}").`,
    header: 'Clear value',
    icon: 'pi pi-exclamation-triangle',
    rejectProps: { label: 'Cancel', severity: 'secondary', outlined: true },
    acceptProps: { label: 'Clear', severity: 'danger' },
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/env-vars/${ev.slug}`)
        toast.add({ severity: 'success', summary: `${ev.slug} cleared`, life: 3000 })
        await load()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Clear failed', life: 5000 })
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
          No environment variables registered. Builders declare them via <code>agent.RegisterEnvVar</code>.
        </div>
      </template>

      <Column field="slug" header="Slug">
        <template #body="{ data: ev }">
          <strong>{{ ev.slug }}</strong>
          <Tag
            v-if="ev.isSecret"
            value="secret"
            severity="danger"
            style="margin-left: 0.5rem; vertical-align: middle"
          />
        </template>
      </Column>

      <Column field="description" header="Description">
        <template #body="{ data: ev }">
          <span v-if="ev.description">{{ ev.description }}</span>
          <span v-else style="color: var(--p-text-muted-color)">—</span>
        </template>
      </Column>

      <Column header="Value">
        <template #body="{ data: ev }">
          <code v-if="ev.isSecret && ev.configured" style="color: var(--p-text-muted-color)">••••••••</code>
          <span v-else-if="ev.isSecret" style="color: var(--p-text-muted-color)">not set</span>
          <code v-else-if="ev.value" style="word-break: break-all">{{ ev.value }}</code>
          <code v-else-if="ev.defaultValue" style="color: var(--p-text-muted-color); font-style: italic">{{ ev.defaultValue }} (default)</code>
          <span v-else style="color: var(--p-text-muted-color)">not set</span>
        </template>
      </Column>

      <Column header="Actions">
        <template #body="{ data: ev }">
          <div style="display: flex; gap: 0.25rem">
            <Button
              :label="ev.configured ? (ev.isSecret ? 'Rotate' : 'Edit') : 'Set'"
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
              aria-label="Clear value"
              @click="clearValue(ev)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Slug"><template #body><Skeleton width="10rem" /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="Value"><template #body><Skeleton /></template></Column>
      <Column header="Actions"><template #body><Skeleton width="6rem" /></template></Column>
    </DataTable>

    <Dialog
      v-model:visible="dialogVisible"
      :header="selected ? `${selected.configured ? 'Update' : 'Set'} ${selected.slug}` : ''"
      modal
      style="width: 32rem"
    >
      <div v-if="selected" style="display: flex; flex-direction: column; gap: 1.25rem; padding-top: 0.5rem">
        <p v-if="selected.description" style="font-size: 0.85rem; color: var(--p-text-muted-color); margin: 0">
          {{ selected.description }}
        </p>

        <div v-if="selected.isSecret" style="font-size: 0.8rem; color: var(--p-text-muted-color); background: var(--p-surface-100); padding: 0.5rem 0.75rem; border-radius: 4px">
          This value is treated as a secret. It will be redacted from LLM input, and you won't be able to read it back from this UI — only rotate.
        </div>

        <FloatLabel v-if="selected.isSecret">
          <Password id="env-value" v-model="formValue" :feedback="false" toggle-mask style="width: 100%" :input-style="{ width: '100%' }" />
          <label for="env-value">Value</label>
        </FloatLabel>
        <FloatLabel v-else>
          <InputText id="env-value" v-model="formValue" :pattern="selected.pattern" style="width: 100%" />
          <label for="env-value">Value</label>
        </FloatLabel>

        <div v-if="selected.pattern" style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">Pattern: </span>
          <code>{{ selected.pattern }}</code>
        </div>

        <Message v-if="patternError" severity="error" :closable="false" style="font-size: 0.8rem">{{ patternError }}</Message>

        <div v-if="!selected.isSecret && selected.defaultValue" style="font-size: 0.8rem">
          <span style="color: var(--p-text-muted-color)">Default: </span>
          <code>{{ selected.defaultValue }}</code>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
          <Button label="Save" :loading="saving" :disabled="!!patternError" @click="save" />
        </div>
      </div>
    </Dialog>
  </div>
</template>
