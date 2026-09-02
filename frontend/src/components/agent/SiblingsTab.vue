<script setup lang="ts">
// SiblingsTab: the agent's A2A address book.
//   - Outbound: other agents this one's LLM can call. Each row produces an
//     agent_<slug> binding, capped at the per-edge max_access (operator
//     intent). The table shows the LIVE effective ceiling = min(intent,
//     current authorizing-grant role) and auto-downgrades when the target's
//     owner lowers the grant; the edge disappears entirely when the grant is
//     revoked (DB cascade).
//   - Inbound: agents that have added THIS agent — who can reach in, and at
//     what live ceiling.
// Who may call this agent's MCP endpoint at all lives on the Access tab.
import { computed, ref, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useAirlockI18n } from '@/i18n'

interface Sibling {
  id: string
  slug: string
  name: string
  description?: string
  maxAccess: string
  effectiveMaxAccess: string
}

interface AddableSibling {
  id: string
  slug: string
  name: string
  description?: string
  ownerName?: string
}

interface InboundSibling {
  id: string
  slug: string
  name: string
  description?: string
  maxAccess: string
  effectiveMaxAccess: string
  ownerName?: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const toast = useToast()
const confirm = useConfirm()
const { t } = useAirlockI18n()

const siblings = ref<Sibling[]>([])
const inbound = ref<InboundSibling[]>([])
watch([siblings, inbound], () => emit('populated', siblings.value.length + inbound.value.length), {
  immediate: true,
})
const addable = ref<AddableSibling[]>([])
const loading = ref(true)

const accessOptions = computed(() => [
  { label: accessLabel('public'), value: 'public' },
  { label: accessLabel('user'), value: 'user' },
  { label: accessLabel('admin'), value: 'admin' },
])

const showAddDialog = ref(false)
const selectedSiblingId = ref('')
const selectedMaxAccess = ref<'public' | 'user' | 'admin'>('user')

const showEditDialog = ref(false)
const editTarget = ref<Sibling | null>(null)
const editMaxAccess = ref<'public' | 'user' | 'admin'>('user')

function accessSeverity(a: string): string {
  if (a === 'admin') return 'warn'
  if (a === 'user') return 'info'
  return 'secondary'
}

function accessLabel(access: string): string {
  if (access === 'public') return t('agentConfig.accessLevel.public')
  if (access === 'user') return t('agentConfig.accessLevel.user')
  if (access === 'admin') return t('agentConfig.accessLevel.admin')
  return access
}

async function loadAll() {
  loading.value = true
  try {
    const [sList, iList, aList] = await Promise.all([
      api.get(`/api/v1/agents/${props.agentId}/siblings`),
      api.get(`/api/v1/agents/${props.agentId}/siblings/inbound`),
      api.get(`/api/v1/agents/${props.agentId}/siblings/addable`),
    ])
    siblings.value = sList.data?.siblings || []
    inbound.value = iList.data?.siblings || []
    addable.value = aList.data?.agents || []
  } finally {
    loading.value = false
  }
}

async function addSibling() {
  if (!selectedSiblingId.value) return
  try {
    await api.post(`/api/v1/agents/${props.agentId}/siblings`, {
      siblingId: selectedSiblingId.value,
      maxAccess: selectedMaxAccess.value,
    })
    showAddDialog.value = false
    selectedSiblingId.value = ''
    selectedMaxAccess.value = 'user'
    await loadAll()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.siblings.addFailed'), life: 5000 })
  }
}

function openEdit(s: Sibling) {
  editTarget.value = s
  editMaxAccess.value = s.maxAccess as 'public' | 'user' | 'admin'
  showEditDialog.value = true
}

async function saveEdit() {
  if (!editTarget.value) return
  try {
    await api.patch(`/api/v1/agents/${props.agentId}/siblings/${editTarget.value.id}`, {
      maxAccess: editMaxAccess.value,
    })
    showEditDialog.value = false
    editTarget.value = null
    await loadAll()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.siblings.updateFailed'), life: 5000 })
  }
}

function confirmRemove(s: Sibling) {
  confirm.require({
    message: t('agentConfig.siblings.removeConfirmation', { name: s.name, binding: `agent_${s.slug}` }),
    header: t('agentConfig.siblings.removeSibling'),
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/siblings/${s.id}`)
        siblings.value = siblings.value.filter(x => x.id !== s.id)
        await loadAll()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('agentConfig.siblings.removeFailed'), life: 5000 })
      }
    },
  })
}

onMounted(loadAll)
</script>

<template>
  <div>
    <!-- Outbound: sibling address book -->
    <h3 style="margin-top: 0">{{ t('agentConfig.siblings.title') }}</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      {{ t('agentConfig.siblings.description') }}
    </p>

    <DataTable v-if="loading" :value="[{}, {}, {}]">
      <Column :header="t('agentConfig.envVars.slug')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.common.name')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.common.description')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.siblings.maxAccess')"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header=""><template #body><Skeleton width="2rem" /></template></Column>
    </DataTable>

    <DataTable v-else-if="siblings.length > 0" :value="siblings" stripedRows>
      <Column field="slug" :header="t('agentConfig.envVars.slug')" />
      <Column field="name" :header="t('agentConfig.common.name')" />
      <Column field="description" :header="t('agentConfig.common.description')" />
      <Column :header="t('agentConfig.siblings.maxAccess')">
        <template #body="{ data: s }">
          <Tag :value="accessLabel(s.effectiveMaxAccess)" :severity="accessSeverity(s.effectiveMaxAccess)" />
          <span
            v-if="s.effectiveMaxAccess !== s.maxAccess"
            style="color: var(--p-text-muted-color); font-size: 0.8em; margin-left: 0.4rem"
            :title="t('agentConfig.siblings.cappedTitle', { access: accessLabel(s.maxAccess) })"
          >{{ t('agentConfig.siblings.cappedFrom', { access: accessLabel(s.maxAccess) }) }}</span>
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: s }">
          <Button icon="pi pi-pencil" size="small" text @click="openEdit(s)" />
          <Button icon="pi pi-trash" size="small" severity="danger" text @click="confirmRemove(s)" />
        </template>
      </Column>
    </DataTable>
    <p v-else style="color: var(--p-text-muted-color)">{{ t('agentConfig.siblings.empty') }}</p>

    <div style="margin-top: 1rem">
      <Button :label="t('agentConfig.siblings.addSibling')" icon="pi pi-plus" size="small" :disabled="addable.length === 0" @click="showAddDialog = true" />
    </div>

    <!-- Inbound: agents that can call this one -->
    <h3 style="margin-top: 2rem">{{ t('agentConfig.siblings.connectedTitle') }}</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      {{ t('agentConfig.siblings.connectedDescription') }}
    </p>

    <DataTable v-if="!loading && inbound.length > 0" :value="inbound" stripedRows>
      <Column field="slug" :header="t('agentConfig.envVars.slug')" />
      <Column field="name" :header="t('agentConfig.common.name')" />
      <Column :header="t('agentConfig.siblings.owner')">
        <template #body="{ data: s }">{{ s.ownerName || '-' }}</template>
      </Column>
      <Column :header="t('agentConfig.siblings.maxAccess')">
        <template #body="{ data: s }">
          <Tag :value="accessLabel(s.effectiveMaxAccess)" :severity="accessSeverity(s.effectiveMaxAccess)" />
        </template>
      </Column>
    </DataTable>
    <p v-else-if="!loading" style="color: var(--p-text-muted-color)">{{ t('agentConfig.siblings.noInbound') }}</p>

    <Dialog v-model:visible="showAddDialog" :header="t('agentConfig.siblings.addSibling')" modal :style="{ width: '32rem' }">
      <p style="margin-top: 0; color: var(--p-text-muted-color)">
        {{ t('agentConfig.siblings.addDialogDescription') }}
      </p>
      <label style="display: block; font-weight: 600; margin-bottom: 0.25rem">{{ t('agentConfig.siblings.app') }}</label>
      <Select
        v-model="selectedSiblingId"
        :options="addable"
        optionLabel="name"
        optionValue="id"
        :placeholder="t('agentConfig.siblings.pickApp')"
        style="width: 100%"
        :pt="{ overlay: { style: 'max-width: 95vw' } }"
      >
        <template #option="slot">
          <!-- white-space:normal so a long name/description wraps instead of
               forcing the overlay wider than the viewport on mobile. -->
          <div style="white-space: normal; overflow-wrap: anywhere; max-width: 100%">
            <strong>{{ slot.option.name }}</strong> <code>({{ slot.option.slug }})</code>
            <span v-if="slot.option.ownerName" style="color: var(--p-text-muted-color); font-size: 0.85em">
              · {{ slot.option.ownerName }}
            </span>
            <div v-if="slot.option.description" style="color: var(--p-text-muted-color); font-size: 0.85em">
              {{ slot.option.description }}
            </div>
          </div>
        </template>
      </Select>
      <label style="display: block; font-weight: 600; margin: 1rem 0 0.25rem">{{ t('agentConfig.siblings.maxAccess') }}</label>
      <Select
        v-model="selectedMaxAccess"
        :options="accessOptions"
        optionLabel="label"
        optionValue="value"
        style="width: 100%"
      />
      <p style="color: var(--p-text-muted-color); font-size: 0.85em; margin-top: 0.5rem">
        {{ t('agentConfig.siblings.maxAccessHelp') }}
      </p>
      <template #footer>
        <Button :label="t('agentConfig.common.cancel')" severity="secondary" text @click="showAddDialog = false" />
        <Button :label="t('agentConfig.common.add')" :disabled="!selectedSiblingId" @click="addSibling" />
      </template>
    </Dialog>

    <Dialog v-model:visible="showEditDialog" :header="t('agentConfig.siblings.editMaxAccess')" modal :style="{ width: '28rem' }">
      <p style="margin-top: 0; color: var(--p-text-muted-color)">
        {{ editTarget?.name }} <code>({{ editTarget?.slug }})</code>
      </p>
      <label style="display: block; font-weight: 600; margin-bottom: 0.25rem">{{ t('agentConfig.siblings.maxAccess') }}</label>
      <Select
        v-model="editMaxAccess"
        :options="accessOptions"
        optionLabel="label"
        optionValue="value"
        style="width: 100%"
      />
      <p style="color: var(--p-text-muted-color); font-size: 0.85em; margin-top: 0.5rem">
        {{ t('agentConfig.siblings.editMaxAccessHelp') }}
      </p>
      <template #footer>
        <Button :label="t('agentConfig.common.cancel')" severity="secondary" text @click="showEditDialog = false" />
        <Button :label="t('agentConfig.common.save')" @click="saveEdit" />
      </template>
    </Dialog>
  </div>
</template>
