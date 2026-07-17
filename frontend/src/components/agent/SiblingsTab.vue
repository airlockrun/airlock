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
import { ref, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'

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

const siblings = ref<Sibling[]>([])
const inbound = ref<InboundSibling[]>([])
watch([siblings, inbound], () => emit('populated', siblings.value.length + inbound.value.length), {
  immediate: true,
})
const addable = ref<AddableSibling[]>([])
const loading = ref(true)

const accessOptions = [
  { label: 'public', value: 'public' },
  { label: 'user', value: 'user' },
  { label: 'admin', value: 'admin' },
]

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
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'add failed', life: 5000 })
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
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'update failed', life: 5000 })
  }
}

function confirmRemove(s: Sibling) {
  confirm.require({
    message: `Remove ${s.name} from this app's address book? This app's LLM will lose its agent_${s.slug} binding on the next build.`,
    header: 'Remove sibling',
    icon: 'pi pi-exclamation-triangle',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${props.agentId}/siblings/${s.id}`)
        siblings.value = siblings.value.filter(x => x.id !== s.id)
        await loadAll()
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'remove failed', life: 5000 })
      }
    },
  })
}

onMounted(loadAll)
</script>

<template>
  <div>
    <!-- Outbound: sibling address book -->
    <h3 style="margin-top: 0">Sibling apps</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      This app will be able to call the other apps listed here. Max access caps what this
      app can do on each; it auto-downgrades (and the row drops) if the target's owner lowers
      or revokes access.
    </p>

    <DataTable v-if="loading" :value="[{}, {}, {}]">
      <Column header="Slug"><template #body><Skeleton /></template></Column>
      <Column header="Name"><template #body><Skeleton /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="Max access"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header=""><template #body><Skeleton width="2rem" /></template></Column>
    </DataTable>

    <DataTable v-else-if="siblings.length > 0" :value="siblings" stripedRows>
      <Column field="slug" header="Slug" />
      <Column field="name" header="Name" />
      <Column field="description" header="Description" />
      <Column header="Max access">
        <template #body="{ data: s }">
          <Tag :value="s.effectiveMaxAccess" :severity="accessSeverity(s.effectiveMaxAccess)" />
          <span
            v-if="s.effectiveMaxAccess !== s.maxAccess"
            style="color: var(--p-text-muted-color); font-size: 0.8em; margin-left: 0.4rem"
            :title="`Set to ${s.maxAccess}, capped by the target's current grant`"
          >capped from {{ s.maxAccess }}</span>
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: s }">
          <Button icon="pi pi-pencil" size="small" text @click="openEdit(s)" />
          <Button icon="pi pi-trash" size="small" severity="danger" text @click="confirmRemove(s)" />
        </template>
      </Column>
    </DataTable>
    <p v-else style="color: var(--p-text-muted-color)">No sibling apps yet.</p>

    <div style="margin-top: 1rem">
      <Button label="Add sibling" icon="pi pi-plus" size="small" :disabled="addable.length === 0" @click="showAddDialog = true" />
    </div>

    <!-- Inbound: agents that can call this one -->
    <h3 style="margin-top: 2rem">Connected to this app</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      Apps that have added this one to their address book - who can call this app via A2A,
      and the live max access each has.
    </p>

    <DataTable v-if="!loading && inbound.length > 0" :value="inbound" stripedRows>
      <Column field="slug" header="Slug" />
      <Column field="name" header="Name" />
      <Column header="Owner">
        <template #body="{ data: s }">{{ s.ownerName || '-' }}</template>
      </Column>
      <Column header="Max access">
        <template #body="{ data: s }">
          <Tag :value="s.effectiveMaxAccess" :severity="accessSeverity(s.effectiveMaxAccess)" />
        </template>
      </Column>
    </DataTable>
    <p v-else-if="!loading" style="color: var(--p-text-muted-color)">No apps call this one.</p>

    <Dialog v-model:visible="showAddDialog" header="Add sibling" modal :style="{ width: '32rem' }">
      <p style="margin-top: 0; color: var(--p-text-muted-color)">
        Apps this app's owner has access to.
      </p>
      <label style="display: block; font-weight: 600; margin-bottom: 0.25rem">App</label>
      <Select
        v-model="selectedSiblingId"
        :options="addable"
        optionLabel="name"
        optionValue="id"
        placeholder="Pick an app"
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
      <label style="display: block; font-weight: 600; margin: 1rem 0 0.25rem">Max access</label>
      <Select
        v-model="selectedMaxAccess"
        :options="accessOptions"
        optionLabel="label"
        optionValue="value"
        style="width: 100%"
      />
      <p style="color: var(--p-text-muted-color); font-size: 0.85em; margin-top: 0.5rem">
        The ceiling for what this app can do when it calls the sibling. The real access is still
        floored by the driving user's and this app's owner's access on the target.
      </p>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showAddDialog = false" />
        <Button label="Add" :disabled="!selectedSiblingId" @click="addSibling" />
      </template>
    </Dialog>

    <Dialog v-model:visible="showEditDialog" header="Edit max access" modal :style="{ width: '28rem' }">
      <p style="margin-top: 0; color: var(--p-text-muted-color)">
        {{ editTarget?.name }} <code>({{ editTarget?.slug }})</code>
      </p>
      <label style="display: block; font-weight: 600; margin-bottom: 0.25rem">Max access</label>
      <Select
        v-model="editMaxAccess"
        :options="accessOptions"
        optionLabel="label"
        optionValue="value"
        style="width: 100%"
      />
      <p style="color: var(--p-text-muted-color); font-size: 0.85em; margin-top: 0.5rem">
        Operator intent. The effective ceiling is still floored by the target's current grant.
      </p>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showEditDialog = false" />
        <Button label="Save" @click="saveEdit" />
      </template>
    </Dialog>
  </div>
</template>
