<script setup lang="ts">
// SiblingsTab: A2A (agent-to-agent) controls on the parent agent's
// detail page.
//   - Two access toggles (allow_non_member_mcp, allow_public_mcp)
//     governing who may call THIS agent's MCP endpoint.
//   - The address book — other agents this one's LLM is allowed to
//     call. Authorization at call time is always evaluated fresh
//     against each target's settings; this list is only a discovery
//     aid that produces `agent_<slug>` bindings in the LLM's
//     run_js sandbox.
import { ref, onMounted, watch } from 'vue'
import api from '@/api/client'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'

interface Sibling {
  id: string
  slug: string
  name: string
  description?: string
  allowNonMemberMcp: boolean
  allowPublicMcp?: boolean
}

interface AddableSibling extends Sibling {
  isMember: boolean
}

interface A2ASettings {
  allowNonMemberMcp: boolean
  allowPublicMcp: boolean
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const toast = useToast()
const confirm = useConfirm()

const siblings = ref<Sibling[]>([])
watch(siblings, (v) => emit('populated', v.length), { immediate: true })
const addable = ref<AddableSibling[]>([])
const loading = ref(true)
const settings = ref<A2ASettings>({ allowNonMemberMcp: false, allowPublicMcp: false })
const showAddDialog = ref(false)
const selectedSiblingId = ref('')

async function loadAll() {
  loading.value = true
  try {
    const [sList, aList, sCfg] = await Promise.all([
      api.get(`/api/v1/agents/${props.agentId}/siblings`),
      api.get(`/api/v1/agents/${props.agentId}/siblings/addable`),
      api.get(`/api/v1/agents/${props.agentId}/a2a-settings`),
    ])
    siblings.value = sList.data?.siblings || []
    addable.value = aList.data?.agents || []
    settings.value = {
      allowNonMemberMcp: !!sCfg.data?.settings?.allowNonMemberMcp,
      allowPublicMcp: !!sCfg.data?.settings?.allowPublicMcp,
    }
  } finally {
    loading.value = false
  }
}

async function saveSettings() {
  // The "public" toggle silently flips "non-member" on — the server
  // enforces this via a CHECK constraint, but we mirror in the UI
  // so the user sees the rule rather than getting a 400.
  if (settings.value.allowPublicMcp) {
    settings.value.allowNonMemberMcp = true
  }
  try {
    await api.put(`/api/v1/agents/${props.agentId}/a2a-settings`, { settings: settings.value })
    toast.add({ severity: 'success', summary: 'MCP settings saved', life: 2000 })
    await loadAll() // addable list changes when non-member-mcp flips
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'save failed', life: 5000 })
  }
}

async function addSibling() {
  if (!selectedSiblingId.value) return
  try {
    await api.post(`/api/v1/agents/${props.agentId}/siblings`, {
      siblingId: selectedSiblingId.value,
    })
    showAddDialog.value = false
    selectedSiblingId.value = ''
    await loadAll()
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'add failed', life: 5000 })
  }
}

function confirmRemove(s: Sibling) {
  confirm.require({
    message: `Remove ${s.name} from this agent's address book? This agent's LLM will lose its agent_${s.slug} binding on the next build.`,
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
    <!-- Access toggles -->
    <h3 style="margin-top: 0">Who can call this agent</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      These toggles govern access to this agent's <code>/api/agent/&lt;uuid&gt;/mcp</code>
      endpoint — used by other Airlock agents and by external MCP clients (Claude Desktop, Codex CLI).
      Toggling either OFF immediately revokes the matching tier; in-flight calls are unaffected.
    </p>
    <div style="display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.5rem">
      <label style="display: flex; align-items: center; gap: 0.75rem">
        <ToggleSwitch v-model="settings.allowNonMemberMcp" :disabled="settings.allowPublicMcp" />
        <span>
          Allow authed users who are <strong>not</strong> members of this agent (they get public-tier access)
        </span>
      </label>
      <label style="display: flex; align-items: center; gap: 0.75rem">
        <ToggleSwitch v-model="settings.allowPublicMcp" />
        <span>
          Allow <strong>anonymous</strong> MCP calls (no JWT). Forces the non-member toggle on.
        </span>
      </label>
      <div>
        <Button label="Save MCP settings" size="small" @click="saveSettings" />
      </div>
    </div>

    <!-- Sibling address book -->
    <h3>Sibling agents</h3>
    <p style="color: var(--p-text-muted-color); margin-top: 0">
      Other agents whose tools this agent's LLM can discover and call. Each row produces an
      <code>agent_&lt;slug&gt;</code> namespace in <code>run_js</code> with one method per tool plus
      <code>prompt({ message, conversationId? })</code>.
      Authorization is always re-evaluated against the target's MCP settings — a sibling listed
      here may still return 403 if the original user lacks access.
    </p>

    <DataTable v-if="loading" :value="[{}, {}, {}]">
      <Column header="Slug"><template #body><Skeleton /></template></Column>
      <Column header="Name"><template #body><Skeleton /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="MCP access"><template #body><Skeleton width="4rem" /></template></Column>
      <Column header=""><template #body><Skeleton width="2rem" /></template></Column>
    </DataTable>

    <DataTable v-else-if="siblings.length > 0" :value="siblings" stripedRows>
      <Column field="slug" header="Slug" />
      <Column field="name" header="Name" />
      <Column field="description" header="Description" />
      <Column header="MCP access">
        <template #body="{ data: s }">
          <Tag v-if="s.allowPublicMcp" value="public" severity="warn" />
          <Tag v-else-if="s.allowNonMemberMcp" value="non-member" severity="info" />
          <Tag v-else value="members-only" severity="secondary" />
        </template>
      </Column>
      <Column header="">
        <template #body="{ data: s }">
          <Button icon="pi pi-trash" size="small" severity="danger" text @click="confirmRemove(s)" />
        </template>
      </Column>
    </DataTable>

    <div style="margin-top: 1rem">
      <Button label="Add sibling" icon="pi pi-plus" size="small" :disabled="addable.length === 0" @click="showAddDialog = true" />
    </div>

    <Dialog v-model:visible="showAddDialog" header="Add sibling" modal :style="{ width: '32rem' }">
      <p style="margin-top: 0; color: var(--p-text-muted-color)">
        Only agents you are a member of, or that have non-member MCP enabled, are listed here.
      </p>
      <Select
        v-model="selectedSiblingId"
        :options="addable"
        optionLabel="name"
        optionValue="id"
        placeholder="Pick an agent"
        style="width: 100%"
      >
        <template #option="slot">
          <div>
            <strong>{{ slot.option.name }}</strong> <code>({{ slot.option.slug }})</code>
            <Tag v-if="slot.option.isMember" value="member" severity="success" style="margin-left: 0.5rem" />
            <Tag v-else value="non-member-open" severity="info" style="margin-left: 0.5rem" />
            <div v-if="slot.option.description" style="color: var(--p-text-muted-color); font-size: 0.85em">
              {{ slot.option.description }}
            </div>
          </div>
        </template>
      </Select>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showAddDialog = false" />
        <Button label="Add" :disabled="!selectedSiblingId" @click="addSibling" />
      </template>
    </Dialog>
  </div>
</template>
