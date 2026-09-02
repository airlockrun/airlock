<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import type { CandidateInfo, NeedInfo } from '@/gen/airlock/v1/api_pb'
import type { ConnectorInfo } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'
import { useConnectorsStore } from '@/stores/connectors'
import {
  connectorDisplayName,
  connectorReadiness,
  connectorSchemaSignature,
  directoryAccess,
} from '@/utils/connectors'
import ResourceBindingDialog from './ResourceBindingDialog.vue'
import InstallConnectorDialog from './InstallConnectorDialog.vue'
import UpdateConnectorDialog from './UpdateConnectorDialog.vue'

const props = withDefaults(defineProps<{ agentId: string; yourAccess?: string }>(), { yourAccess: '' })
const emit = defineEmits<{ populated: [count: number]; mutated: [] }>()
const store = useConnectorsStore()
const confirm = useConfirm()
const toast = useToast()
const { locale, t, formatNumber } = useAirlockI18n()
const bindingOpen = ref(false)
const installOpen = ref(false)
const updateOpen = ref(false)
const updateConnector = ref<ConnectorInfo | null>(null)
const groupBindingOpen = ref(false)
const selected = ref<NeedInfo | null>(null)
const selectedGroupId = ref('')
const groupSaving = ref(false)
const creatingGroup = ref(false)
const groupName = ref('')
const groupMemberIds = ref<string[]>([])
const groupCreating = ref(false)
const capabilityMessageIds = {
  view: 'connectors.common.capability.view',
  bind: 'connectors.common.capability.bind',
  manage: 'connectors.common.capability.manage',
} as const

const canAdmin = computed(() => props.yourAccess === 'admin')
watch(() => store.needs, (needs) => emit('populated', needs.length), { immediate: true, deep: true })

function connector(need: NeedInfo): ConnectorInfo | undefined {
  return store.connectorFor(need)
}

function compatibleCandidates(need: NeedInfo): CandidateInfo[] {
  return store.candidates[need.slug] ?? []
}

function compatibleGroups(need: NeedInfo) {
  return (store.targetGroups[need.slug] ?? []).flatMap((candidate) => candidate.group ? [{
    ...candidate.group,
    optionLabel: t('connectors.tab.groupOption', {
      name: candidate.group.name,
      ready: formatNumber(candidate.compatibleReadyMemberCount),
      total: formatNumber(candidate.group.memberCount),
    }),
    disabled: !candidate.eligible,
    reason: candidate.reason,
  }] : [])
}

const selectedGroupUsable = computed(() => !!selected.value && compatibleGroups(selected.value)
  .some((group) => group.id === selectedGroupId.value && !group.disabled))
const availableGroupMembers = computed(() => selected.value
  ? compatibleCandidates(selected.value)
      .filter((candidate) => candidate.readiness === 'ready' && candidate.capabilities.includes('bind'))
      .map((candidate) => ({
        value: candidate.resourceId,
        label: candidate.displayName || candidate.name || candidate.slug,
      }))
  : [])

function existingConnectorRows(need: NeedInfo): Array<{
  connector: ConnectorInfo
  compatible: boolean
  reason: string
}> {
  const candidateIds = new Set(compatibleCandidates(need).map((item) => item.resourceId))
  return store.connectors.map((item) => {
    if (candidateIds.has(item.id)) return { connector: item, compatible: true, reason: t('connectors.tab.compatible') }
    return { connector: item, compatible: false, reason: t('connectors.tab.incompatibleReason') }
  })
}

function compatibilityLabel(value: boolean): string {
  return value ? t('connectors.tab.compatible') : t('connectors.tab.incompatible')
}

function compatibilitySeverity(value: boolean): 'success' | 'secondary' {
  return value ? 'success' : 'secondary'
}

function capabilityLabel(capability: string): string {
  const messageId = capabilityMessageIds[capability as keyof typeof capabilityMessageIds]
  return messageId ? t(messageId) : capability
}

function capabilityList(capabilities: string[]): string {
  return capabilities.map(capabilityLabel).join(', ')
}

function appCount(count: number): string {
  const category = new Intl.PluralRules(locale.value).select(count)
  const id = category === 'one'
    ? 'connectors.tab.appCount.one'
    : category === 'few'
      ? 'connectors.tab.appCount.few'
      : category === 'many'
        ? 'connectors.tab.appCount.many'
        : 'connectors.tab.appCount.other'
  return t(id, { formattedCount: formatNumber(count) })
}

function openBinding(need: NeedInfo): void {
  selected.value = need
  if (need.connectorMultiple) {
    selectedGroupId.value = need.boundConnectorGroupId
    creatingGroup.value = false
    groupBindingOpen.value = true
  } else {
    bindingOpen.value = true
  }
}

function openInstall(need: NeedInfo): void {
  selected.value = need
  installOpen.value = true
}

function openUpdate(need: NeedInfo, connector: ConnectorInfo): void {
  selected.value = need
  updateConnector.value = connector
  updateOpen.value = true
}

function openGroupCreation(): void {
  groupName.value = ''
  groupMemberIds.value = []
  creatingGroup.value = true
}

async function createGroup(): Promise<void> {
  if (!selected.value || !groupName.value.trim() || !groupMemberIds.value.length) return
  groupCreating.value = true
  try {
    selectedGroupId.value = await store.createGroup(
      props.agentId,
      selected.value.slug,
      groupName.value.trim(),
      selected.value.description,
      groupMemberIds.value,
      t,
    )
    creatingGroup.value = false
    toast.add({ severity: 'success', summary: t('connectors.tab.groupCreated'), life: 3000 })
  } catch (cause: unknown) {
    const error = cause as { message?: unknown; response?: { data?: { error?: unknown } } }
    const message = typeof error?.response?.data?.error === 'string'
      ? error.response.data.error
      : typeof error?.message === 'string' ? error.message : t('connectors.tab.groupCreationFailed')
    toast.add({ severity: 'error', summary: message, life: 5000 })
  } finally {
    groupCreating.value = false
  }
}

async function load(): Promise<void> {
  try {
    await store.fetchAgent(props.agentId, canAdmin.value, t)
  } catch {
    emit('populated', 1)
  }
}

async function changed(): Promise<void> {
  await load()
  emit('mutated')
}

async function saveGroupBinding(): Promise<void> {
  if (!selected.value || !selectedGroupId.value) return
  groupSaving.value = true
  try {
    await store.bindGroup(props.agentId, selected.value.slug, selectedGroupId.value, t)
    groupBindingOpen.value = false
    emit('mutated')
    toast.add({ severity: 'success', summary: t('connectors.tab.groupBound'), life: 3000 })
  } catch (cause: unknown) {
    const error = cause as { message?: unknown; response?: { data?: { error?: unknown } } }
    const message = typeof error?.response?.data?.error === 'string'
      ? error.response.data.error
      : typeof error?.message === 'string' ? error.message : t('connectors.tab.groupBindingFailed')
    toast.add({ severity: 'error', summary: message, life: 5000 })
  } finally {
    groupSaving.value = false
  }
}

function unbind(need: NeedInfo): void {
  const current = connector(need)
  confirm.require({
    header: t('connectors.tab.disconnectConfirmTitle'),
    message: t('connectors.tab.disconnectConfirmMessage', {
      name: current ? connectorDisplayName(current) : t('connectors.tab.thisInstallation'),
    }),
    acceptLabel: t('connectors.tab.disconnect'),
    rejectLabel: t('connectors.tab.cancel'),
    accept: async () => {
      try {
        await store.unbind(props.agentId, need.slug, t)
        emit('mutated')
        toast.add({ severity: 'success', summary: t('connectors.tab.disconnected'), life: 3000 })
      } catch (cause: unknown) {
        const message = typeof cause === 'object' && cause !== null && 'message' in cause && typeof cause.message === 'string'
          ? cause.message
          : t('connectors.tab.disconnectFailed')
        toast.add({ severity: 'error', summary: message, life: 5000 })
      }
    },
  })
}

onMounted(load)
</script>

<template>
  <Message v-if="store.error" severity="error" :closable="false">
    <div class="load-error"><span>{{ store.error }}</span><Button :label="t('connectors.common.retry')" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
  </Message>
  <div v-else-if="store.loading" class="skeletons"><Skeleton v-for="i in 2" :key="i" height="10rem" /></div>
  <div v-else-if="store.needs.length" class="connector-needs">
    <article v-for="item in store.needs" :key="item.slug" class="connector-need">
      <header class="need-header">
        <div>
          <div class="need-title">{{ connector(item) ? connectorDisplayName(connector(item)!) : item.slug }}</div>
          <div class="muted">{{ t('connectors.tab.appHandle') }} <code>{{ item.slug }}</code></div>
          <p>{{ item.description }}</p>
        </div>
        <div class="header-tags">
          <Tag :value="item.connectorMultiple ? t('connectors.tab.targetGroup') : t('connectors.tab.singleInstallation')" severity="info" />
          <Tag :value="item.bound ? t('connectors.tab.bound') : t('connectors.tab.unbound')" :severity="item.bound ? 'success' : 'warn'" />
          <Tag v-if="item.boundConnectorGroupName" :value="item.boundConnectorGroupName" severity="success" />
          <Tag
            v-if="connector(item)"
            :value="connectorReadiness(connector(item)!.readiness, t).label"
            :severity="connectorReadiness(connector(item)!.readiness, t).severity"
          />
        </div>
      </header>

      <Message v-if="item.boundConnectorId && !connector(item)" severity="warn" :closable="false">
        {{ t('connectors.tab.boundNotVisible') }}
      </Message>
      <Message v-else-if="connector(item)?.readinessMessage" :severity="connectorReadiness(connector(item)!.readiness, t).severity" :closable="false">
        {{ connector(item)?.readinessMessage }}
      </Message>

      <section>
        <div class="contract-heading">
          <h3>{{ t('connectors.tab.requiredContract') }}</h3>
          <code>{{ item.connectorContractId }}</code>
        </div>
        <div class="requirements-grid">
          <div>
            <h4>{{ t('connectors.common.commands') }}</h4>
            <div v-if="item.connectorRequiredCommands.length" class="requirement-list">
              <div v-for="command in item.connectorRequiredCommands" :key="command.name" class="requirement-row">
                <span><code>{{ command.name }}@{{ command.revision }}</code><Tag :value="command.mode" severity="secondary" /></span>
                <small>{{ command.description || t('connectors.common.noDescription') }}</small>
                <small><strong>{{ t('connectors.tab.args') }}</strong> <code class="schema-signature">{{ connectorSchemaSignature(command.inputSchemaJson) }}</code></small>
                <small><strong>{{ t('connectors.tab.returns') }}</strong> <code class="schema-signature">{{ connectorSchemaSignature(command.outputSchemaJson) }}</code></small>
              </div>
            </div>
            <p v-else class="muted">{{ t('connectors.tab.noCommandsRequired') }}</p>
          </div>
          <div>
            <h4>{{ t('connectors.common.localDirectories') }}</h4>
            <div v-if="item.connectorRequiredDirectories.length" class="requirement-list">
              <div v-for="directory in item.connectorRequiredDirectories" :key="directory.name" class="requirement-row">
                <span><code>{{ directory.name }}@{{ directory.revision }}</code><Tag :value="directoryAccess(directory, t)" severity="warn" /></span>
              </div>
            </div>
            <p v-else class="muted">{{ t('connectors.tab.noDirectoriesRequired') }}</p>
          </div>
        </div>
        <div v-if="item.connectorMultiple" class="group-summary">
          <span class="muted">{{ t('connectors.tab.targetGroupBinding') }}</span>
          <strong v-if="item.boundConnectorGroupName">{{ item.boundConnectorGroupName }}</strong>
          <span v-else class="muted">{{ t('connectors.tab.noTargetGroupSelected') }}</span>
          <small v-if="item.boundConnectorGroupId"><code>{{ item.boundConnectorGroupId }}</code></small>
        </div>
      </section>

      <section>
        <div class="resource-heading">
          <h3>{{ t('connectors.tab.existingResources') }}</h3>
          <span class="muted">{{ t('connectors.tab.compatibleCount', { formattedCount: formatNumber(compatibleCandidates(item).length) }) }}</span>
        </div>
        <div v-if="existingConnectorRows(item).length" class="resource-list">
          <div v-for="row in existingConnectorRows(item)" :key="row.connector.id" class="resource-row">
            <span class="resource-name">
              <strong>{{ connectorDisplayName(row.connector) }}</strong>
              <small><code>{{ row.connector.contractId || t('connectors.tab.noPublishedContract') }}</code> | {{ appCount(row.connector.agentCount) }}</small>
              <small v-if="row.compatible !== true" class="incompatible-reason">{{ row.reason }}</small>
            </span>
            <span class="resource-state">
              <Tag :value="compatibilityLabel(row.compatible)" :severity="compatibilitySeverity(row.compatible)" />
              <Tag :value="connectorReadiness(row.connector.readiness, t).label" :severity="connectorReadiness(row.connector.readiness, t).severity" />
              <Button v-if="canAdmin && row.connector.hostId && row.connector.contractId === item.connectorContractId" :label="t('connectors.tab.update')" icon="pi pi-refresh" size="small" text @click="openUpdate(item, row.connector)" />
            </span>
          </div>
        </div>
        <p v-else class="muted">{{ t('connectors.tab.noInstallationsVisible') }}</p>
      </section>

      <footer class="need-actions">
        <Button v-if="canAdmin" :label="t('connectors.tab.installOnHost')" icon="pi pi-desktop" outlined @click="openInstall(item)" />
        <Button v-if="canAdmin && !item.bound" :label="item.connectorMultiple ? t('connectors.tab.bindTargetGroup') : t('connectors.tab.bindExisting')" icon="pi pi-link" @click="openBinding(item)" />
        <template v-else-if="canAdmin && item.bound">
          <Button :label="item.connectorMultiple ? t('connectors.tab.switchTargetGroup') : t('connectors.tab.switchResource')" icon="pi pi-sync" outlined @click="openBinding(item)" />
          <Button :label="t('connectors.tab.disconnect')" icon="pi pi-unlink" severity="danger" text @click="unbind(item)" />
        </template>
        <span v-else class="muted">{{ t('connectors.tab.viewOnly') }}</span>
        <span v-if="connector(item)" class="access-line">{{ t('connectors.tab.yourAccess', { access: capabilityList(connector(item)!.capabilities) || t('connectors.common.none') }) }}</span>
      </footer>
    </article>
  </div>
  <div v-else class="empty">{{ t('connectors.tab.noRequirements') }}</div>

  <ResourceBindingDialog
    v-model:visible="bindingOpen"
    :agent-id="agentId"
    :need="selected"
    auth-mode="none"
    @changed="changed"
  />
  <InstallConnectorDialog
    v-model:visible="installOpen"
    :agent-id="agentId"
    :connector-need="selected"
    @installed="changed"
  />
  <UpdateConnectorDialog
    v-model:visible="updateOpen"
    :agent-id="agentId"
    :connector-need="selected"
    :connector="updateConnector"
    :agent-admin="canAdmin"
    @updated="changed"
  />
  <Dialog v-model:visible="groupBindingOpen" :header="t('connectors.tab.bindGroupTitle')" modal :style="{ width: 'min(32rem, calc(100vw - 2rem))' }">
    <div v-if="selected && !creatingGroup" class="group-dialog">
      <p class="muted">{{ t('connectors.tab.chooseGroup', { contractId: selected.connectorContractId }) }}</p>
      <div class="field">
        <label for="connector-target-group">{{ t('connectors.tab.targetGroup') }}</label>
        <Select
          id="connector-target-group"
          v-model="selectedGroupId"
          :options="compatibleGroups(selected)"
          option-label="optionLabel"
          option-value="id"
          option-disabled="disabled"
          :placeholder="t('connectors.tab.selectTargetGroup')"
          fluid
        />
      </div>
      <Message v-if="!compatibleGroups(selected).length" severity="warn" :closable="false">
        {{ t('connectors.tab.noMatchingGroups') }}
      </Message>
      <Message v-else-if="!compatibleGroups(selected).some((group) => !group.disabled)" severity="warn" :closable="false">
        {{ t('connectors.tab.noUsableGroups') }}
      </Message>
      <div v-if="compatibleGroups(selected).some((group) => group.disabled)" class="group-reasons">
        <small v-for="group in compatibleGroups(selected).filter((item) => item.disabled)" :key="group.id" class="muted"><strong>{{ group.name }}:</strong> {{ group.reason }}</small>
      </div>
      <Button :label="t('connectors.tab.createTargetGroup')" icon="pi pi-plus" outlined :disabled="!availableGroupMembers.length" @click="openGroupCreation" />
      <small v-if="!availableGroupMembers.length" class="muted">{{ t('connectors.tab.noAvailableGroupMembers') }}</small>
    </div>
    <div v-else-if="selected" class="group-dialog">
      <Button :label="t('connectors.tab.backToGroups')" icon="pi pi-arrow-left" text class="back-button" :disabled="groupCreating" @click="creatingGroup = false" />
      <div class="field">
        <label for="connector-target-group-name">{{ t('connectors.tab.groupName') }}</label>
        <InputText id="connector-target-group-name" v-model="groupName" maxlength="256" :placeholder="t('connectors.tab.groupNamePlaceholder')" />
      </div>
      <div class="field">
        <label for="connector-target-group-members">{{ t('connectors.tab.initialInstallations') }}</label>
        <MultiSelect id="connector-target-group-members" v-model="groupMemberIds" :options="availableGroupMembers" option-label="label" option-value="value" display="chip" fluid />
        <small class="muted">{{ t('connectors.tab.initialInstallationsHelp') }}</small>
      </div>
    </div>
    <template #footer>
      <Button :label="t('connectors.tab.cancel')" text severity="secondary" :disabled="groupSaving || groupCreating" @click="groupBindingOpen = false" />
      <Button v-if="creatingGroup" :label="t('connectors.tab.createGroup')" :loading="groupCreating" :disabled="!groupName.trim() || !groupMemberIds.length" @click="createGroup" />
      <Button v-else :label="t('connectors.tab.bindTargetGroup')" :loading="groupSaving" :disabled="!selectedGroupUsable" @click="saveGroupBinding" />
    </template>
  </Dialog>
</template>

<style scoped>
.connector-needs, .skeletons, .resource-list, .requirement-list, .group-dialog, .group-reasons, .field { display: flex; flex-direction: column; }
.connector-needs { gap: 1rem; }
.connector-need { border: 1px solid var(--p-content-border-color); border-radius: 0.75rem; overflow: hidden; }
.connector-need > header, .connector-need > section, .connector-need > footer { padding: 1rem; }
.connector-need > section, .connector-need > footer { border-top: 1px solid var(--p-content-border-color); }
.need-header, .contract-heading, .resource-heading, .need-actions, .resource-row, .resource-state, .requirement-row span { display: flex; align-items: center; gap: 0.65rem; }
.need-header, .contract-heading, .resource-heading, .resource-row { justify-content: space-between; }
.need-header { align-items: flex-start; }
.need-header p { margin: 0.45rem 0 0; }
.need-title { font-size: 1.05rem; font-weight: 650; }
.header-tags, .resource-state { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.35rem; }
.connector-need h3, .connector-need h4 { margin: 0; }
.connector-need h3 { font-size: 0.95rem; }
.connector-need h4 { margin-bottom: 0.5rem; color: var(--p-text-muted-color); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.requirements-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin-top: 0.8rem; }
.requirement-list { gap: 0.45rem; }
.requirement-row { padding: 0.6rem; border: 1px solid var(--p-content-border-color); border-radius: 0.5rem; }
.requirement-row small { display: block; margin-top: 0.3rem; color: var(--p-text-muted-color); }
.schema-signature { white-space: normal; overflow-wrap: anywhere; }
.group-summary { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.9rem; padding-top: 0.75rem; border-top: 1px dashed var(--p-content-border-color); }
.muted, .resource-name small, .access-line { color: var(--p-text-muted-color); font-size: 0.8rem; }
.resource-list { gap: 0.45rem; margin-top: 0.65rem; }
.resource-row { padding: 0.65rem; border-radius: 0.5rem; background: var(--p-content-hover-background); }
.resource-name { display: flex; flex-direction: column; min-width: 0; }
.incompatible-reason { color: var(--p-orange-500) !important; }
.need-actions { flex-wrap: wrap; }
.access-line { margin-left: auto; }
.empty { padding: 2rem; text-align: center; color: var(--p-text-muted-color); }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.skeletons { gap: 0.75rem; }
.group-dialog { gap: 1rem; }
.group-reasons { gap: 0.3rem; }
.field { gap: 0.35rem; }
.field label { font-size: 0.85rem; font-weight: 600; }
.back-button { align-self: flex-start; padding-left: 0; }
@media (max-width: 44rem) {
  .need-header, .resource-row { align-items: stretch; flex-direction: column; }
  .header-tags, .resource-state { justify-content: flex-start; }
  .requirements-grid { grid-template-columns: 1fr; }
  .need-actions { align-items: stretch; flex-direction: column; }
  .need-actions :deep(.p-button) { width: 100%; }
  .access-line { margin-left: 0; }
}
</style>
