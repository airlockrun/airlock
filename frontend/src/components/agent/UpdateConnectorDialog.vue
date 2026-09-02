<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { NeedInfo } from '@/gen/airlock/v1/api_pb'
import type { ConnectorInfo, HostInfo } from '@/gen/airlock/v1/types_pb'
import { ConnectorArtifactValidationError, listConnectorArtifacts } from '@/api/connectors'
import { listHosts, requestUpdate } from '@/api/hosts'
import { useNow } from '@/composables/useNow'
import { useAirlockI18n } from '@/i18n'
import { hasCapability } from '@/utils/resources'
import {
  connectorSettingDefaults,
  connectorSettingError,
  isHostStale,
  serializeConnectorSettings,
  type ConnectorArtifactCatalog,
  type ConnectorArtifactTarget,
  type ConnectorArtifactVersion,
  type ConnectorSettingDescriptor,
  type ConnectorSettingValue,
} from '@/utils/connectors'

const props = defineProps<{
  agentId: string
  connectorNeed: NeedInfo | null
  connector: ConnectorInfo | null
  agentAdmin: boolean
}>()
const emit = defineEmits<{ updated: [] }>()
const visible = defineModel<boolean>('visible', { default: false })
const toast = useToast()
const now = useNow()
const { t } = useAirlockI18n()

const hosts = ref<HostInfo[]>([])
const catalog = ref<ConnectorArtifactCatalog | null>(null)
const selectedArtifactSetId = ref('')
const replaceSettings = ref(false)
const settingValues = ref<Record<string, ConnectorSettingValue>>({})
const loading = ref(false)
const saving = ref(false)
const error = ref('')
let loadSequence = 0

const host = computed(() => hosts.value.find((item) => item.id === props.connector?.hostId))
const compatibleVersions = computed(() => {
  const connector = props.connector
  const need = props.connectorNeed
  const target = host.value ? `${host.value.platform}-${host.value.architecture}` : ''
  if (!connector || !need || !target || connector.contractId !== need.connectorContractId) return []
  const versions = catalog.value?.versions ?? []
  const sameInterface = (version: ConnectorArtifactVersion) => version.interface.kind === connector.kind
    && version.interface.contractId === need.connectorContractId
  return versions.filter((version) =>
    sameInterface(version)
    && version.targets.some((item) => item.target === target),
  )
})
const versionOptions = computed(() => compatibleVersions.value.map((version) => ({
  value: version.artifactSetId,
  label: `${version.version} · ${version.sourceCommit || version.buildId}`,
})))
const selectedVersion = computed(() => compatibleVersions.value.find((version) => version.artifactSetId === selectedArtifactSetId.value))
const selectedTarget = computed<ConnectorArtifactTarget | undefined>(() => {
  const selectedHost = host.value
  return selectedHost && selectedVersion.value?.targets.find((item) => item.target === `${selectedHost.platform}-${selectedHost.architecture}`)
})
const selectedSettings = computed(() => selectedVersion.value?.settings ?? [])
const invalidSettings = computed(() => replaceSettings.value
  ? selectedSettings.value.filter((setting) => settingError(setting))
  : [])
const blocker = computed(() => {
  if (!props.agentAdmin) return t('connectors.update.agentAdminRequired')
  if (!host.value) return t('connectors.update.hostUnavailable')
  if (!hasCapability(host.value.capabilities, 'manage')) return t('connectors.update.manageRequired')
  if (host.value.accessMode !== 'full' && host.value.accessMode !== 'update_only') return t('connectors.update.disabled')
  if (isHostStale(host.value.lastSeenAt, now.value)) return t('connectors.install.host.stale')
  if (!compatibleVersions.value.length) return t('connectors.update.noArtifact', { platform: `${host.value.platform}-${host.value.architecture}` })
  if (selectedVersion.value?.settings.some((setting) => !setting.jsonName)) return t('connectors.install.host.rebuildForSettings')
  return ''
})
const canUpdate = computed(() => !!selectedTarget.value && !blocker.value && !invalidSettings.value.length)

function errorMessage(cause: unknown, fallback: string): string {
  if (cause instanceof ConnectorArtifactValidationError) return t(cause.messageId, cause.values)
  if (typeof cause === 'object' && cause !== null) {
    const typed = cause as { response?: { data?: { error?: unknown } } }
    if (typeof typed.response?.data?.error === 'string') return typed.response.data.error
  }
  return fallback
}

async function load(): Promise<void> {
  if (!props.connectorNeed || !props.connector) return
  if (!props.agentAdmin) {
    hosts.value = []
    catalog.value = null
    selectedArtifactSetId.value = ''
    replaceSettings.value = false
    settingValues.value = {}
    error.value = ''
    return
  }
  const sequence = ++loadSequence
  loading.value = true
  error.value = ''
  selectedArtifactSetId.value = ''
  replaceSettings.value = false
  settingValues.value = {}
  try {
    const [loadedHosts, loadedCatalog] = await Promise.all([
      listHosts(),
      listConnectorArtifacts(props.agentId, props.connectorNeed.slug),
    ])
    if (sequence !== loadSequence) return
    hosts.value = loadedHosts
    catalog.value = loadedCatalog
    const versions = compatibleVersions.value
    const platform = `${host.value?.platform}-${host.value?.architecture}`
    selectedArtifactSetId.value = (versions.find((version) =>
      version.targets.some((target) => target.target === platform && target.sha256 !== props.connector?.artifactDigest),
    ) ?? versions[0])?.artifactSetId ?? ''
  } catch (cause: unknown) {
    if (sequence === loadSequence) error.value = errorMessage(cause, t('connectors.update.loadFailed'))
  } finally {
    if (sequence === loadSequence) loading.value = false
  }
}

watch(visible, (open) => {
  if (open) void load()
  else loadSequence++
})

watch(() => selectedVersion.value?.artifactSetId ?? '', () => {
  settingValues.value = connectorSettingDefaults(selectedSettings.value)
})

function settingLabel(setting: ConnectorSettingDescriptor): string {
  if (/\s/.test(setting.name)) return setting.name
  const words = setting.name.replaceAll('-', ' ').replaceAll('_', ' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}

function settingPlaceholder(setting: ConnectorSettingDescriptor): string {
  if (setting.kind === 'url') return 'https://example.com'
  if (setting.kind === 'file') return '/path/to/file'
  if (setting.kind === 'directory') return '/path/to/directory'
  if (setting.kind === 'duration') return '5s'
  return ''
}

function settingError(setting: ConnectorSettingDescriptor): string {
  return connectorSettingError(setting, settingValues.value[setting.jsonName], t)
}

function accessModeLabel(mode: string): string {
  if (mode === 'full') return t('connectors.host.access.full')
  if (mode === 'update_only') return t('connectors.host.access.updateOnly')
  if (mode === 'none') return t('connectors.host.access.none')
  return mode
}

async function update(): Promise<void> {
  const connector = props.connector
  const target = selectedTarget.value
  if (!connector || !target || !canUpdate.value) return
  saving.value = true
  try {
    const settingsJson = replaceSettings.value
      ? serializeConnectorSettings(selectedSettings.value, settingValues.value)
      : ''
    await requestUpdate(connector.id, target.artifactFileId, settingsJson)
    visible.value = false
    toast.add({
      severity: 'success',
      summary: t('connectors.update.updating', { connector: connector.displayName || connector.name || connector.slug }),
      detail: t('connectors.install.host.workQueued'),
      life: 4000,
    })
    emit('updated')
  } catch (cause: unknown) {
    toast.add({ severity: 'error', summary: errorMessage(cause, t('connectors.update.failed')), life: 5000 })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <Dialog v-model:visible="visible" :header="t('connectors.update.title')" modal :style="{ width: 'min(46rem, calc(100vw - 2rem))' }">
    <div class="update-body">
      <div>
        <h3>{{ connector?.displayName || connector?.name || connector?.slug }}</h3>
        <p class="muted">{{ t('connectors.update.description') }}</p>
      </div>
      <Skeleton v-if="loading" height="10rem" />
      <Message v-else-if="error" severity="error" :closable="false">
        <div class="load-error"><span>{{ error }}</span><Button :label="t('connectors.common.retry')" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
      </Message>
      <template v-else>
        <Message v-if="blocker" severity="warn" :closable="false">{{ blocker }}</Message>
        <div v-if="host" class="host-summary">
          <strong>{{ host.name }}</strong>
          <span>{{ host.platform }} / {{ host.architecture }}</span>
          <Tag :value="accessModeLabel(host.accessMode)" :severity="host.accessMode === 'full' ? 'success' : 'warn'" />
        </div>
        <div v-if="versionOptions.length" class="field">
          <label for="connector-update-version">{{ t('connectors.update.retainedVersion') }}</label>
          <Select id="connector-update-version" v-model="selectedArtifactSetId" :options="versionOptions" option-label="label" option-value="value" fluid />
          <small v-if="selectedTarget" class="muted">{{ t('connectors.update.artifactDigest', { filename: selectedTarget.filename, sha256: selectedTarget.sha256 }) }}</small>
        </div>

        <template v-if="selectedVersion && !selectedVersion.settings.some((setting) => !setting.jsonName)">
          <div class="settings-toggle">
            <Checkbox v-model="replaceSettings" input-id="connector-update-settings" binary />
            <label for="connector-update-settings">{{ t('connectors.update.replaceSettings') }}</label>
          </div>
          <Message severity="info" :closable="false">
            {{ t('connectors.update.retainSettings') }}
          </Message>
          <div v-if="replaceSettings && selectedSettings.length" class="settings-form">
            <div v-for="(setting, index) in selectedSettings" :key="setting.jsonName" class="field">
              <div class="setting-label">
                <label :for="`connector-update-setting-${index}`">{{ settingLabel(setting) }}</label>
                <Tag v-if="setting.required" :value="t('connectors.common.required')" severity="warn" />
              </div>
              <Password v-if="setting.kind === 'secret'" :id="`connector-update-setting-${index}`" v-model="settingValues[setting.jsonName]" :feedback="false" toggle-mask autocomplete="new-password" fluid />
              <Checkbox v-else-if="setting.kind === 'bool'" v-model="settingValues[setting.jsonName]" :input-id="`connector-update-setting-${index}`" binary />
              <InputText v-else-if="setting.kind === 'integer'" :id="`connector-update-setting-${index}`" v-model="settingValues[setting.jsonName]" inputmode="numeric" pattern="-?[0-9]+" fluid />
              <Select v-else-if="setting.kind === 'enum'" :id="`connector-update-setting-${index}`" v-model="settingValues[setting.jsonName]" :options="setting.enumValues" :placeholder="t('connectors.install.host.selectValue')" fluid />
              <InputText v-else :id="`connector-update-setting-${index}`" v-model="settingValues[setting.jsonName]" :type="setting.kind === 'url' ? 'url' : 'text'" :placeholder="settingPlaceholder(setting)" fluid />
              <small v-if="setting.description" class="muted">{{ setting.description }}</small>
              <small v-if="settingError(setting)" class="field-error">{{ settingError(setting) }}</small>
            </div>
          </div>
        </template>
      </template>
    </div>
    <template #footer>
      <Button :label="t('connectors.tab.cancel')" text severity="secondary" :disabled="saving" @click="visible = false" />
      <Button :label="t('connectors.update.queue')" icon="pi pi-refresh" :loading="saving" :disabled="!canUpdate" @click="update" />
    </template>
  </Dialog>
</template>

<style scoped>
.update-body, .field, .settings-form { display: flex; flex-direction: column; }
.update-body { gap: 1rem; }
.update-body h3 { margin: 0 0 0.3rem; }
.update-body p { margin: 0; }
.field, .settings-form { gap: 0.45rem; }
.field > label, .setting-label label { font-size: 0.85rem; font-weight: 600; }
.settings-form { gap: 0.8rem; padding-top: 0.4rem; border-top: 1px solid var(--p-content-border-color); }
.settings-toggle, .setting-label, .host-summary, .load-error { display: flex; align-items: center; gap: 0.65rem; }
.setting-label, .load-error { justify-content: space-between; }
.host-summary { flex-wrap: wrap; padding: 0.75rem; border-radius: 0.5rem; background: var(--p-content-hover-background); }
.host-summary span { color: var(--p-text-muted-color); }
.host-summary :deep(.p-tag) { margin-left: auto; }
.muted { color: var(--p-text-muted-color); }
.field-error { color: var(--p-red-500); }
@media (max-width: 40rem) {
  .load-error { align-items: stretch; flex-direction: column; }
  .host-summary :deep(.p-tag) { margin-left: 0; }
}
</style>
