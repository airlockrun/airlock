<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import type { NeedInfo } from '@/gen/airlock/v1/api_pb'
import type { HostInfo } from '@/gen/airlock/v1/types_pb'
import { ConnectorArtifactValidationError, listConnectorArtifacts } from '@/api/connectors'
import { listHosts, requestInstall } from '@/api/hosts'
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
}>()
const emit = defineEmits<{ installed: [] }>()
const visible = defineModel<boolean>('visible', { default: false })
const toast = useToast()
const now = useNow()
const { locale, t, formatNumber } = useAirlockI18n()

interface HostChoice {
  host: HostInfo
  version?: ConnectorArtifactVersion
  target?: ConnectorArtifactTarget
  reason: string
}

const hosts = ref<HostInfo[]>([])
const catalog = ref<ConnectorArtifactCatalog | null>(null)
const loading = ref(false)
const error = ref('')
const selectedHostId = ref('')
const displayName = ref('')
const settingValues = ref<Record<string, ConnectorSettingValue>>({})
const saving = ref(false)
let loadSequence = 0

const choices = computed<HostChoice[]>(() => hosts.value.map((host) => {
  const platform = `${host.platform}-${host.architecture}`
  const version = catalog.value?.versions.find((item) => item.compatible && item.targets.some((target) => target.target === platform))
  const target = version?.targets.find((item) => item.target === platform)
  let reason = ''
  if (!hasCapability(host.capabilities, 'manage')) reason = t('connectors.install.host.manageRequired')
  else if (host.accessMode !== 'full') reason = host.accessMode === 'update_only'
    ? t('connectors.install.host.updatesOnly')
    : t('connectors.install.host.managementDisabled')
  else if (isHostStale(host.lastSeenAt, now.value)) reason = t('connectors.install.host.stale')
  else if (!target) reason = t('connectors.install.host.noArtifact', { platform })
  else if (version?.settings.some((setting) => !setting.jsonName)) reason = t('connectors.install.host.rebuildForSettings')
  return { host, version, target, reason }
}))
const selectedChoice = computed(() => choices.value.find((choice) => choice.host.id === selectedHostId.value))
const selectedSettings = computed(() => selectedChoice.value?.version?.settings ?? [])
const invalidSettings = computed(() => selectedSettings.value.filter((setting) => settingError(setting)))
const canInstall = computed(() => !!selectedChoice.value
  && !selectedChoice.value.reason
  && !!displayName.value.trim()
  && !invalidSettings.value.length)

function settingError(setting: ConnectorSettingDescriptor): string {
  return connectorSettingError(setting, settingValues.value[setting.jsonName], t)
}

function errorMessage(cause: unknown, fallback: string): string {
  if (cause instanceof ConnectorArtifactValidationError) return t(cause.messageId, cause.values)
  if (typeof cause === 'object' && cause !== null) {
    const typed = cause as { message?: unknown; response?: { data?: { error?: unknown } } }
    if (typeof typed.response?.data?.error === 'string') return typed.response.data.error
    if (typeof typed.message === 'string') return typed.message
  }
  return fallback
}

async function load(): Promise<void> {
  if (!props.connectorNeed) return
  const sequence = ++loadSequence
  loading.value = true
  error.value = ''
  selectedHostId.value = ''
  displayName.value = ''
  settingValues.value = {}
  try {
    const [loadedHosts, loadedCatalog] = await Promise.all([
      listHosts(),
      listConnectorArtifacts(props.agentId, props.connectorNeed.slug),
    ])
    if (sequence !== loadSequence) return
    hosts.value = loadedHosts
    catalog.value = loadedCatalog
    displayName.value = loadedCatalog.name || props.connectorNeed.slug
  } catch (cause: unknown) {
    if (sequence === loadSequence) error.value = errorMessage(cause, t('connectors.install.host.loadFailed'))
  } finally {
    if (sequence === loadSequence) loading.value = false
  }
}

watch(visible, (open) => {
  if (open) void load()
  else loadSequence++
})

watch(() => selectedChoice.value?.version?.artifactSetId ?? '', () => {
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

function connectorCount(count: number): string {
  const category = new Intl.PluralRules(locale.value).select(count)
  const id = category === 'one'
    ? 'connectors.install.host.connectorCount.one'
    : category === 'few'
      ? 'connectors.install.host.connectorCount.few'
      : category === 'many'
        ? 'connectors.install.host.connectorCount.many'
        : 'connectors.install.host.connectorCount.other'
  return t(id, { formattedCount: formatNumber(count) })
}

function serializedSettings(): string {
  return serializeConnectorSettings(selectedSettings.value, settingValues.value)
}

async function install(): Promise<void> {
  const choice = selectedChoice.value
  const need = props.connectorNeed
  if (!choice?.target || choice.reason || !need || !canInstall.value) return
  saving.value = true
  try {
    await requestInstall(choice.host.id, {
      agentId: props.agentId,
      needSlug: need.slug,
      artifactFileId: choice.target.artifactFileId,
      displayName: displayName.value.trim(),
      settingsJson: serializedSettings(),
    })
    visible.value = false
    toast.add({
      severity: 'success',
      summary: t('connectors.install.host.installingOn', { host: choice.host.name }),
      detail: t('connectors.install.host.workQueued'),
      life: 4000,
    })
    emit('installed')
  } catch (cause: unknown) {
    toast.add({ severity: 'error', summary: errorMessage(cause, t('connectors.install.host.failed')), life: 5000 })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <Dialog v-model:visible="visible" :header="t('connectors.install.host.title')" modal :style="{ width: 'min(46rem, calc(100vw - 2rem))' }">
    <div class="install-body">
      <div>
        <h3>{{ catalog?.name || connectorNeed?.slug }}</h3>
        <p class="muted">{{ t('connectors.install.host.description') }}</p>
      </div>

      <div v-if="loading" class="skeletons"><Skeleton v-for="i in 3" :key="i" height="5rem" /></div>
      <Message v-else-if="error" severity="error" :closable="false">
        <div class="load-error"><span>{{ error }}</span><Button :label="t('connectors.common.retry')" icon="pi pi-refresh" size="small" outlined @click="load" /></div>
      </Message>
      <Message v-else-if="!choices.length" severity="secondary" :closable="false">
        {{ t('connectors.install.host.noneAvailable') }}
      </Message>
      <div v-else class="host-list" role="radiogroup" :aria-label="t('connectors.install.host.selectionLabel')">
        <button
          v-for="choice in choices"
          :key="choice.host.id"
          type="button"
          class="host-choice"
          :class="{ selected: selectedHostId === choice.host.id }"
          :disabled="!!choice.reason"
          :aria-checked="selectedHostId === choice.host.id"
          role="radio"
          @click="selectedHostId = choice.host.id"
        >
          <span class="host-icon"><i class="pi pi-server" /></span>
          <span class="host-summary">
            <strong>{{ choice.host.name }}</strong>
            <small>{{ choice.host.platform }} / {{ choice.host.architecture }} · {{ connectorCount(choice.host.connectorCount) }}</small>
            <small v-if="choice.reason" class="unavailable">{{ choice.reason }}</small>
            <small v-else>{{ choice.version?.version }} · {{ choice.target?.filename }}</small>
          </span>
          <i :class="selectedHostId === choice.host.id ? 'pi pi-check-circle' : 'pi pi-circle'" />
        </button>
      </div>

      <template v-if="selectedChoice">
        <div class="field">
          <label for="connector-install-name">{{ t('connectors.install.host.installationName') }}</label>
          <InputText id="connector-install-name" v-model="displayName" maxlength="256" fluid />
        </div>
        <div v-if="selectedSettings.length" class="settings-form">
          <h4>{{ t('connectors.install.host.settings') }}</h4>
          <div v-for="(setting, index) in selectedSettings" :key="setting.jsonName" class="field">
            <div class="setting-label">
              <label :for="`connector-setting-${index}`">{{ settingLabel(setting) }}</label>
              <Tag v-if="setting.required" :value="t('connectors.common.required')" severity="warn" />
            </div>
            <Password
              v-if="setting.kind === 'secret'"
              :id="`connector-setting-${index}`"
              v-model="settingValues[setting.jsonName]"
              :feedback="false"
              toggle-mask
              autocomplete="new-password"
              fluid
            />
            <Checkbox
              v-else-if="setting.kind === 'bool'"
              v-model="settingValues[setting.jsonName]"
              :input-id="`connector-setting-${index}`"
              binary
            />
            <InputText
              v-else-if="setting.kind === 'integer'"
              :id="`connector-setting-${index}`"
              v-model="settingValues[setting.jsonName]"
              inputmode="numeric"
              pattern="-?[0-9]+"
              fluid
            />
            <Select
              v-else-if="setting.kind === 'enum'"
              :id="`connector-setting-${index}`"
              v-model="settingValues[setting.jsonName]"
              :options="setting.enumValues"
              :placeholder="t('connectors.install.host.selectValue')"
              fluid
            />
            <InputText
              v-else
              :id="`connector-setting-${index}`"
              v-model="settingValues[setting.jsonName]"
              :type="setting.kind === 'url' ? 'url' : 'text'"
              :placeholder="settingPlaceholder(setting)"
              fluid
            />
            <small v-if="setting.description">{{ setting.description }}</small>
            <small v-if="settingError(setting)" class="field-error">{{ settingError(setting) }}</small>
          </div>
        </div>
      </template>
    </div>
    <template #footer>
      <Button :label="t('connectors.tab.cancel')" text severity="secondary" :disabled="saving" @click="visible = false" />
      <Button :label="t('connectors.install.host.installConnector')" icon="pi pi-download" :loading="saving" :disabled="!canInstall" @click="install" />
    </template>
  </Dialog>
</template>

<style scoped>
.install-body, .skeletons, .host-list, .field, .settings-form { display: flex; flex-direction: column; }
.install-body { gap: 1rem; }
.install-body h3 { margin: 0 0 0.3rem; }
.muted, .field small, .host-summary small { color: var(--p-text-muted-color); }
.host-list, .skeletons { gap: 0.55rem; }
.host-choice { width: 100%; display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 0.75rem; padding: 0.85rem; border: 1px solid var(--p-content-border-color); border-radius: 0.65rem; background: var(--p-content-background); color: inherit; text-align: left; cursor: pointer; }
.host-choice:not(:disabled):hover, .host-choice.selected { border-color: var(--p-primary-color); background: var(--p-primary-50); }
.host-choice:disabled { cursor: not-allowed; opacity: 0.68; }
.host-icon { display: grid; place-items: center; width: 2.25rem; height: 2.25rem; border-radius: 0.5rem; background: var(--p-content-hover-background); }
.host-summary { display: flex; min-width: 0; flex-direction: column; gap: 0.2rem; }
.unavailable { color: var(--p-orange-500) !important; }
.field-error { color: var(--p-red-500) !important; }
.field { gap: 0.35rem; padding-top: 0.25rem; }
.field > label { font-size: 0.85rem; font-weight: 600; }
.settings-form { gap: 0.8rem; padding-top: 0.4rem; border-top: 1px solid var(--p-content-border-color); }
.settings-form h4 { margin: 0.3rem 0 0; }
.setting-label { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
.setting-label label { font-size: 0.85rem; font-weight: 600; }
.load-error { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
@media (max-width: 40rem) {
  .load-error { align-items: stretch; flex-direction: column; }
}
</style>
