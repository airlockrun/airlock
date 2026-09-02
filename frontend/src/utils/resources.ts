import type { CandidateInfo, OwnedResourceInfo } from '@/gen/airlock/v1/api_pb'
import type { HostInfo, SetupCountsInfo } from '@/gen/airlock/v1/types_pb'
import type { AirlockI18nComposable } from '@/i18n'
import type { MessageId } from '@/i18n/messages'
import { resourceMessages } from '@/i18n/messages/resources'
import { isHostStale } from '@/utils/connectors'

type ResourceI18n = Pick<AirlockI18nComposable, 't' | 'formatNumber'>

function fallbackT(id: MessageId, values: Record<string, string | number> = {}): string {
  let message = resourceMessages[id as keyof typeof resourceMessages]?.defaultMessage ?? id
  if (message.includes('|')) {
    const choices = message.split('|').map(choice => choice.trim())
    message = Number(values.count) === 1 ? choices[0] : choices[choices.length - 1]
  }
  return message.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key] ?? `{${key}}`))
}

function translate(i18n: ResourceI18n | undefined, id: MessageId, values: Record<string, string | number> = {}): string {
  return i18n ? i18n.t(id, values) : fallbackT(id, values)
}

function formattedCount(i18n: ResourceI18n | undefined, count: number): string {
  return i18n ? i18n.formatNumber(count) : String(count)
}

export interface CandidateAction {
  kind: 'bind' | 'authorize' | 'configure' | 'disabled'
  label: string
  reason?: string
}

export type BindingDialogCompletion = 'changed' | 'configure'

export function hasCapability(capabilities: string[], capability: string): boolean {
  return capabilities.includes(capability)
}

export function candidateAction(candidate: CandidateInfo, authMode: string, i18n: ResourceI18n): CandidateAction {
  if (!hasCapability(candidate.capabilities, 'bind')) {
    return {
      kind: 'disabled',
      label: translate(i18n, 'resources.actions.cannotBind'),
      reason: translate(i18n, 'resources.binding.noBindAccess'),
    }
  }

  switch (candidate.readiness) {
    case 'ready':
      return { kind: 'bind', label: translate(i18n, 'resources.actions.useResource') }
    case 'scope_upgrade_requires_manager':
      return {
        kind: 'disabled',
        label: translate(i18n, 'resources.actions.managerRequired'),
        reason: translate(i18n, 'resources.binding.managerMustExtend'),
      }
    case 'scope_upgrade_required':
      if (!hasCapability(candidate.capabilities, 'manage')) {
        return {
          kind: 'disabled',
          label: translate(i18n, 'resources.actions.managerRequired'),
          reason: translate(i18n, 'resources.binding.managerMustExtend'),
        }
      }
      return { kind: 'authorize', label: translate(i18n, 'resources.actions.extendAccess') }
    case 'authorization_required':
      if (!hasCapability(candidate.capabilities, 'manage')) {
        return {
          kind: 'disabled',
          label: translate(i18n, 'resources.actions.managerRequired'),
          reason: translate(i18n, 'resources.binding.manageRequired'),
        }
      }
      if (authMode === 'oauth' || authMode === 'oauth_discovery') {
        return { kind: 'authorize', label: translate(i18n, 'resources.actions.authorize') }
      }
      return { kind: 'configure', label: translate(i18n, 'resources.actions.setUpAndUse') }
    case 'needs_configuration':
      return { kind: 'disabled', label: translate(i18n, 'resources.actions.configureLocally'), reason: translate(i18n, 'resources.binding.connectorConfigureFirst') }
    case 'incompatible_protocol':
      return { kind: 'disabled', label: translate(i18n, 'resources.actions.protocolIncompatible'), reason: translate(i18n, 'resources.binding.protocolUnsupported') }
    case 'unhealthy':
      return { kind: 'disabled', label: translate(i18n, 'resources.actions.unhealthy'), reason: translate(i18n, 'resources.binding.connectorRecover') }
    case 'starting':
      return { kind: 'disabled', label: translate(i18n, 'resources.status.starting'), reason: translate(i18n, 'resources.binding.connectorNotReady') }
    case 'offline':
      return { kind: 'disabled', label: translate(i18n, 'resources.status.offline'), reason: translate(i18n, 'resources.binding.connectorReconnect') }
    default:
      return { kind: 'disabled', label: translate(i18n, 'resources.actions.unavailable'), reason: translate(i18n, 'resources.binding.notReady') }
  }
}

export function canCreateResourceForNeed(authMode: string): boolean {
  return authMode !== 'none'
}

export function bindingDialogCompletion(
  action: 'bind' | 'configure' | 'create',
): BindingDialogCompletion {
  return action === 'configure' ? 'configure' : 'changed'
}

export function resourceStatus(resource: OwnedResourceInfo, i18n: ResourceI18n, host?: HostInfo, now = Date.now()): { label: string; severity: 'success' | 'warn' | 'danger' | 'secondary' } {
  if (resource.type === 'connector') {
    if (resource.connectorStatus?.lifecycle === 'revoked') return { label: translate(i18n, 'resources.status.revoked'), severity: 'danger' }
    switch (resource.connectorStatus?.readiness) {
      case 'ready': return { label: translate(i18n, 'resources.status.ready'), severity: 'success' }
      case 'needs_configuration': return { label: translate(i18n, 'resources.status.needsLocalConfiguration'), severity: 'warn' }
      case 'incompatible_protocol': return { label: translate(i18n, 'resources.status.incompatibleProtocol'), severity: 'danger' }
      case 'unhealthy': return { label: translate(i18n, 'resources.status.unhealthy'), severity: 'danger' }
      case 'starting': return { label: translate(i18n, 'resources.status.starting'), severity: 'warn' }
      case 'offline': return { label: translate(i18n, 'resources.status.offline'), severity: 'secondary' }
      default: return { label: resource.connectorStatus?.readiness || translate(i18n, 'resources.status.unknown'), severity: 'secondary' }
    }
  }
  if (resource.type === 'host') {
    if (!resource.authorized) return { label: translate(i18n, 'resources.status.needsSetup'), severity: 'warn' }
    if (!host) return { label: translate(i18n, 'resources.status.unknown'), severity: 'secondary' }
    if (host.lifecycle && host.lifecycle !== 'active') {
      return {
        label: host.lifecycle === 'revoked' ? translate(i18n, 'resources.status.revoked') : host.lifecycle,
        severity: 'danger',
      }
    }
    return isHostStale(host.lastSeenAt, now)
      ? { label: translate(i18n, 'resources.status.stale'), severity: 'warn' }
      : { label: translate(i18n, 'resources.status.ready'), severity: 'success' }
  }
  if (!resource.authorized) return { label: translate(i18n, 'resources.status.needsSetup'), severity: 'warn' }
  if (resource.agentCount === 0 && resource.authMode !== 'none') {
    return { label: translate(i18n, 'resources.status.dormant'), severity: 'secondary' }
  }
  return { label: translate(i18n, 'resources.status.ready'), severity: 'success' }
}

export function resourceLabel(resource: Pick<OwnedResourceInfo, 'displayName' | 'name' | 'slug'>): string {
  return resource.displayName || resource.name || resource.slug
}

export function resourceDetailAccess(capabilities: string[]): { details: boolean; consumers: boolean; grants: boolean } {
  return {
    details: hasCapability(capabilities, 'view'),
    consumers: hasCapability(capabilities, 'view'),
    grants: hasCapability(capabilities, 'manage'),
  }
}

export function setupSummary(counts: SetupCountsInfo | null, i18n?: ResourceI18n): { total: number; tooltip: string } {
  if (!counts) return { total: 0, tooltip: '' }
  const parts: string[] = []
  if (counts.connections) parts.push(translate(i18n, 'resources.setup.connections', { count: counts.connections, formattedCount: formattedCount(i18n, counts.connections) }))
  if (counts.mcpServers) parts.push(translate(i18n, 'resources.setup.mcpServers', { count: counts.mcpServers, formattedCount: formattedCount(i18n, counts.mcpServers) }))
  if (counts.envVars) parts.push(translate(i18n, 'resources.setup.envVars', { count: counts.envVars, formattedCount: formattedCount(i18n, counts.envVars) }))
  if (counts.connectors) parts.push(translate(i18n, 'resources.setup.connectors', { count: counts.connectors, formattedCount: formattedCount(i18n, counts.connectors) }))
  const total = counts.connections + counts.mcpServers + counts.envVars + counts.connectors
  return {
    total,
    tooltip: total ? translate(i18n, 'resources.setup.needsSetup', { count: total, items: parts.join(', ') }) : '',
  }
}

export interface OAuthCallbackNotice {
  severity: 'success' | 'warn' | 'error'
  summary: string
  detail: string
}

export function oauthCallbackNotice(status: string, message: string, resourceId: string, i18n?: ResourceI18n): OAuthCallbackNotice {
  const fallback: Record<string, OAuthCallbackNotice> = {
    authorized: {
      severity: 'success',
      summary: translate(i18n, 'resources.oauth.authorizedSummary'),
      detail: resourceId ? translate(i18n, 'resources.oauth.authorizedDetailId', { id: resourceId }) : translate(i18n, 'resources.oauth.authorizedDetail'),
    },
    denied: {
      severity: 'warn',
      summary: translate(i18n, 'resources.oauth.cancelledSummary'),
      detail: translate(i18n, 'resources.oauth.credentialsRemain'),
    },
    partial_grant: {
      severity: 'warn',
      summary: translate(i18n, 'resources.oauth.partialSummary'),
      detail: translate(i18n, 'resources.oauth.partialDetail'),
    },
    invalidated: {
      severity: 'warn',
      summary: translate(i18n, 'resources.oauth.invalidatedSummary'),
      detail: translate(i18n, 'resources.oauth.invalidatedDetail'),
    },
    exchange_failed: {
      severity: 'error',
      summary: translate(i18n, 'resources.oauth.exchangeFailedSummary'),
      detail: translate(i18n, 'resources.oauth.exchangeFailedDetail'),
    },
  }
  const notice = fallback[status] ?? {
    severity: 'error' as const,
    summary: translate(i18n, 'resources.oauth.failedSummary'),
    detail: translate(i18n, 'resources.oauth.failedDetail'),
  }
  if (!message) return notice
  return {
    ...notice,
    detail: status === 'authorized' ? message : translate(i18n, 'resources.oauth.providerMessage', { message, detail: notice.detail }),
  }
}
