import type { CandidateInfo, OwnedResourceInfo } from '@/gen/airlock/v1/api_pb'
import type { SetupCountsInfo } from '@/gen/airlock/v1/types_pb'

export interface CandidateAction {
  kind: 'bind' | 'authorize' | 'configure' | 'disabled'
  label: string
  reason?: string
}

export type BindingDialogCompletion = 'changed' | 'configure'

export function hasCapability(capabilities: string[], capability: string): boolean {
  return capabilities.includes(capability)
}

export function candidateAction(candidate: CandidateInfo, authMode: string): CandidateAction {
  if (!hasCapability(candidate.capabilities, 'bind')) {
    return { kind: 'disabled', label: 'Cannot bind', reason: 'You do not have bind access to this resource.' }
  }

  switch (candidate.readiness) {
    case 'ready':
      return { kind: 'bind', label: 'Use resource' }
    case 'scope_upgrade_requires_manager':
      return {
        kind: 'disabled',
        label: 'Manager required',
        reason: 'A resource manager must extend its OAuth access before it can be used here.',
      }
    case 'scope_upgrade_required':
      if (!hasCapability(candidate.capabilities, 'manage')) {
        return {
          kind: 'disabled',
          label: 'Manager required',
          reason: 'A resource manager must extend its OAuth access before it can be used here.',
        }
      }
      return { kind: 'authorize', label: 'Extend access' }
    case 'authorization_required':
      if (!hasCapability(candidate.capabilities, 'manage')) {
        return {
          kind: 'disabled',
          label: 'Manager required',
          reason: 'Manage access is required to configure or authorize this resource.',
        }
      }
      if (authMode === 'oauth' || authMode === 'oauth_discovery') {
        return { kind: 'authorize', label: 'Authorize' }
      }
      return { kind: 'configure', label: 'Set up and use' }
    default:
      return { kind: 'disabled', label: 'Unavailable', reason: 'This resource is not ready to use.' }
  }
}

export function canCreateResourceForNeed(needType: string, authMode: string): boolean {
  return needType === 'exec_endpoint' || authMode !== 'none'
}

export function bindingDialogCompletion(
  action: 'bind' | 'configure' | 'create',
  needType: string,
): BindingDialogCompletion {
  return action === 'configure' || (action === 'create' && needType === 'exec_endpoint')
    ? 'configure'
    : 'changed'
}

export function resourceStatus(resource: OwnedResourceInfo): { label: string; severity: 'success' | 'warn' | 'secondary' } {
  if (!resource.authorized) return { label: 'Needs setup', severity: 'warn' }
  if (resource.agentCount === 0 && resource.authMode !== 'none') {
    return { label: 'Dormant', severity: 'secondary' }
  }
  return { label: 'Ready', severity: 'success' }
}

export function resourceLabel(resource: Pick<OwnedResourceInfo, 'displayName' | 'name' | 'slug'>): string {
  return resource.displayName || resource.name || resource.slug
}

export function resourceDetailAccess(capabilities: string[]): { consumers: boolean; grants: boolean } {
  return {
    consumers: hasCapability(capabilities, 'view'),
    grants: hasCapability(capabilities, 'manage'),
  }
}

export function setupSummary(counts: SetupCountsInfo | null): { total: number; tooltip: string } {
  if (!counts) return { total: 0, tooltip: '' }
  const parts: string[] = []
  if (counts.connections) parts.push(`${counts.connections} connection${counts.connections === 1 ? '' : 's'}`)
  if (counts.mcpServers) parts.push(`${counts.mcpServers} MCP server${counts.mcpServers === 1 ? '' : 's'}`)
  if (counts.envVars) parts.push(`${counts.envVars} env var${counts.envVars === 1 ? '' : 's'}`)
  if (counts.execEndpoints) parts.push(`${counts.execEndpoints} exec endpoint${counts.execEndpoints === 1 ? '' : 's'}`)
  const total = counts.connections + counts.mcpServers + counts.envVars + counts.execEndpoints
  return {
    total,
    tooltip: total ? `${parts.join(', ')} need${total === 1 ? 's' : ''} setup` : '',
  }
}

export interface OAuthCallbackNotice {
  severity: 'success' | 'warn' | 'error'
  summary: string
  detail: string
}

export function oauthCallbackNotice(status: string, message: string, resourceId: string): OAuthCallbackNotice {
  const fallback: Record<string, OAuthCallbackNotice> = {
    authorized: {
      severity: 'success',
      summary: 'Resource authorized and connected',
      detail: resourceId ? `Resource ${resourceId} is ready.` : 'The resource is ready.',
    },
    denied: {
      severity: 'warn',
      summary: 'Authorization was cancelled',
      detail: 'The current resource and credentials remain active.',
    },
    partial_grant: {
      severity: 'warn',
      summary: 'Required access was not granted',
      detail: 'The provider did not grant every required scope. The current resource and credentials remain active.',
    },
    invalidated: {
      severity: 'warn',
      summary: 'Authorization could not be applied',
      detail: 'The app or resource changed during authorization. The current binding remains active; retry from setup.',
    },
    exchange_failed: {
      severity: 'error',
      summary: 'Provider authorization failed',
      detail: 'Airlock could not complete the provider token exchange. The current resource and credentials remain active.',
    },
  }
  const notice = fallback[status] ?? {
    severity: 'error' as const,
    summary: 'Resource authorization failed',
    detail: 'The current resource and credentials remain active. Retry from setup.',
  }
  if (!message) return notice
  return {
    ...notice,
    detail: status === 'authorized' ? message : `${message} ${notice.detail}`,
  }
}
