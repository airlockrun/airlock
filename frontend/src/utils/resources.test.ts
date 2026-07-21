import { describe, expect, it } from 'vitest'
import type { CandidateInfo, OwnedResourceInfo } from '@/gen/airlock/v1/api_pb'
import type { SetupCountsInfo } from '@/gen/airlock/v1/types_pb'
import {
  bindingDialogCompletion,
  canCreateResourceForNeed,
  candidateAction,
  oauthCallbackNotice,
  resourceDetailAccess,
  resourceStatus,
  setupSummary,
} from './resources'

function candidate(readiness: string, capabilities: string[]): CandidateInfo {
  return { readiness, capabilities } as CandidateInfo
}

describe('resource candidate actions', () => {
  it('binds only ready candidates with bind access', () => {
    expect(candidateAction(candidate('ready', ['bind']), 'token').kind).toBe('bind')
    expect(candidateAction(candidate('ready', ['view']), 'token')).toMatchObject({ kind: 'disabled', label: 'Cannot bind' })
  })

  it('requires manage access for OAuth authorization and scope extension', () => {
    expect(candidateAction(candidate('scope_upgrade_required', ['bind', 'manage']), 'oauth').kind).toBe('authorize')
    expect(candidateAction(candidate('scope_upgrade_requires_manager', ['bind']), 'oauth').kind).toBe('disabled')
    expect(candidateAction(candidate('authorization_required', ['bind', 'manage']), 'oauth').kind).toBe('authorize')
  })

  it('binds non-OAuth resources before opening their configuration form', () => {
    expect(candidateAction(candidate('authorization_required', ['bind', 'manage']), 'token').kind).toBe('configure')
  })

  it('offers no-auth creation only for exec endpoint needs', () => {
    expect(canCreateResourceForNeed('connection', 'none')).toBe(false)
    expect(canCreateResourceForNeed('mcp_server', 'none')).toBe(false)
    expect(canCreateResourceForNeed('exec_endpoint', 'none')).toBe(true)
    expect(canCreateResourceForNeed('connection', 'api_key')).toBe(true)
  })

  it('chooses one terminal event for completed dialog actions', () => {
    expect(bindingDialogCompletion('bind', 'connection')).toBe('changed')
    expect(bindingDialogCompletion('configure', 'connection')).toBe('configure')
    expect(bindingDialogCompletion('create', 'exec_endpoint')).toBe('configure')
    expect(bindingDialogCompletion('create', 'connection')).toBe('changed')
  })
})

describe('resource inventory status', () => {
  it('distinguishes ready, setup, and dormant resources', () => {
    expect(resourceStatus({ authorized: false, agentCount: 1 } as OwnedResourceInfo).label).toBe('Needs setup')
    expect(resourceStatus({ authorized: true, agentCount: 1 } as OwnedResourceInfo).label).toBe('Ready')
    expect(resourceStatus({ authorized: true, agentCount: 0, authMode: 'oauth' } as OwnedResourceInfo).label).toBe('Dormant')
  })
})

describe('resource detail capabilities', () => {
  it('loads consumers only with view and grants only with manage', () => {
    expect(resourceDetailAccess(['bind'])).toEqual({ consumers: false, grants: false })
    expect(resourceDetailAccess(['view'])).toEqual({ consumers: true, grants: false })
    expect(resourceDetailAccess(['manage'])).toEqual({ consumers: false, grants: true })
  })
})

describe('resource callback and setup helpers', () => {
  it('includes exec endpoints in setup totals and labels', () => {
    const summary = setupSummary({ connections: 1, mcpServers: 0, envVars: 0, execEndpoints: 2 } as SetupCountsInfo)
    expect(summary.total).toBe(3)
    expect(summary.tooltip).toBe('1 connection, 2 exec endpoints need setup')
  })

  it.each([
    ['authorized', 'success', 'Resource authorized and connected'],
    ['denied', 'warn', 'Authorization was cancelled'],
    ['partial_grant', 'warn', 'Required access was not granted'],
    ['invalidated', 'warn', 'Authorization could not be applied'],
    ['exchange_failed', 'error', 'Provider authorization failed'],
    ['unexpected', 'error', 'Resource authorization failed'],
  ] as const)('maps %s to a useful notice', (status, severity, summary) => {
    expect(oauthCallbackNotice(status, '', '')).toMatchObject({ severity, summary })
  })
})
