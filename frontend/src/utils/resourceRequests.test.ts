import { describe, expect, it } from 'vitest'
import {
  serializeAPIKeyRequest,
  serializeAuthorizationRequest,
  serializeExecEndpointRequest,
  serializeOAuthAppRequest,
} from './resourceRequests'

describe('resource request serialization', () => {
  it('serializes create-new credential and OAuth app staging requests', () => {
    expect(serializeAPIKeyRequest('secret', 'Separate GitHub', true)).toMatchObject({
      apiKey: 'secret',
      displayName: 'Separate GitHub',
      createNew: true,
    })
    expect(serializeOAuthAppRequest('client', 'secret', 'Separate OAuth', true)).toMatchObject({
      clientId: 'client',
      clientSecret: 'secret',
      displayName: 'Separate OAuth',
      createNew: true,
    })
  })

  it('distinguishes existing candidates from provisional authorization', () => {
    const common = {
      agentId: 'agent-1',
      type: 'connection',
      slug: 'github',
      redirectUri: 'https://airlock.test/agents/agent-1',
    }
    expect(serializeAuthorizationRequest({ ...common, resourceId: 'resource-1', displayName: '', createNew: false })).toMatchObject({
      resourceId: 'resource-1',
      createNew: false,
    })
    expect(serializeAuthorizationRequest({ ...common, resourceId: '', displayName: 'New GitHub', createNew: true })).toMatchObject({
      resourceId: '',
      displayName: 'New GitHub',
      createNew: true,
    })
  })

  it('serializes exec create-new intent and existing reconfiguration separately', () => {
    const fields = { host: 'host.test', port: 22, sshUser: 'root', displayName: 'Production' }
    expect(serializeExecEndpointRequest({ ...fields, createNew: true })).toMatchObject({ createNew: true })
    expect(serializeExecEndpointRequest({ ...fields, displayName: '', createNew: false })).toMatchObject({ createNew: false })
  })
})
