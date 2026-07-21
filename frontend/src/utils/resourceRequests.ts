import { create, toJson } from '@bufbuild/protobuf'
import {
  ConfigureExecEndpointRequestSchema,
  SetAPIKeyRequestSchema,
  SetOAuthAppRequestSchema,
  StartAuthorizationForNeedRequestSchema,
} from '@/gen/airlock/v1/api_pb'

export function serializeAPIKeyRequest(apiKey: string, displayName: string, createNew: boolean) {
  return toJson(
    SetAPIKeyRequestSchema,
    create(SetAPIKeyRequestSchema, { apiKey, displayName, createNew }),
    { alwaysEmitImplicit: true },
  )
}

export function serializeOAuthAppRequest(clientId: string, clientSecret: string, displayName: string, createNew: boolean) {
  return toJson(
    SetOAuthAppRequestSchema,
    create(SetOAuthAppRequestSchema, { clientId, clientSecret, displayName, createNew }),
    { alwaysEmitImplicit: true },
  )
}

export function serializeAuthorizationRequest(fields: {
  agentId: string
  type: string
  slug: string
  resourceId: string
  displayName: string
  redirectUri: string
  createNew: boolean
}) {
  return toJson(
    StartAuthorizationForNeedRequestSchema,
    create(StartAuthorizationForNeedRequestSchema, fields),
    { alwaysEmitImplicit: true },
  )
}

export function serializeExecEndpointRequest(fields: {
  host: string
  port: number
  sshUser: string
  displayName: string
  createNew: boolean
}) {
  return toJson(
    ConfigureExecEndpointRequestSchema,
    create(ConfigureExecEndpointRequestSchema, fields),
    { alwaysEmitImplicit: true },
  )
}
