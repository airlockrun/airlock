import { create, fromJson, toJson } from '@bufbuild/protobuf'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import api from '@/api/client'
import type { CandidateInfo, ConnectorTargetGroupCandidateInfo, GetConnectorResponse, NeedInfo } from '@/gen/airlock/v1/api_pb'
import type { ConnectorArtifactFileInfo, ConnectorArtifactSetInfo, ConnectorInfo, ConnectorTargetGroupInfo } from '@/gen/airlock/v1/types_pb'
import { ConnectorTargetGroupInfoSchema } from '@/gen/airlock/v1/types_pb'
import {
  AddConnectorTargetGroupMemberRequestSchema,
  BindNeedRequestSchema,
  BindConnectorGroupRequestSchema,
  CreateConnectorTargetGroupRequestSchema,
  GetConnectorResponseSchema,
  ListCandidatesResponseSchema,
  ListConnectorArtifactsResponseSchema,
  ListConnectorsResponseSchema,
  ListConnectorTargetGroupsResponseSchema,
  ListConnectorTargetGroupCandidatesResponseSchema,
  ListNeedsResponseSchema,
} from '@/gen/airlock/v1/api_pb'
import {
  parseConnectorInterface,
  parseConnectorSettings,
  type ConnectorArtifactCatalog,
  type ConnectorArtifactTarget,
  type ConnectorArtifactVersion,
} from '@/utils/connectors'

export type ConnectorArtifactErrorMessageId =
  | 'connectors.install.error.unsupportedPlatform'
  | 'connectors.install.error.invalidInterface'
  | 'connectors.install.error.invalidSettings'
  | 'connectors.install.error.unsupportedMacOSSystemServiceMode'

export class ConnectorArtifactValidationError extends Error {
  constructor(
    readonly messageId: ConnectorArtifactErrorMessageId,
    readonly values: Record<string, string>,
  ) {
    super(messageId)
    this.name = 'ConnectorArtifactValidationError'
  }
}
export async function listAgentConnectorNeeds(agentId: string): Promise<NeedInfo[]> {
  const { data } = await api.get(`/api/v1/agents/${agentId}/needs`)
  return fromJson(ListNeedsResponseSchema, data).needs.filter((need) => need.type === 'connector')
}

export async function listConnectors(): Promise<ConnectorInfo[]> {
  const { data } = await api.get('/api/v1/connectors')
  return fromJson(ListConnectorsResponseSchema, data).connectors
}

export async function getConnectorDetail(connectorId: string): Promise<GetConnectorResponse> {
  const { data } = await api.get(`/api/v1/connectors/${connectorId}`)
  return fromJson(GetConnectorResponseSchema, data)
}

export async function getConnector(connectorId: string): Promise<ConnectorInfo> {
  const connector = (await getConnectorDetail(connectorId)).connector
  if (!connector) throw new Error('Connector response did not include a connector')
  return connector
}

export async function listConnectorCandidates(agentId: string, slug: string): Promise<CandidateInfo[]> {
  const { data } = await api.get(`/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/candidates`)
  return fromJson(ListCandidatesResponseSchema, data).candidates
}

export async function bindConnector(agentId: string, slug: string, resourceId: string): Promise<void> {
  const request = create(BindNeedRequestSchema, { resourceId })
  await api.post(
    `/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/bind`,
    toJson(BindNeedRequestSchema, request),
  )
}

export async function unbindConnector(agentId: string, slug: string): Promise<void> {
  await api.delete(`/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/bind`)
}

export async function listConnectorTargetGroups(): Promise<ConnectorTargetGroupInfo[]> {
  const { data } = await api.get('/api/v1/connector-target-groups')
  return fromJson(ListConnectorTargetGroupsResponseSchema, data).groups
}

export async function listConnectorTargetGroupCandidates(agentId: string, slug: string): Promise<ConnectorTargetGroupCandidateInfo[]> {
  const { data } = await api.get(`/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/target-groups`)
  return fromJson(ListConnectorTargetGroupCandidatesResponseSchema, data).candidates
}

export async function createConnectorTargetGroup(agentId: string, needSlug: string, name: string, description: string, connectorIds: string[]): Promise<ConnectorTargetGroupInfo> {
  const request = create(CreateConnectorTargetGroupRequestSchema, { name, description, agentId, needSlug, connectorIds })
  const { data } = await api.post('/api/v1/connector-target-groups', toJson(CreateConnectorTargetGroupRequestSchema, request))
  return fromJson(ConnectorTargetGroupInfoSchema, data)
}

export async function addConnectorTargetGroupMember(groupId: string, connectorId: string, position: number): Promise<void> {
  const request = create(AddConnectorTargetGroupMemberRequestSchema, { connectorId, position })
  await api.post(`/api/v1/connector-target-groups/${groupId}/members`, toJson(AddConnectorTargetGroupMemberRequestSchema, request))
}

export async function bindConnectorGroup(agentId: string, slug: string, targetGroupId: string): Promise<void> {
  const request = create(BindConnectorGroupRequestSchema, { targetGroupId })
  await api.post(
    `/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/bind-group`,
    toJson(BindConnectorGroupRequestSchema, request),
  )
}

function target(file: ConnectorArtifactFileInfo): ConnectorArtifactTarget {
  const match = /^(linux|windows|darwin)-(amd64|arm64|armv7)$/.exec(file.platform)
  if (!match || (match[2] === 'armv7' && match[1] !== 'linux')) {
    throw new ConnectorArtifactValidationError('connectors.install.error.unsupportedPlatform', {
      artifactFileId: file.id,
      platform: file.platform,
    })
  }
  return {
    artifactFileId: file.id,
    target: file.platform,
    os: match[1],
    arch: match[2],
    filename: file.filename,
    sizeBytes: file.sizeBytes,
    sha256: file.sha256,
    noticesSha256: file.noticesSha256,
    noticesSizeBytes: file.noticesSizeBytes,
  }
}

function artifactVersion(set: ConnectorArtifactSetInfo, latest: boolean): ConnectorArtifactVersion {
  let interfaceValue: unknown
  try {
    interfaceValue = JSON.parse(set.interfaceJson) as unknown
  } catch {
    throw new ConnectorArtifactValidationError('connectors.install.error.invalidInterface', { artifactSetId: set.id })
  }
  const interfaceDescriptor = parseConnectorInterface(interfaceValue)
  if (!interfaceDescriptor) {
    throw new ConnectorArtifactValidationError('connectors.install.error.invalidInterface', { artifactSetId: set.id })
  }
  let settingsValue: unknown
  try {
    settingsValue = JSON.parse(set.settingsJson) as unknown
  } catch {
    throw new ConnectorArtifactValidationError('connectors.install.error.invalidSettings', { artifactSetId: set.id })
  }
  const settings = parseConnectorSettings(settingsValue)
  if (!settings) {
    throw new ConnectorArtifactValidationError('connectors.install.error.invalidSettings', { artifactSetId: set.id })
  }
  const serviceMode = set.serviceMode === 'user' || set.serviceMode === 'system' ? set.serviceMode : ''
  const targets = set.files.map(target)
  if (serviceMode === 'system' && targets.some((item) => item.os === 'darwin')) {
    throw new ConnectorArtifactValidationError('connectors.install.error.unsupportedMacOSSystemServiceMode', { artifactSetId: set.id })
  }
  return {
    artifactSetId: set.id,
    version: set.artifactVersion,
    sourceCommit: set.sourceRef,
    buildId: set.buildId,
    createdAt: set.createdAt ? timestampDate(set.createdAt).toISOString() : '',
    compatible: true,
    latestCompatible: latest,
    artifactDigest: set.artifactDigest,
    serviceMode,
    interface: interfaceDescriptor,
    settings,
    runtimeExpectations: [],
    notices: [],
    targets,
  }
}

export function artifactCatalog(data: unknown): ConnectorArtifactCatalog {
  const response = fromJson(ListConnectorArtifactsResponseSchema, data)
  return {
    connectorSlug: response.connectorSlug,
    name: response.name,
    description: response.description,
    versions: response.artifactSets.map((set, index) => artifactVersion(set, index === 0)),
  }
}

export async function listConnectorArtifacts(agentId: string, slug: string): Promise<ConnectorArtifactCatalog> {
  const { data } = await api.get(`/api/v1/agents/${agentId}/needs/connector/${encodeURIComponent(slug)}/artifacts`)
  return artifactCatalog(data)
}
