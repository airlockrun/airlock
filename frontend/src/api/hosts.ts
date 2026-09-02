import { create, fromJson, toJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import type { GetHostResponse, HostEnrollmentInfo, HostManagementJobResponse } from '@/gen/airlock/v1/api_pb'
import type { HostInfo } from '@/gen/airlock/v1/types_pb'
import {
  ApproveHostEnrollmentRequestSchema,
  DenyHostEnrollmentRequestSchema,
  GetHostResponseSchema,
  HostEnrollmentInfoSchema,
  HostManagementJobResponseSchema,
  InspectHostEnrollmentRequestSchema,
  ListHostsResponseSchema,
  RequestConnectorInstallRequestSchema,
  RequestConnectorRemoveRequestSchema,
  RequestConnectorRollbackRequestSchema,
  RequestConnectorUpdateRequestSchema,
  RequestHostShellRequestSchema,
} from '@/gen/airlock/v1/api_pb'

export async function listHosts(): Promise<HostInfo[]> {
  const { data } = await api.get('/api/v1/hosts')
  return fromJson(ListHostsResponseSchema, data).hosts
}

export async function getHost(id: string): Promise<GetHostResponse> {
  const { data } = await api.get(`/api/v1/hosts/${id}`)
  return fromJson(GetHostResponseSchema, data)
}

export async function inspectHostEnrollment(userCode: string): Promise<HostEnrollmentInfo> {
  const request = create(InspectHostEnrollmentRequestSchema, { userCode })
  const { data } = await api.post('/api/v1/host-enrollments/inspect', toJson(InspectHostEnrollmentRequestSchema, request))
  return fromJson(HostEnrollmentInfoSchema, data)
}

export async function approveHostEnrollment(userCode: string): Promise<HostEnrollmentInfo> {
  const request = create(ApproveHostEnrollmentRequestSchema, { userCode })
  const { data } = await api.post('/api/v1/host-enrollments/approve', toJson(ApproveHostEnrollmentRequestSchema, request))
  return fromJson(HostEnrollmentInfoSchema, data)
}

export async function denyHostEnrollment(userCode: string): Promise<void> {
  const request = create(DenyHostEnrollmentRequestSchema, { userCode })
  await api.post('/api/v1/host-enrollments/deny', toJson(DenyHostEnrollmentRequestSchema, request))
}

export async function requestShell(hostId: string, command: string, args: string[]): Promise<HostManagementJobResponse> {
  const request = create(RequestHostShellRequestSchema, { command, arguments: args, timeoutSeconds: 1800 })
  const { data } = await api.post(`/api/v1/hosts/${hostId}/shell`, toJson(RequestHostShellRequestSchema, request))
  return fromJson(HostManagementJobResponseSchema, data)
}

export async function requestInstall(hostId: string, values: {
  agentId: string
  needSlug: string
  artifactFileId: string
  displayName: string
  settingsJson: string
}): Promise<HostManagementJobResponse> {
  const request = create(RequestConnectorInstallRequestSchema, { ...values, timeoutSeconds: 1800 })
  const { data } = await api.post(`/api/v1/hosts/${hostId}/connectors`, toJson(RequestConnectorInstallRequestSchema, request))
  return fromJson(HostManagementJobResponseSchema, data)
}

export async function requestUpdate(connectorId: string, artifactFileId: string, settingsJson = ''): Promise<HostManagementJobResponse> {
  const request = create(RequestConnectorUpdateRequestSchema, { artifactFileId, settingsJson, timeoutSeconds: 1800 })
  const { data } = await api.post(`/api/v1/connectors/${connectorId}/update`, toJson(RequestConnectorUpdateRequestSchema, request))
  return fromJson(HostManagementJobResponseSchema, data)
}

export async function requestRemove(connectorId: string): Promise<HostManagementJobResponse> {
  const request = create(RequestConnectorRemoveRequestSchema, { timeoutSeconds: 1800 })
  const { data } = await api.post(`/api/v1/connectors/${connectorId}/remove`, toJson(RequestConnectorRemoveRequestSchema, request))
  return fromJson(HostManagementJobResponseSchema, data)
}

export async function requestRollback(connectorId: string): Promise<HostManagementJobResponse> {
  const request = create(RequestConnectorRollbackRequestSchema, { timeoutSeconds: 1800 })
  const { data } = await api.post(`/api/v1/connectors/${connectorId}/rollback`, toJson(RequestConnectorRollbackRequestSchema, request))
  return fromJson(HostManagementJobResponseSchema, data)
}
