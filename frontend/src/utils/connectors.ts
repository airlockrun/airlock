import type { ConnectorInfo } from '@/gen/airlock/v1/types_pb'
import type { Timestamp } from '@bufbuild/protobuf/wkt'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { connectorMessages } from '@/i18n/messages/connectors'

export type ConnectorTranslate = (
  id: keyof typeof connectorMessages,
  values?: Record<string, string | number>,
) => string

function connectorMessage(
  id: keyof typeof connectorMessages,
  values: Record<string, string | number> = {},
  translate?: ConnectorTranslate,
): string {
  if (translate) return translate(id, values)
  return connectorMessages[id].defaultMessage.replace(/\{(\w+)\}/g, (_, name: string) => String(values[name] ?? ''))
}

export interface ConnectorCommandDescriptor {
  name: string
  revision: number
  description: string
  mode: string
  inputSchemaHash: string
  outputSchemaHash: string
}

export interface ConnectorDirectoryDescriptor {
  name: string
  revision: number
  description: string
  read: boolean
  write: boolean
  list: boolean
}

export interface ConnectorInterfaceDescriptor {
  kind: string
  contractId: string
  name: string
  description: string
  artifactVersion: string
  artifactDigest: string
  commands: ConnectorCommandDescriptor[]
  directories: ConnectorDirectoryDescriptor[]
}

export interface ConnectorSettingDescriptor {
  name: string
  jsonName: string
  kind: string
  description: string
  required: boolean
  defaultValue: string
  enumValues: string[]
}

export type ConnectorSettingValue = string | boolean

const maxInt64 = 9223372036854775807n
const minInt64 = -9223372036854775808n
const int64Magnitude = 9223372036854775808n
const durationUnits: Record<string, bigint> = {
  ns: 1n,
  us: 1000n,
  'µs': 1000n,
  'μs': 1000n,
  ms: 1000000n,
  s: 1000000000n,
  m: 60000000000n,
  h: 3600000000000n,
}

export const hostStaleAfterMs = 2 * 60 * 1000

export function parseGoDurationNanoseconds(value: string): string | null {
  let offset = 0
  let negative = false
  if (value[offset] === '+' || value[offset] === '-') {
    negative = value[offset] === '-'
    offset++
  }
  if (value.slice(offset) === '0') return '0'
  if (offset === value.length) return null

  let total = 0n
  while (offset < value.length) {
    if (value[offset] !== '.' && (value[offset] < '0' || value[offset] > '9')) return null

    let whole = 0n
    const wholeStart = offset
    while (offset < value.length && value[offset] >= '0' && value[offset] <= '9') {
      if (whole > int64Magnitude / 10n) return null
      whole = whole * 10n + BigInt(value.charCodeAt(offset) - 48)
      if (whole > int64Magnitude) return null
      offset++
    }
    const hasWhole = offset !== wholeStart

    let fraction = 0n
    let scale = 1
    let hasFraction = false
    if (value[offset] === '.') {
      offset++
      const fractionStart = offset
      let overflow = false
      while (offset < value.length && value[offset] >= '0' && value[offset] <= '9') {
        if (!overflow) {
          if (fraction > maxInt64 / 10n) {
            overflow = true
          } else {
            const next = fraction * 10n + BigInt(value.charCodeAt(offset) - 48)
            if (next > int64Magnitude) overflow = true
            else {
              fraction = next
              scale *= 10
            }
          }
        }
        offset++
      }
      hasFraction = offset !== fractionStart
    }
    if (!hasWhole && !hasFraction) return null

    const unitStart = offset
    while (offset < value.length && value[offset] !== '.' && (value[offset] < '0' || value[offset] > '9')) offset++
    if (unitStart === offset) return null
    const unit = durationUnits[value.slice(unitStart, offset)]
    if (unit === undefined || whole > int64Magnitude / unit) return null

    let part = whole * unit
    if (fraction > 0n) {
      // Go deliberately performs this fractional operation in float64 to stay
      // nanosecond-accurate for fractions of hours. The bounded result is then
      // added to the exact BigInt whole-value path.
      part += BigInt(Math.trunc(Number(fraction) * (Number(unit) / scale)))
    }
    if (part > int64Magnitude) return null
    total += part
    if (total > int64Magnitude) return null
  }

  const result = negative ? -total : total
  if (result < minInt64 || result > maxInt64) return null
  return result.toString()
}

function parseInt64(value: string): string | null {
  if (!/^-?(0|[1-9]\d*)$/.test(value)) return null
  const parsed = BigInt(value)
  return parsed >= minInt64 && parsed <= maxInt64 ? parsed.toString() : null
}

export function connectorSettingDefaults(settings: ConnectorSettingDescriptor[]): Record<string, ConnectorSettingValue> {
  const values: Record<string, ConnectorSettingValue> = {}
  for (const setting of settings) {
    if (!setting.jsonName) continue
    values[setting.jsonName] = setting.kind === 'bool'
      ? setting.defaultValue === 'true'
      : setting.defaultValue
  }
  return values
}

export function connectorSettingError(
  setting: ConnectorSettingDescriptor,
  value: ConnectorSettingValue | undefined,
  translate?: ConnectorTranslate,
): string {
  if (setting.kind === 'bool') return setting.required && value !== true
    ? connectorMessage('connectors.settings.error.mustBeEnabled', {}, translate)
    : ''
  if (setting.kind === 'integer') {
    if ((value === undefined || value === '') && !setting.required) return ''
    if (typeof value !== 'string' || parseInt64(value) === null) return connectorMessage('connectors.settings.error.signedInteger', {}, translate)
    if (setting.required && BigInt(value) === 0n) return connectorMessage('connectors.settings.error.nonZeroInteger', {}, translate)
    return ''
  }
  if (setting.kind === 'duration') {
    if ((value === undefined || value === '') && !setting.required) return ''
    if (typeof value !== 'string') return connectorMessage('connectors.settings.error.duration', {}, translate)
    const nanoseconds = parseGoDurationNanoseconds(value)
    if (nanoseconds === null) return connectorMessage('connectors.settings.error.duration', {}, translate)
    if (setting.required && nanoseconds === '0') return connectorMessage('connectors.settings.error.nonZeroDuration', {}, translate)
    return ''
  }
  return setting.required && (typeof value !== 'string' || !value.trim())
    ? connectorMessage('connectors.settings.error.required', {}, translate)
    : ''
}

export function serializeConnectorSettings(
  settings: ConnectorSettingDescriptor[],
  values: Record<string, ConnectorSettingValue>,
): string {
  const fields: string[] = []
  for (const setting of settings) {
    if (!setting.jsonName) throw new Error(`Setting ${setting.name} has no published JSON name`)
    const value = values[setting.jsonName]
    if (value === undefined || value === null) continue
    if (typeof value === 'string' && !value && !setting.required && !setting.defaultValue) continue
    const error = connectorSettingError(setting, value)
    if (error) throw new Error(`${setting.name}: ${error}`)

    let encoded: string
    if (setting.kind === 'integer') encoded = parseInt64(value as string)!
    else if (setting.kind === 'duration') encoded = parseGoDurationNanoseconds(value as string)!
    else encoded = JSON.stringify(value)
    fields.push(`${JSON.stringify(setting.jsonName)}:${encoded}`)
  }
  return `{${fields.join(',')}}`
}

export function isHostStale(lastSeenAt: Timestamp | undefined, now = Date.now()): boolean {
  return !lastSeenAt || now - timestampDate(lastSeenAt).getTime() >= hostStaleAfterMs
}

export function hostStatus(
  host: { lifecycle: string; lastSeenAt?: Timestamp },
  now = Date.now(),
  translate?: ConnectorTranslate,
): { label: string; severity: 'success' | 'warn' | 'danger' | 'secondary' } {
  if (host.lifecycle && host.lifecycle !== 'active') {
    return {
      label: host.lifecycle === 'revoked'
        ? connectorMessage('connectors.host.status.revoked', {}, translate)
        : host.lifecycle,
      severity: 'danger',
    }
  }
  return isHostStale(host.lastSeenAt, now)
    ? { label: connectorMessage('connectors.host.status.stale', {}, translate), severity: 'warn' }
    : { label: connectorMessage('connectors.host.status.ready', {}, translate), severity: 'success' }
}

export interface ConnectorArtifactTarget {
  artifactFileId: string
  target: string
  os: string
  arch: string
  filename: string
  sizeBytes: bigint
  sha256: string
  noticesSha256: string
  noticesSizeBytes: bigint
}

export interface ConnectorArtifactVersion {
  artifactSetId: string
  version: string
  sourceCommit: string
  buildId: string
  createdAt: string
  compatible: boolean
  latestCompatible: boolean
  artifactDigest: string
  serviceMode: ConnectorServiceMode | ''
  interface: ConnectorInterfaceDescriptor
  settings: ConnectorSettingDescriptor[]
  runtimeExpectations: string[]
  notices: string[]
  targets: ConnectorArtifactTarget[]
}

export interface ConnectorArtifactCatalog {
  connectorSlug: string
  name: string
  description: string
  versions: ConnectorArtifactVersion[]
}

type JsonRecord = Record<string, unknown>

function record(value: unknown): JsonRecord | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as JsonRecord
    : null
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function integer(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) ? value : 0
}

function bool(value: unknown): boolean {
  return value === true
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function schemaType(value: unknown, depth = 0): string {
  const schema = record(value)
  if (!schema) return 'unknown'

  if (Array.isArray(schema.enum) && schema.enum.length) {
    return schema.enum.map((item) => JSON.stringify(item)).join(' | ')
  }
  if ('const' in schema) return JSON.stringify(schema.const)
  if (Array.isArray(schema.anyOf)) {
    return [...new Set(schema.anyOf.map((item) => schemaType(item, depth)))].join(' | ')
  }
  if (schema.type === 'array') {
    const item = schemaType(schema.items, depth + 1)
    return item.includes(' | ') ? `(${item})[]` : `${item}[]`
  }
  if (schema.type === 'object') {
    const properties = record(schema.properties)
    if (!properties || !Object.keys(properties).length) return '{}'
    if (depth >= 3) return 'object'
    const required = new Set(strings(schema.required))
    const fields = Object.entries(properties).map(([name, property]) =>
      `${name}${required.has(name) ? '' : '?'}: ${schemaType(property, depth + 1)}`,
    )
    return `{ ${fields.join('; ')} }`
  }
  if (typeof schema.type === 'string' && schema.type) return schema.type
  return 'unknown'
}

export function connectorSchemaSignature(raw: string): string {
  if (!raw) return 'unknown'
  try {
    return schemaType(JSON.parse(raw) as unknown)
  } catch {
    return 'unknown'
  }
}

function command(value: unknown): ConnectorCommandDescriptor | null {
  const item = record(value)
  if (!item || !text(item.name)) return null
  return {
    name: text(item.name),
    revision: integer(item.revision),
    description: text(item.description),
    mode: text(item.mode),
    inputSchemaHash: text(item.inputSchemaHash),
    outputSchemaHash: text(item.outputSchemaHash),
  }
}

function directory(value: unknown): ConnectorDirectoryDescriptor | null {
  const item = record(value)
  if (!item || !text(item.name)) return null
  return {
    name: text(item.name),
    revision: integer(item.revision),
    description: text(item.description),
    read: bool(item.read),
    write: bool(item.write),
    list: bool(item.list),
  }
}

function descriptors<T>(value: unknown, parse: (item: unknown) => T | null): T[] {
  if (!Array.isArray(value)) return []
  return value.map(parse).filter((item): item is T => item !== null)
}

export function parseConnectorInterface(value: unknown): ConnectorInterfaceDescriptor | null {
  const item = record(value)
  if (!item || !text(item.contractId)) return null
  return {
    kind: text(item.kind),
    contractId: text(item.contractId),
    name: text(item.name),
    description: text(item.description),
    artifactVersion: text(item.artifactVersion),
    artifactDigest: text(item.artifactDigest),
    commands: descriptors(item.commands, command),
    directories: descriptors(item.directories, directory),
  }
}

export function parseConnectorInterfaceJson(json: string): ConnectorInterfaceDescriptor | null {
  if (!json) return null
  try {
    return parseConnectorInterface(JSON.parse(json) as unknown)
  } catch {
    return null
  }
}

function setting(value: unknown): ConnectorSettingDescriptor | null {
  const item = record(value)
  if (!item || !text(item.name)) return null
  return {
    name: text(item.name),
    jsonName: text(item.jsonName),
    kind: text(item.kind),
    description: text(item.description),
    required: bool(item.required),
    defaultValue: text(item.default),
    enumValues: strings(item.enum),
  }
}

export function parseConnectorSettings(value: unknown): ConnectorSettingDescriptor[] | null {
  if (!Array.isArray(value)) return null
  const parsed = value.map(setting)
  return parsed.every((item): item is ConnectorSettingDescriptor => item !== null) ? parsed : null
}

export function connectorReadiness(readiness: string, translate?: ConnectorTranslate): {
  label: string
  severity: 'success' | 'warn' | 'danger' | 'secondary'
} {
  switch (readiness) {
    case 'ready': return { label: connectorMessage('connectors.common.readiness.ready', {}, translate), severity: 'success' }
    case 'needs_configuration': return { label: connectorMessage('connectors.common.readiness.needsConfiguration', {}, translate), severity: 'warn' }
    case 'incompatible_protocol': return { label: connectorMessage('connectors.common.readiness.incompatibleProtocol', {}, translate), severity: 'danger' }
    case 'unhealthy': return { label: connectorMessage('connectors.common.readiness.unhealthy', {}, translate), severity: 'danger' }
    case 'starting': return { label: connectorMessage('connectors.common.readiness.starting', {}, translate), severity: 'warn' }
    case 'offline': return { label: connectorMessage('connectors.common.readiness.offline', {}, translate), severity: 'secondary' }
    default: return { label: readiness || connectorMessage('connectors.common.readiness.unknown', {}, translate), severity: 'secondary' }
  }
}

export function connectorDisplayName(connector: Pick<ConnectorInfo, 'displayName' | 'name' | 'kind' | 'slug'>): string {
  return connector.displayName || connector.name || connector.kind || connector.slug
}

export function directoryAccess(
  directory: Pick<ConnectorDirectoryDescriptor, 'read' | 'write' | 'list'>,
  translate?: ConnectorTranslate,
): string {
  const access = []
  if (directory.read) access.push(connectorMessage('connectors.common.access.read', {}, translate))
  if (directory.write) access.push(connectorMessage('connectors.common.access.write', {}, translate))
  if (directory.list) access.push(connectorMessage('connectors.common.access.list', {}, translate))
  return access.join(', ')
}

export type ConnectorServiceMode = 'user' | 'system'
