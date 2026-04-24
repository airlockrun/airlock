import type { Value, Struct } from '@bufbuild/protobuf/wkt'

/** Recursively unwrap a protobuf Value to a plain JS value. */
export function unwrapValue(v: Value | undefined): unknown {
  if (!v || !v.kind) return undefined
  switch (v.kind.case) {
    case 'nullValue':
      return null
    case 'numberValue':
      return v.kind.value
    case 'stringValue':
      return v.kind.value
    case 'boolValue':
      return v.kind.value
    case 'structValue':
      return unwrapStruct(v.kind.value)
    case 'listValue':
      return v.kind.value.values.map(unwrapValue)
    default:
      return undefined
  }
}

/** Unwrap a protobuf Struct to a plain JS object. */
export function unwrapStruct(s: Struct | undefined): Record<string, unknown> {
  if (!s) return {}
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(s.fields)) {
    out[key] = unwrapValue(value)
  }
  return out
}
