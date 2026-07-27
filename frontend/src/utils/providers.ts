export const OPENAI_COMPATIBLE_PROVIDER_ID = 'openai-compatible'

export type ProviderSlugRow = {
  id?: string
  providerId: string
  slug: string
}

export type ProviderRequestSession = {
  generation: number
  providerId: string
}

export function nextProviderRequestSession(
  current: ProviderRequestSession,
  providerId: string,
): ProviderRequestSession {
  return { generation: current.generation + 1, providerId }
}

export function isCurrentProviderRequest(
  current: ProviderRequestSession,
  request: ProviderRequestSession,
): boolean {
  return current.generation === request.generation && current.providerId === request.providerId
}

export function setRowPending(current: ReadonlySet<string>, id: string, pending: boolean): Set<string> {
  const next = new Set(current)
  if (pending) next.add(id)
  else next.delete(id)
  return next
}

export function toProviderSlug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 63)
    .replace(/-$/g, '')
}

export function uniqueProviderSlug(
  providerId: string,
  preferred: string,
  rows: ProviderSlugRow[],
  excludeId = '',
): string {
  const base = toProviderSlug(preferred) || toProviderSlug(providerId)
  const used = new Set(
    rows
      .filter((row) => row.providerId === providerId && row.id !== excludeId)
      .map((row) => row.slug),
  )
  if (!used.has(base)) return base

  for (let suffix = 2; ; suffix++) {
    const suffixText = `-${suffix}`
    const candidate = base.slice(0, 63 - suffixText.length).replace(/-$/g, '') + suffixText
    if (!used.has(candidate)) return candidate
  }
}

export function isValidProviderSlug(value: string): boolean {
  return value.length <= 63 && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value)
}

export function isValidProviderURL(value: string, required: boolean): boolean {
  const raw = value.trim()
  if (!raw) return !required
  try {
    const url = new URL(raw)
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      !!url.host &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash
    )
  } catch {
    return false
  }
}
