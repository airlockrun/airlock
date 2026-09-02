import { timestampDate } from '@bufbuild/protobuf/wkt'
import type { Timestamp } from '@bufbuild/protobuf/wkt'
import type { JobInfo, JobProgressInfo } from '@/gen/airlock/v1/types_pb'
import type { AirlockI18nComposable } from '@/i18n'

type Translate = AirlockI18nComposable['t']
type FormatDate = AirlockI18nComposable['formatDate']

export function isActiveJob(job: JobInfo): boolean {
  return job.status === 'queued' || job.status === 'running'
}

export function jobStatusLabel(job: JobInfo, t: Translate): string {
  if (job.status === 'running' && job.cancelRequestedAt) return t('operations.job.status.cancelling')
  return jobStatusText(job.status, t)
}

export function jobStatusText(status: string, t: Translate): string {
  switch (status) {
    case 'queued': return t('operations.job.status.queued')
    case 'running': return t('operations.job.status.running')
    case 'succeeded': return t('operations.job.status.succeeded')
    case 'failed': return t('operations.job.status.failed')
    case 'cancelled': return t('operations.job.status.cancelled')
    case 'leased': return t('operations.job.status.leased')
    case 'retryable': return t('operations.job.status.retryable')
    case 'interrupted': return t('operations.job.status.interrupted')
    default: return status
  }
}

export function jobStatusSeverity(job: JobInfo): string {
  if (job.status === 'succeeded') return 'success'
  if (job.status === 'failed') return 'danger'
  if (job.status === 'running') return job.cancelRequestedAt ? 'warn' : 'info'
  if (job.status === 'queued') return 'warn'
  return 'secondary'
}

export function progressPercent(progress: JobProgressInfo): number | null {
  if (progress.total <= 0n) return null
  const percent = Number((progress.completed * 100n) / progress.total)
  return Math.max(0, Math.min(100, percent))
}

export function formatJobTimestamp(timestamp: Timestamp | undefined, formatDate: FormatDate): string {
  return timestamp ? formatDate(timestampDate(timestamp), {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  }) : '-'
}

export function formatJobJson(value: string): string {
  if (!value) return '-'
  try {
    return JSON.stringify(JSON.parse(value), null, 2)
  } catch {
    return value
  }
}
