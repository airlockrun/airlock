import { timestampDate } from '@bufbuild/protobuf/wkt'
import type { Timestamp } from '@bufbuild/protobuf/wkt'
import type { JobInfo, JobProgressInfo } from '@/gen/airlock/v1/types_pb'

export function isActiveJob(job: JobInfo): boolean {
  return job.status === 'queued' || job.status === 'running'
}

export function jobStatusLabel(job: JobInfo): string {
  return job.status === 'running' && job.cancelRequestedAt ? 'Cancelling' : job.status
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

export function formatJobTimestamp(timestamp?: Timestamp): string {
  return timestamp ? timestampDate(timestamp).toLocaleString() : '-'
}

export function formatJobJson(value: string): string {
  if (!value) return '-'
  try {
    return JSON.stringify(JSON.parse(value), null, 2)
  } catch {
    return value
  }
}
