import type { SecurityBulkJob } from '@/api/security_center'

export function isBulkRunning(job?: SecurityBulkJob | null): boolean {
  return !!job && ['queued', 'running', 'validating'].includes(job.state)
}

/** Downloaded/staged rules are not yet active: reserve completion for validation. */
export function bulkProgress(job?: SecurityBulkJob | null): number {
  if (!job)
    return 0
  if (job.state === 'succeeded')
    return 100
  if (!Number.isFinite(job.completed) || !Number.isFinite(job.total) || job.total <= 0)
    return 0
  return Math.min(95, Math.max(0, Math.round(job.completed / job.total * 95)))
}
