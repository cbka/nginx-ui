import type { CrowdSecSharing } from '@/api/security_center'

export function sharingConfiguredValue(status?: CrowdSecSharing): boolean | null {
  return status?.configured && typeof status.enabled === 'boolean'
    ? status.enabled
    : null
}

export function canApplySharing(status: CrowdSecSharing | undefined, desired: boolean | null): boolean {
  const current = sharingConfiguredValue(status)
  return !!status?.editable && current !== null && desired !== null && current !== desired
}
