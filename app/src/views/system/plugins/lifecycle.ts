/** Deactivation hooks can change live services even without certificate usage. */
export function requiresDisableConfirmation(permissions: string[], usageTotal = 0): boolean {
  return permissions.includes('lifecycle.deactivate') || usageTotal > 0
}
