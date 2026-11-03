import type { RuleException, SecurityEvent, SiteSecurityPolicy, SiteSecurityState } from '@/api/security_center'

export function inheritedSitePolicy(): SiteSecurityPolicy {
  return {
    modsecurity: 'inherit',
    crowdsec: 'inherit',
    paranoia_level: null,
    inbound_threshold: null,
    outbound_threshold: null,
    excluded_rule_ids: [],
    modsecurity_allowlist: [],
    crowdsec_allowlist: [],
    exceptions: [],
    blocked_paths: [],
  }
}

export function validSitePolicy(policy: SiteSecurityPolicy | undefined): boolean {
  return !!policy
    && [
      'inherit',
      'Off',
      'On',
      'DetectionOnly',
    ].includes(policy.modsecurity)
    && ['inherit', 'on', 'off'].includes(policy.crowdsec)
    && (policy.paranoia_level === null || [1, 2, 3, 4].includes(policy.paranoia_level))
    && [policy.inbound_threshold, policy.outbound_threshold].every(value => value === null || (Number.isInteger(value) && value >= 1 && value <= 1000))
    && policy.exceptions.length <= 100 && policy.exceptions.every(validException)
    && policy.blocked_paths.length <= 100 && policy.blocked_paths.every(validExactPath)
    && new Set(policy.blocked_paths).size === policy.blocked_paths.length
    && validAllowlistDraft(policy.modsecurity_allowlist)
    && validAllowlistDraft(policy.crowdsec_allowlist)
    && policy.excluded_rule_ids.length <= 200
    && policy.excluded_rule_ids.every(value => Number.isInteger(value) && value >= 900000 && value <= 999999)
}

// Network parsing is authoritative on the server before configuration is applied.
export function validAllowlistDraft(entries: string[] | undefined): boolean {
  return entries === undefined || (Array.isArray(entries) && entries.length <= 400
    && entries.every(entry => typeof entry === 'string' && /^[\da-f:./]{1,64}$/i.test(entry)))
}

export function validExactPath(path: string): boolean {
  return path.length <= 512 && /^\/[\w/.,~!$&()*+:=@%-]*$/.test(path)
}

export function validException(exception: RuleException): boolean {
  return Number.isInteger(exception.rule_id) && exception.rule_id >= 900000 && exception.rule_id <= 999999
    && !!(exception.path || exception.parameter)
    && (!exception.path || validExactPath(exception.path))
    && (!exception.parameter || /^[\w.-]{1,100}$/.test(exception.parameter))
}

export function exceptionFromEvent(event: SecurityEvent): RuleException {
  return {
    rule_id: event.rule_id ?? 0,
    path: event.path?.split('?')[0] || undefined,
    parameter: event.parameter?.replace(/^ARGS:/, '') || undefined,
  }
}

export function canSyncSavedPolicy(state: Pick<SiteSecurityState, 'revision' | 'replica'> | undefined, dirty: boolean): boolean {
  return !!state?.revision && !state.replica && !dirty
}

export function cloneSitePolicy(policy: SiteSecurityPolicy): SiteSecurityPolicy {
  return {
    ...policy,
    excluded_rule_ids: [...policy.excluded_rule_ids],
    modsecurity_allowlist: [
      ...(policy.modsecurity_allowlist ?? []),
    ],
    crowdsec_allowlist: [
      ...(policy.crowdsec_allowlist ?? []),
    ],
    blocked_paths: [...policy.blocked_paths],
    exceptions: policy.exceptions.map(item => ({ ...item })),
  }
}

export function validTemplatePolicy(policy: SiteSecurityPolicy | undefined): boolean {
  return validSitePolicy(policy)
}

export function templateChanges(before: SiteSecurityPolicy, after: SiteSecurityPolicy): { field: string, before: string, after: string }[] {
  return (Object.keys(after) as (keyof SiteSecurityPolicy)[])
    .filter(field => JSON.stringify(before[field]) !== JSON.stringify(after[field]))
    .map(field => ({
      field,
      before: JSON.stringify(before[field]),
      after: JSON.stringify(after[field]),
    }))
}
