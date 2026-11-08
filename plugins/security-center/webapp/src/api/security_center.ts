import { http } from '@/runtime'

export interface CrowdSecSharing {
  configured: boolean
  enabled: boolean | null
  editable: boolean
  runtime_verified: boolean
  message: string
  applied?: boolean
}

export type AppSecMode = 'off' | 'detection' | 'block'

export interface SecurityStatus {
  enabled: boolean
  crowdsec_enabled: boolean
  modsecurity_enabled: boolean
  events_configured: boolean
  scenario_changes_enabled: boolean
  runtime_integration_verified: boolean
  appsec_enabled?: boolean
}

export interface AppSecHubItem {
  name: string
  description?: string
  version?: string
  status?: string
  available: boolean
  installed: boolean
  loaded?: boolean | null
  update_available?: boolean
  tainted?: boolean
  editable?: boolean
}

export interface AppSecStatus {
  enabled: boolean
  ready: boolean
  detection_ready?: boolean
  detection_listen_addr?: string
  listen_addr?: string
  configs: AppSecHubItem[]
  collections: AppSecHubItem[]
  rules: AppSecHubItem[]
  rule_count: number
  runtime_integration_verified?: boolean
  site_counts?: { off: number, detection: number, block: number }
}

export interface ModSecurityConfig {
  appsec_mode?: AppSecMode
  crowdsec_enabled: boolean
  mode: 'Off' | 'DetectionOnly' | 'On'
  paranoia_level: number
  inbound_threshold: number
  outbound_threshold: number
  excluded_rule_ids: number[]
  modsecurity_allowlist?: string[]
  crowdsec_allowlist?: string[]
}

export interface SecuritySite {
  name: string
  server_names: string[]
}

export interface RuleException {
  rule_id: number
  path?: string
  parameter?: string
}

export interface SiteSecurityPolicy {
  appsec?: 'inherit' | AppSecMode
  modsecurity: 'inherit' | ModSecurityConfig['mode']
  crowdsec: 'inherit' | 'on' | 'off'
  exceptions: RuleException[]
  blocked_paths: string[]
  paranoia_level: number | null
  inbound_threshold: number | null
  outbound_threshold: number | null
  excluded_rule_ids: number[]
  modsecurity_allowlist?: string[]
  crowdsec_allowlist?: string[]
}

export interface SecurityTemplate {
  id: string
  name: string
  description: string
  builtin: boolean
  policy: SiteSecurityPolicy
}

export interface SiteSecurityState {
  revision: string
  owner: string
  replica: boolean
  policy: SiteSecurityPolicy
  effective: { modsecurity: ModSecurityConfig, crowdsec: boolean, appsec?: AppSecMode }
}

export interface SecurityEvent {
  timestamp: string
  source: 'modsecurity' | 'crowdsec'
  vhost: string
  node: string
  event_id: string
  rule_id?: number
  scenario?: string
  message: string
  method?: string
  path?: string
  parameter?: string
  client_ip?: string
  action?: string
  transaction_id?: string
}

export interface SecurityEvents {
  items: SecurityEvent[]
  limited: boolean
  limit: number
  since: string
  cluster_completeness_verified: boolean
}

export interface SiteSyncResult {
  results: { node_id: number, node: string, status: 'applied' | 'unchanged' | 'failed' | 'unsupported', message: string, revision: string }[]
  revision: string
  atomic: boolean
  message: string
}

export interface SecurityMutation {
  message: string
  applied?: boolean
}

export type SecurityBulkKind = 'scenarios' | 'appsec'
export type SecurityBulkAction = 'install' | 'activate' | 'skip'
export interface SecurityBulkItem {
  name: string
  action: SecurityBulkAction
  reason: string
  state?: 'pending' | 'installing' | 'staged' | 'succeeded' | 'skipped' | 'failed' | 'rolled_back'
}
export interface SecurityBulkPreview {
  kind: SecurityBulkKind
  preview_id: string
  items: SecurityBulkItem[]
  eligible_count: number
  skipped_count: number
}
export interface SecurityBulkJob {
  id: string
  kind: SecurityBulkKind
  state: 'queued' | 'running' | 'validating' | 'succeeded' | 'failed' | 'interrupted'
  completed: number
  total: number
  items: SecurityBulkItem[]
  message: string
  created_at: string
  updated_at: string
}

const base = '/security-center'
const options = {}

export default {
  bulkPreview: (kind: SecurityBulkKind): Promise<SecurityBulkPreview> => http.get(`${base}/crowdsec/bulk/preview`, {
    ...options,
    params: { kind },
  }),
  startBulk: (kind: SecurityBulkKind, previewId: string): Promise<SecurityBulkJob> => http.post(`${base}/crowdsec/bulk/jobs`, { kind, preview_id: previewId }, options),
  bulkJob: (id: string): Promise<SecurityBulkJob> => http.get(`${base}/crowdsec/bulk/jobs/${encodeURIComponent(id)}`, options),
  currentBulkJob: (): Promise<SecurityBulkJob | null> => http.get(`${base}/crowdsec/bulk/jobs/current`, options),
  changeAppSecRule: (name: string, action: 'install' | 'activate'): Promise<SecurityMutation> => http.post(`${base}/crowdsec/appsec/rules`, { name, action }, options),
  appsec: (): Promise<AppSecStatus> => http.get(`${base}/crowdsec/appsec`, options),
  sharing: (): Promise<CrowdSecSharing> => http.get(`${base}/crowdsec/sharing`, options),
  saveSharing: (enabled: boolean): Promise<CrowdSecSharing> => http.put(`${base}/crowdsec/sharing`, { enabled }, options),
  templates: (): Promise<{ items: SecurityTemplate[] }> => http.get(`${base}/templates`, options),
  saveTemplate: (id: string, payload: Pick<SecurityTemplate, 'name' | 'description' | 'policy'>): Promise<SecurityMutation> => http.put(`${base}/templates/${encodeURIComponent(id)}`, payload, options),
  deleteTemplate: (id: string): Promise<SecurityMutation> => http.delete(`${base}/templates/${encodeURIComponent(id)}`, options),
  events: (params: { source: string, vhost?: string, node?: string, request_id?: string, since: string, limit: number }): Promise<SecurityEvents> => http.get(`${base}/events`, { ...options, params }),
  rules: (): Promise<{ items: { id: number, message: string, file: string }[], truncated: boolean }> => http.get(`${base}/modsecurity/rules`, options),
  sites: (): Promise<{ items: SecuritySite[] }> => http.get(`${base}/sites`, options),
  site: (name: string): Promise<SiteSecurityState> => http.get(`${base}/sites/${encodeURIComponent(name)}`, options),
  syncSite: (name: string): Promise<SiteSyncResult> => http.post(`${base}/sites/${encodeURIComponent(name)}/sync`, undefined, options),
  saveSite: (name: string, policy: SiteSecurityPolicy): Promise<SecurityMutation> => http.put(`${base}/sites/${encodeURIComponent(name)}`, policy, options),
  status: (): Promise<SecurityStatus> => http.get(`${base}/status`, options),
  decisions: (): Promise<{ items: unknown }> => http.get(`${base}/crowdsec/decisions`, options),
  addDecision: (payload: { ip: string, duration: string, reason: string }): Promise<SecurityMutation> =>
    http.post(`${base}/crowdsec/decisions`, payload, options),
  deleteDecision: (id: number): Promise<SecurityMutation> =>
    http.delete(`${base}/crowdsec/decisions/${id}`, options),
  scenarios: (): Promise<{ items: unknown }> => http.get(`${base}/crowdsec/scenarios`, options),
  changeScenario: (name: string, action: 'install' | 'remove'): Promise<SecurityMutation> =>
    http.post(`${base}/crowdsec/scenarios`, { name, action }, options),
  modsecurity: (): Promise<ModSecurityConfig> => http.get(`${base}/modsecurity`, options),
  saveModsecurity: (payload: ModSecurityConfig): Promise<SecurityMutation> =>
    http.put(`${base}/modsecurity`, payload, options),
}
