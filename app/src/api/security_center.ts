import { http } from '@uozi-admin/request'

export interface CrowdSecSharing {
  configured: boolean
  enabled: boolean | null
  editable: boolean
  runtime_verified: boolean
  message: string
  applied?: boolean
}

export interface SecurityStatus {
  enabled: boolean
  crowdsec_enabled: boolean
  modsecurity_enabled: boolean
  scenario_changes_enabled: boolean
  runtime_integration_verified: boolean
}

export interface ModSecurityConfig {
  crowdsec_enabled: boolean
  mode: 'Off' | 'DetectionOnly' | 'On'
  paranoia_level: number
  inbound_threshold: number
  outbound_threshold: number
  excluded_rule_ids: number[]
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
  modsecurity: 'inherit' | ModSecurityConfig['mode']
  crowdsec: 'inherit' | 'on' | 'off'
  exceptions: RuleException[]
  blocked_paths: string[]
  paranoia_level: number | null
  inbound_threshold: number | null
  outbound_threshold: number | null
  excluded_rule_ids: number[]
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
  effective: { modsecurity: ModSecurityConfig, crowdsec: boolean }
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

const base = '/security-center'
const options = { skipErrHandling: true, skipNodeProxy: true }

export default {
  sharing: (): Promise<CrowdSecSharing> => http.get(`${base}/crowdsec/sharing`, options),
  saveSharing: (enabled: boolean): Promise<CrowdSecSharing> => http.put(`${base}/crowdsec/sharing`, { enabled }, options),
  templates: (): Promise<{ items: SecurityTemplate[] }> => http.get(`${base}/templates`, options),
  saveTemplate: (id: string, payload: Pick<SecurityTemplate, 'name' | 'description' | 'policy'>): Promise<SecurityMutation> => http.put(`${base}/templates/${encodeURIComponent(id)}`, payload, options),
  deleteTemplate: (id: string): Promise<SecurityMutation> => http.delete(`${base}/templates/${encodeURIComponent(id)}`, options),
  events: (params: { source: string, vhost?: string, node?: string, since: string, limit: number }): Promise<SecurityEvents> => http.get(`${base}/events`, { ...options, params }),
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
