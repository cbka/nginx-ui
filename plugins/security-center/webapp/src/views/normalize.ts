export interface Decision {
  id: number
  value: string
  type: string
  scope: string
  origin: string
  duration: string
  reason: string
}

export interface Scenario {
  name: string
  status: string
  version: string
  installed: boolean
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function text(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number'
    ? String(value)
    : ''
}

// cscli versions return either flat decisions or alerts containing decisions.
export function normalizeDecisions(input: unknown): Decision[] {
  if (!Array.isArray(input))
    return []
  return input.flatMap(item => {
    const alert = record(item)
    const decisions = Array.isArray(alert.decisions)
      ? alert.decisions
      : [item]
    return decisions.flatMap(raw => {
      const decision = record(raw)
      const id = Number(decision.id)
      if (!Number.isSafeInteger(id) || id <= 0)
        return []
      return [
        {
          id,
          value: text(decision.value),
          type: text(decision.type),
          scope: text(decision.scope),
          origin: text(decision.origin),
          duration: text(decision.duration),
          reason: text(decision.scenario || decision.reason || alert.scenario),
        },
      ]
    })
  })
}

export function normalizeScenarios(input: unknown): Scenario[] {
  const data = record(input)
  const entries = Array.isArray(input)
    ? input
    : Array.isArray(data.scenarios)
      ? data.scenarios
      : Object.entries(data).map(([name, item]) => ({
          name,
          ...record(item),
        }))
  return entries.flatMap(raw => {
    const item = record(raw)
    const name = text(item.name)
    if (!name)
      return []
    const local = record(item.local)
    const status = text(item.status)
    return [
      {
        name,
        status,
        version: text(item.local_version || item.version || local.version),
        installed: typeof item.installed === 'boolean'
          ? item.installed
          : typeof local.installed === 'boolean'
            ? local.installed
            : status.toLowerCase().split(/[,\s]+/).some(flag => flag === 'enabled' || flag === 'installed'),
      },
    ]
  })
}

export function parseExcludedRules(value: string): number[] | undefined {
  if (!value.trim())
    return []
  const tokens = value.trim().split(/[\s,]+/)
  if (tokens.some(token => !/^\d+$/.test(token)))
    return undefined
  const ids = tokens.map(Number)
  if (ids.some(id => !Number.isSafeInteger(id) || id < 900000 || id > 999999))
    return undefined
  const unique = [
    ...new Set(ids),
  ]
  return unique.length <= 200
    ? unique
    : undefined
}

// Privileged integrations run only on the local controller, never via a selected peer.
export function canManageSecurity(nodeId: number): boolean {
  return nodeId === 0
}

// A failed optional CLI capability must not mark another healthy list unavailable.
export function crowdsecListResult<T>(result: PromiseSettledResult<{ items: unknown }>, normalize: (input: unknown) => T[], errorMessage: (error: unknown) => string): { items: T[], error: string } {
  return result.status === 'fulfilled'
    ? {
        items: normalize(result.value.items),
        error: '',
      }
    : {
        items: [],
        error: errorMessage(result.reason),
      }
}
