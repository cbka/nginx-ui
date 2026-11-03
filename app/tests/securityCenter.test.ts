import { describe, expect, test } from 'bun:test'
import { canManageSecurity, crowdsecListResult, normalizeDecisions, normalizeScenarios, parseExcludedRules } from '../../plugins/security-center/webapp/src/views/normalize'
import { canApplySharing, sharingConfiguredValue } from '../../plugins/security-center/webapp/src/views/sharing'
import { canSyncSavedPolicy, cloneSitePolicy, exceptionFromEvent, inheritedSitePolicy, templateChanges, validExactPath, validException, validSitePolicy, validTemplatePolicy } from '../../plugins/security-center/webapp/src/views/sitePolicy'

describe('Security Center CLI responses', () => {
  test('normalizes nested alerts without losing decision IDs or reasons', () => {
    expect(normalizeDecisions([
      {
        scenario: 'crowdsecurity/ssh-bf',
        decisions: [
          {
            id: 23,
            value: '192.0.2.1',
            scope: 'Ip',
            type: 'ban',
          },
        ],
      },
    ]))
      .toEqual([
        {
          id: 23,
          value: '192.0.2.1',
          scope: 'Ip',
          type: 'ban',
          reason: 'crowdsecurity/ssh-bf',
          origin: '',
          duration: '',
        },
      ])
  })
  test('flat responses are supported; invalid delete targets are excluded', () => {
    expect(normalizeDecisions([
      { id: '5', value: '2001:db8::1' },
      { id: '../other' },
      { id: 0 },
    ]).map(item => item.id)).toEqual([5])
    expect(normalizeDecisions(null)).toEqual([])
  })
  test('supports scenario arrays and cscli keyed structures', () => {
    expect(normalizeScenarios({
      scenarios: [
        { name: 'crowdsecurity/ssh-bf', status: 'enabled', local_version: '1.2' },
      ],
    })[0])
      .toEqual({
        name: 'crowdsecurity/ssh-bf',
        status: 'enabled',
        version: '1.2',
        installed: true,
      })
    expect(normalizeScenarios({
      'crowdsecurity/ssh-bf': {
        local: { installed: true, version: '1.3' },
      },
    })[0].installed).toBe(true)
    expect(normalizeScenarios([
      { name: 'crowdsecurity/ssh-bf', status: 'disabled' },
    ])[0].installed).toBe(false)
  })
})

describe('OWASP CRS exclusions', () => {
  test('empty text removes exclusions and duplicate IDs are collapsed', () => {
    expect(parseExcludedRules(' ')).toEqual([])
    expect(parseExcludedRules('920350, 942100\n920350')).toEqual([920350, 942100])
  })
  test('rejects injected configuration, non CRS IDs and oversized lists', () => {
    for (const value of [
      '920350; SecRuleEngine Off',
      '920350\nInclude /tmp/x',
      '-920350',
      '1e6',
      '42',
      '1000000',
    ])
      expect(parseExcludedRules(value)).toBeUndefined()
    expect(parseExcludedRules(Array.from({ length: 201 }, (_, i) => 900000 + i).join(','))).toBeUndefined()
  })
})

test('only the local controller permits privileged security management', () => {
  expect(canManageSecurity(0)).toBe(true)
  expect(canManageSecurity(1)).toBe(false)
  expect(canManageSecurity(-1)).toBe(false)
  expect(canManageSecurity(Number.NaN)).toBe(false)
})

describe('website policy inheritance', () => {
  test('reset preserves inheritance instead of copying fixed global defaults', () => {
    const policy = inheritedSitePolicy()
    expect(policy).toEqual({
      modsecurity: 'inherit',
      crowdsec: 'inherit',
      paranoia_level: null,
      inbound_threshold: null,
      outbound_threshold: null,
      excluded_rule_ids: [],
      exceptions: [],
      blocked_paths: [],
    })
    expect(validSitePolicy(policy)).toBe(true)
  })
  test('validates overrides and does not coerce blank fields to zero', () => {
    const policy = inheritedSitePolicy()
    expect(validSitePolicy({ ...policy, inbound_threshold: 0 })).toBe(false)
    expect(validSitePolicy({ ...policy, paranoia_level: 5 })).toBe(false)
    expect(validSitePolicy({
      ...policy,
      excluded_rule_ids: [42],
    })).toBe(false)
    expect(validSitePolicy({
      ...policy,
      crowdsec: 'off',
      modsecurity: 'DetectionOnly',
      paranoia_level: 2,
      excluded_rule_ids: [942100],
    })).toBe(true)
  })
})

describe('event-derived rule scope', () => {
  test('strips query strings and ARGS prefix without silently accepting headers', () => {
    const event = {
      timestamp: '',
      source: 'modsecurity' as const,
      vhost: 'site.conf',
      node: 'node1',
      event_id: '1',
      message: '',
      rule_id: 942100,
      path: '/search?q=foo',
      parameter: 'ARGS:q',
    }
    expect(exceptionFromEvent(event)).toEqual({ rule_id: 942100, path: '/search', parameter: 'q' })
    expect(validException(exceptionFromEvent(event))).toBe(true)
    expect(validException(exceptionFromEvent({ ...event, parameter: 'REQUEST_HEADERS:Cookie' }))).toBe(false)
  })
  test('refuses global unscoped exceptions and injected rule paths', () => {
    expect(validException({ rule_id: 942100 })).toBe(false)
    expect(validExactPath('/api/search')).toBe(true)
    expect(validExactPath('/api/search?q=x')).toBe(false)
    expect(validExactPath('/x" deny,status:403')).toBe(false)
    expect(validException({ rule_id: 942100, parameter: 'q\nSecRuleEngine Off' })).toBe(false)
    expect(validSitePolicy({
      ...inheritedSitePolicy(),
      blocked_paths: ['/admin', '/admin'],
    })).toBe(false)
  })
})

test('peer synchronization never exports an unsaved draft or a replica', () => {
  expect(canSyncSavedPolicy(undefined, false)).toBe(false)
  expect(canSyncSavedPolicy({ revision: '', replica: false }, false)).toBe(false)
  expect(canSyncSavedPolicy({ revision: 'saved-hash', replica: false }, true)).toBe(false)
  expect(canSyncSavedPolicy({ revision: 'saved-hash', replica: true }, false)).toBe(false)
  expect(canSyncSavedPolicy({ revision: 'saved-hash', replica: false }, false)).toBe(true)
})

describe('Reusable site security templates', () => {
  test('custom templates preserve every valid site policy without silently changing protection', () => {
    const base = {
      ...inheritedSitePolicy(),
      modsecurity: 'On' as const,
    }
    expect(validTemplatePolicy(base)).toBe(true)
    const permissive = {
      ...base,
      modsecurity: 'Off' as const,
      crowdsec: 'off' as const,
      excluded_rule_ids: [942100],
    }
    expect(cloneSitePolicy(permissive)).toEqual(permissive)
    expect(validTemplatePolicy({ ...base, modsecurity: 'inherit' })).toBe(true)
    expect(validTemplatePolicy({ ...base, modsecurity: 'Off' })).toBe(true)
    expect(validTemplatePolicy({ ...base, crowdsec: 'off' })).toBe(true)
    expect(validTemplatePolicy({
      ...base,
      excluded_rule_ids: [942100],
    })).toBe(true)
    expect(validTemplatePolicy({
      ...base,
      exceptions: [
        { rule_id: 942100, path: '/api/search', parameter: 'q' },
      ],
    })).toBe(true)
  })
  test('template drafts are independent and comparison includes removed exceptions', () => {
    const original = {
      ...inheritedSitePolicy(),
      exceptions: [
        { rule_id: 942100, path: '/search' },
      ],
      blocked_paths: ['/old'],
    }
    const draft = cloneSitePolicy(original)
    draft.exceptions[0].path = '/new'
    draft.blocked_paths.push('/extra')
    expect(original.exceptions[0].path).toBe('/search')
    expect(original.blocked_paths).toEqual(['/old'])
    const changes = templateChanges(original, inheritedSitePolicy())
    expect(changes.map(change => change.field)).toEqual(['exceptions', 'blocked_paths'])
    expect(changes[0].after).toBe('[]')
  })
})

describe('Community signal sharing configuration', () => {
  const configured = {
    configured: true,
    enabled: false,
    editable: true,
    runtime_verified: false,
    message: 'configuration only',
  }
  test('unknown or unavailable integration never masquerades as disabled', () => {
    expect(sharingConfiguredValue()).toBe(null)
    expect(sharingConfiguredValue({ ...configured, configured: false })).toBe(null)
    expect(sharingConfiguredValue({ ...configured, enabled: null })).toBe(null)
    expect(sharingConfiguredValue(configured)).toBe(false)
    expect(sharingConfiguredValue({ ...configured, enabled: true })).toBe(true)
  })
  test('only an editable known configuration with an explicit change can be applied', () => {
    expect(canApplySharing(configured, true)).toBe(true)
    expect(canApplySharing(configured, false)).toBe(false)
    expect(canApplySharing(configured, null)).toBe(false)
    expect(canApplySharing({ ...configured, editable: false }, true)).toBe(false)
    expect(canApplySharing({ ...configured, configured: false }, true)).toBe(false)
    expect(canApplySharing({ ...configured, enabled: null }, true)).toBe(false)
  })
})

test('CrowdSec partial failures do not mark a healthy empty decision list unavailable', () => {
  const healthy = {
    status: 'fulfilled' as const,
    value: { items: [] },
  }
  const failed = { status: 'rejected' as const, reason: 'scenario capability unavailable' }
  const format = (error: unknown) => String(error)
  expect(crowdsecListResult(healthy, normalizeDecisions, format)).toEqual({ items: [], error: '' })
  expect(crowdsecListResult(failed, normalizeScenarios, format)).toEqual({ items: [], error: 'scenario capability unavailable' })
  expect(crowdsecListResult(healthy, normalizeScenarios, format)).toEqual({ items: [], error: '' })
  expect(crowdsecListResult(failed, normalizeDecisions, format).error).not.toBe('')
})
