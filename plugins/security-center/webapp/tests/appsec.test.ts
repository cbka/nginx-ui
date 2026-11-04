import { expect, test } from 'bun:test'
import { cloneSitePolicy, inheritedSitePolicy, validSitePolicy } from '../src/views/sitePolicy'

test('AppSec inherits independently of ModSecurity and retains explicit modes', () => {
  const policy = inheritedSitePolicy()
  expect(policy.appsec).toBe('inherit')
  for (const mode of ['off', 'detection', 'block'] as const) {
    policy.appsec = mode
    policy.modsecurity = 'Off'
    expect(validSitePolicy(policy)).toBe(true)
    expect(cloneSitePolicy(policy).appsec).toBe(mode)
  }
  expect(validSitePolicy({ ...policy, appsec: 'enabled' } as never)).toBe(false)
})
