import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { Transpiler } from 'bun'
import { expect, test } from 'bun:test'
import { canManageSecurity, crowdsecListResult, normalizeDecisions, normalizeScenarios, parseExcludedRules } from '../src/views/normalize'

// Exercise the component's actual refresh with unavailable endpoints that reject.
// No requests should reach these endpoints merely because the plugin is active.
test('refresh gates engine requests and clears stale settings when an integration disappears', async () => {
  let modsecurity = false
  const calls: string[] = []
  const source = readFileSync(new URL('../src/views/SecurityCenter.vue', import.meta.url), 'utf8')
  const script = source.split('<script setup lang="ts">')[1].split('</script>')[0].replace(/^import .*\n/gm, '')
  const javascript = new Transpiler({ loader: 'ts' }).transformSync(script)
  const component = runInNewContext(`${javascript}\n;({ refresh, sites, waf, selectedSite, siteError, wafError })`, {
    ref: (value: unknown) => ({ value }),
    reactive: (value: unknown) => value,
    computed: (get: () => unknown) => ({
      get value() { return get() },
    }),
    watch: () => {},
    onMounted: () => {},
    onBeforeUnmount: () => {},
    App: {
      useApp: () => ({ message: {}, modal: {} }),
    },
    useSettingsStore: () => ({
      node: { id: 0 },
    }),
    $gettext: (value: string) => value,
    canManageSecurity,
    crowdsecListResult,
    normalizeDecisions,
    normalizeScenarios,
    parseExcludedRules,
    getErrorMessage: (error: Error) => error.message,
    security: {
      status: async () => ({ enabled: true, crowdsec_enabled: false, modsecurity_enabled: modsecurity }),
      sites: async () => {
        calls.push('sites')
        if (!modsecurity)
          throw new Error('503 unavailable')
        return {
          items: [
            { name: 'demo.conf', server_names: [] },
          ],
        }
      },
      modsecurity: async () => {
        calls.push('waf')
        if (!modsecurity)
          throw new Error('503 unavailable')
        return { mode: 'On', excluded_rule_ids: [] }
      },
      decisions: async () => { throw new Error('CrowdSec must not be called') },
      scenarios: async () => { throw new Error('CrowdSec must not be called') },
    },
  })
  await component.refresh()
  expect(calls).toEqual([])
  expect(component.siteError.value).toBe('')
  modsecurity = true
  await component.refresh()
  expect(calls).toEqual(['sites', 'waf'])
  expect(component.sites.value.length).toBe(1)
  component.selectedSite.value = 'demo.conf'
  modsecurity = false
  await component.refresh()
  expect(calls).toEqual(['sites', 'waf'])
  expect(component.sites.value.length).toBe(0)
  expect(component.selectedSite.value).toBe('')
  expect(component.waf.value).toBeUndefined()
  expect(component.wafError.value).toBe('')
})
