import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { Transpiler } from 'bun'
import { expect, test } from 'bun:test'

function harness(options: { applied?: boolean, saveError?: boolean, syncError?: boolean, peers?: string[], syncRevision?: string, reloadError?: boolean } = {}) {
  const source = readFileSync(new URL('../src/views/SiteProtection.vue', import.meta.url), 'utf8')
  const script = source.split('<script setup lang="ts">')[1].split('</script>')[0].replace(/^import .*\n/gm, '')
  const policy = {
    modsecurity: 'On',
    crowdsec: 'on',
    appsec: 'block',
    paranoia_level: null,
    inbound_threshold: null,
    outbound_threshold: null,
    excluded_rule_ids: [],
    exceptions: [],
    blocked_paths: [],
    modsecurity_allowlist: [],
    crowdsec_allowlist: [],
  }
  const state = { revision: '10', replica: false, policy }
  const node = { id: 0 }
  const props = { name: 'example.test' }
  const calls: string[] = []
  let confirm: { onOk: () => Promise<void> } | undefined
  let afterSave = () => {}
  const component = runInNewContext(`${new Transpiler({ loader: 'ts' }).transformSync(script)}\n;({apply, synchronize, load, error, resultText, resultType, syncResult, saving, syncing})`, {
    defineProps: () => props,
    defineEmits: () => () => {},
    ref: (value: unknown) => ({ value }),
    computed: (get: (() => unknown) | { get: () => unknown }) => ({
      get value() {
        return typeof get === 'function'
          ? get()
          : get.get()
      },
    }),
    watch: () => {},
    onBeforeUnmount: () => {},
    useSettingsStore: () => ({ node }),
    canManageSecurity: (id: number) => id === 0,
    canSyncSavedPolicy: (value: typeof state | undefined, dirty: boolean) => !!value?.revision && !value.replica && !dirty,
    parseExcludedRules: () => [],
    validSitePolicy: () => true,
    App: {
      useApp: () => ({
        modal: {
          confirm: (value: typeof confirm) => { confirm = value },
        },
      }),
    },
    $gettext: (message: string) => message,
    getErrorMessage: (error: Error) => error.message,
    security: {
      site: async () => {
        calls.push('load')
        if (options.reloadError && state.revision === '11')
          throw new Error('State reload failed')
        return JSON.parse(JSON.stringify(state))
      },
      saveSite: async () => {
        calls.push('save')
        if (options.saveError)
          throw new Error('Validation failed')
        state.revision = '11'
        afterSave()
        return { applied: options.applied ?? true }
      },
      syncSite: async () => {
        calls.push('sync')
        if (options.syncError)
          throw new Error('Peer timed out')
        return {
          revision: options.syncRevision ?? '11',
          message: 'Peer results',
          atomic: false,
          results: (options.peers ?? ['applied', 'unchanged']).map((status, node_id) => ({
            node_id,
            node: `peer-${node_id}`,
            status,
            message: status,
            revision: '11',
          })),
        }
      },
    },
  })
  return {
    component,
    calls,
    node,
    props,
    state,
    confirmed: () => confirm!.onOk(),
    afterSave: (fn: () => void) => { afterSave = fn },
  }
}

test('one confirmed apply saves then automatically synchronizes the saved revision', async () => {
  const h = harness()
  await h.component.load()
  h.component.apply()
  expect(h.calls).toEqual(['load'])
  await h.confirmed()
  expect(h.calls).toEqual(['load', 'save', 'load', 'sync'])
  expect(h.component.resultType.value).toBe('success')
  expect(h.component.syncResult.value.results.length).toBe(2)
  expect(h.component.saving.value || h.component.syncing.value).toBe(false)
})

test('failed local validation never synchronizes peers', async () => {
  const h = harness({ saveError: true })
  await h.component.load()
  h.component.apply()
  await expect(h.confirmed()).rejects.toThrow('Validation failed')
  expect(h.calls).toEqual(['load', 'save'])
  expect(h.component.error.value).toBe('Validation failed')
})

test('unconfirmed local application never synchronizes peers or claims success', async () => {
  const h = harness({ applied: false })
  await h.component.load()
  h.component.apply()
  await h.confirmed()
  expect(h.calls.includes('sync')).toBe(false)
  expect(h.component.resultType.value).toBe('warning')
})

test('partial failure remains visible and sync retry does not save another revision', async () => {
  const h = harness({
    peers: ['applied', 'failed', 'unsupported'],
  })
  await h.component.load()
  h.component.apply()
  await h.confirmed()
  expect(h.component.resultType.value).toBe('warning')
  expect(h.component.syncResult.value.results.map((p: { status: string }) => p.status)).toEqual(['applied', 'failed', 'unsupported'])
  h.component.synchronize()
  await h.confirmed()
  expect(h.calls.filter(call => call === 'save').length).toBe(1)
  expect(h.calls.filter(call => call === 'sync').length).toBe(2)
})

test('transport errors and missing or mismatched confirmations cannot claim cluster success', async () => {
  for (const options of [
    { syncError: true },
    { peers: [] },
    { syncRevision: '12' },
  ]) {
    const h = harness(options)
    await h.component.load()
    h.component.apply()
    await h.confirmed()
    expect(h.component.resultType.value === 'success').toBe(false)
    if (options.syncError)
      expect(h.component.error.value).toContain('Saved locally, but synchronization is not confirmed')
    expect(h.component.saving.value || h.component.syncing.value).toBe(false)
  }
})

test('controller changes after confirmation or while saving prevent peer mutations', async () => {
  const before = harness()
  await before.component.load()
  before.component.apply()
  before.node.id = 3
  await expect(before.confirmed()).rejects.toThrow('controller changed')
  expect(before.calls).toEqual(['load'])

  const during = harness()
  await during.component.load()
  during.component.apply()
  during.afterSave(() => {
    during.node.id = 3
  })
  await during.confirmed()
  expect(during.calls).toEqual(['load', 'save'])
})

test('reload failure after a local save does not synchronize an unverified state', async () => {
  const h = harness({ reloadError: true })
  await h.component.load()
  h.component.apply()
  await h.confirmed()
  expect(h.calls).toEqual(['load', 'save', 'load'])
  expect(h.component.error.value).toContain('Saved locally, but synchronization is not confirmed')
  expect(h.component.resultType.value === 'success').toBe(false)
})

test('switching websites while saving does not synchronize the new website', async () => {
  const h = harness()
  await h.component.load()
  h.component.apply()
  h.afterSave(() => {
    h.props.name = 'other.test'
  })
  await h.confirmed()
  expect(h.calls).toEqual(['load', 'save'])
  expect(h.component.syncResult.value).toBeUndefined()
})
