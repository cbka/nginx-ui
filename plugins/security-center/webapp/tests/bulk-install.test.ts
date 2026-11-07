import type { SecurityBulkJob } from '../src/api/security_center'
import { Transpiler } from 'bun'
import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { bulkProgress, isBulkRunning } from '../src/views/bulkInstall'

const pendingJob: SecurityBulkJob = {
  id: 'job-1',
  kind: 'appsec',
  state: 'running',
  completed: 0,
  total: 2,
  items: [
    {
      name: 'crowdsecurity/vpatch-test',
      action: 'install',
      reason: '',
      state: 'installing',
    },
  ],
  message: '',
  created_at: '2026-11-07T12:00:00Z',
  updated_at: '2026-11-07T12:00:00Z',
}
function harness() {
  const source = readFileSync(new URL('../src/views/BulkInstall.vue', import.meta.url), 'utf8')
  const script = source.split('<script setup lang="ts">')[1].split('</script>')[0].replace(/^import .*\n/gm, '')
  const node = { id: 0 }
  const props = { kind: 'appsec', disabled: false }
  const events: unknown[][] = []
  const calls: string[] = []
  const hooks: (() => void)[] = []
  const watches: (() => void)[] = []
  let previewWait: Promise<void> | undefined
  let releasePreview = () => {}
  let current: SecurityBulkJob | null = null
  let failPreview = false
  let failStart = false
  let failPoll = false
  let statusFail = false
  const component = runInNewContext(`${new Transpiler({ loader: 'ts' }).transformSync(script)}\n;({show, prepare, start, recover, poll, preview, job, error, loading, starting})`, {
    defineProps: () => props,
    defineEmits: () => (...args: unknown[]) => events.push(args),
    ref: (value: unknown) => ({ value }),
    computed: (get: () => unknown) => ({
      get value() { return get() },
    }),
    watch: (_source: unknown, fn: () => void) => watches.push(fn),
    onMounted: () => {},
    onBeforeUnmount: (fn: () => void) => hooks.push(fn),
    setTimeout: () => 1,
    clearTimeout: () => {},
    useSettingsStore: () => ({ node }),
    canManageSecurity: (id: number) => id === 0,
    $gettext: (message: string) => message,
    getErrorMessage: (error: Error) => error.message,
    isBulkRunning,
    bulkProgress,
    security: {
      currentBulkJob: async () => {
        calls.push('current')
        if (statusFail)
          throw new Error('Status offline')
        return current
      },
      bulkPreview: async () => {
        calls.push('preview')
        await previewWait
        if (failPreview)
          throw new Error('Catalog offline')
        return {
          kind: 'appsec',
          preview_id: 'preview-1',
          eligible_count: 2,
          skipped_count: 1,
          items: [
            { name: 'crowdsecurity/vpatch-test', action: 'install', reason: '' },
            { name: 'local/test', action: 'skip', reason: 'Lokal geändert' },
          ],
        }
      },
      startBulk: async (kind: string, id: string) => {
        calls.push(`start:${kind}:${id}`)
        current = { ...pendingJob }
        if (failStart)
          throw new Error('Response lost')
        return current
      },
      bulkJob: async () => {
        calls.push('poll')
        if (failPoll)
          throw new Error('Network offline')
        return current
      },
    },
  })
  return {
    component,
    calls,
    events,
    node,
    props,
    unmount: () => hooks.forEach(fn => fn()),
    changeNode: (id: number) => {
      node.id = id
      watches[1]()
    },
    deferPreview: () => {
      previewWait = new Promise<void>(resolve => {
        releasePreview = resolve
      })
    },
    releasePreview: () => releasePreview(),
    setCurrent: (job: SecurityBulkJob | null) => { current = job },
    failPreview: () => { failPreview = true },
    failStart: () => { failStart = true },
    failPoll: () => { failPoll = true },
    failStatus: () => { statusFail = true },
  }
}

test('opening bulk action only previews; explicit confirmation sends one snapshot-bound mutation', async () => {
  const h = harness()
  await h.component.show()
  expect(h.calls).not.toContain('start:appsec:preview-1')
  expect(h.component.preview.value.items[1].action).toBe('skip')
  await h.component.start()
  await h.component.start()
  expect(h.calls.filter(call => call.startsWith('start:'))).toEqual(['start:appsec:preview-1'])
})

test('running server job is recovered after navigation and prevents another preview or start', async () => {
  const h = harness()
  h.setCurrent({ ...pendingJob, kind: 'scenarios' })
  await h.component.show()
  await h.component.prepare()
  await h.component.start()
  expect(h.component.job.value.kind).toBe('scenarios')
  expect(h.calls).toEqual(['current'])
  expect(h.events).toContainEqual(['busy', true])
})

test('failed catalog or status cannot leave a usable old preview', async () => {
  const h = harness()
  await h.component.show()
  h.failPreview()
  await h.component.prepare()
  await h.component.start()
  expect(h.component.preview.value).toBeUndefined()
  expect(h.component.error.value).toBe('Catalog offline')
  expect(h.calls.some(call => call.startsWith('start:'))).toBe(false)
  const missingStatus = harness()
  missingStatus.failStatus()
  await missingStatus.component.show()
  expect(missingStatus.calls).toEqual(['current'])
})

test('lost start response recovers the durable job, never automatically resubmits', async () => {
  const h = harness()
  await h.component.show()
  h.failStart()
  await h.component.start()
  expect(h.component.job.value.id).toBe('job-1')
  expect(h.calls.filter(call => call.startsWith('start:'))).toHaveLength(1)
  expect(h.component.preview.value).toBeUndefined()
  expect(h.component.error.value).toContain('Start nicht eindeutig bestätigt')
})

test('poll failure stays uncertain and never reports success; completion refreshes only once', async () => {
  const h = harness()
  h.setCurrent({ ...pendingJob })
  await h.component.show()
  h.failPoll()
  await h.component.poll()
  expect(h.component.error.value).toContain('kann auf der Engine weiterlaufen')
  expect(h.events.some(event => event[0] === 'completed')).toBe(false)
  const finished = harness()
  finished.setCurrent({ ...pendingJob, state: 'succeeded', completed: 2 })
  await finished.component.recover()
  await finished.component.recover()
  expect(finished.events.filter(event => event[0] === 'completed')).toHaveLength(1)
})

test('controller switch, unmount and disabled mode prevent mutation', async () => {
  for (const mode of ['node', 'unmount', 'disabled']) {
    const h = harness()
    await h.component.show()
    if (mode === 'node')
      h.node.id = 2
    if (mode === 'unmount')
      h.unmount()
    if (mode === 'disabled')
      h.props.disabled = true
    await h.component.start()
    expect(h.calls.some(call => call.startsWith('start:'))).toBe(false)
  }
})

test('progress reserves100percent for validated success, not staging or rollback', () => {
  expect(bulkProgress()).toBe(0)
  expect(bulkProgress({ ...pendingJob, completed: 2, state: 'validating' })).toBe(95)
  expect(bulkProgress({ ...pendingJob, completed: 2, state: 'failed' })).toBe(95)
  expect(bulkProgress({ ...pendingJob, completed: 2, state: 'succeeded' })).toBe(100)
  expect(isBulkRunning({ ...pendingJob, state: 'interrupted' })).toBe(false)
})

test('late preview is discarded across a controller switch and local controls recover', async () => {
  const h = harness()
  h.deferPreview()
  const preparing = h.component.prepare()
  await Promise.resolve()
  await Promise.resolve()
  h.changeNode(2)
  h.changeNode(0)
  h.releasePreview()
  await preparing
  expect(h.component.preview.value).toBeUndefined()
  expect(h.component.loading.value).toBe(false)
  await h.component.show()
  expect(h.component.preview.value.preview_id).toBe('preview-1')
  expect(h.calls.some(call => call.startsWith('start:'))).toBe(false)
})
