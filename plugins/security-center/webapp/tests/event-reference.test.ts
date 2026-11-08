import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { Transpiler } from 'bun'
import { expect, test } from 'bun:test'

function harness() {
  const source = readFileSync(new URL('../src/views/SecurityEvents.vue', import.meta.url), 'utf8')
  const script = source.split('<script setup lang="ts">')[1].split('</script>')[0].replace(/^import .*\n/gm, '')
  const calls: unknown[] = []
  const node = { id: 0 }
  const component = runInNewContext(`${new Transpiler({ loader: 'ts' }).transformSync(script)}\n;({load, requestID, result, source})`, {
    defineProps: () => ({ sites: [] }),
    defineEmits: () => () => {},
    ref: (value: unknown) => ({ value }),
    computed: (get: () => unknown) => ({
      get value() { return get() },
    }),
    watch: () => {},
    onBeforeUnmount: () => {},
    useSettingsStore: () => ({ node }),
    canManageSecurity: (id: number) => id === 0,
    App: {
      useApp: () => ({ modal: {}, message: {} }),
    },
    $gettext: (message: string) => message,
    getErrorMessage: (error: Error) => error.message,
    security: {
      events: async (params: unknown) => {
        calls.push(params)
        return {
          items: [
            { transaction_id: 'server-reference', node: 'kub1' },
          ],
          limit: 100,
        }
      },
    },
  })
  return { component, calls, node }
}

test('request reference is sent to server across all security sources', async () => {
  const h = harness()
  h.component.requestID.value = '  0123456789abcdef0123456789abcdef  '
  await h.component.load()
  expect(h.calls).toEqual([
    {
      source: 'all',
      request_id: '0123456789abcdef0123456789abcdef',
      vhost: undefined,
      node: undefined,
      since: '1h',
      limit: 100,
    },
  ])
  // No client-only filter: the server returns the matching historical page.
  expect(h.component.result.value.items.length).toBe(1)
})

test('clearing reference omits filter and remote node cannot query', async () => {
  const h = harness()
  await h.component.load()
  expect((h.calls[0] as { request_id?: string }).request_id).toBeUndefined()
  h.node.id = 2
  await h.component.load()
  expect(h.calls.length).toBe(1)
})
