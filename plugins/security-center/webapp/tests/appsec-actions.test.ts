import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { Transpiler } from 'bun'
import { expect, test } from 'bun:test'

function harness(response: { applied?: boolean, message: string }, fail = false) {
  const source = readFileSync(new URL('../src/views/AppSecPanel.vue', import.meta.url), 'utf8')
  const script = source.split('<script setup lang="ts">')[1].split('</script>')[0].replace(/^import .*\n/gm, '')
  let confirm: { onOk: () => Promise<void> } | undefined
  const calls: unknown[] = []
  const node = { id: 0 }
  const component = runInNewContext(`${new Transpiler({ loader: 'ts' }).transformSync(script)}\n;({changeRule, busy, mutationError, resultMessage})`, {
    defineProps: () => ({}),
    defineEmits: () => () => {},
    ref: (value: unknown) => ({ value }),
    computed: (get: () => unknown) => ({
      get value() { return get() },
    }),
    watch: () => {},
    onMounted: () => {},
    onBeforeUnmount: () => {},
    useSettingsStore: () => ({ node }),
    canManageSecurity: (id: number) => id === 0,
    App: {
      useApp: () => ({
        modal: {
          confirm: (options: typeof confirm) => { confirm = options },
        },
      }),
    },
    $gettext: (message: string) => message,
    getErrorMessage: (error: Error) => error.message,
    security: {
      changeAppSecRule: async (...args: unknown[]) => {
        calls.push(args)
        if (fail)
          throw new Error('Reload failed')
        return response
      },
      appsec: async () => ({ rules: [] }),
    },
  })
  return {
    component,
    calls,
    node,
    confirmed: () => confirm!.onOk(),
    hasConfirmation: () => !!confirm,
  }
}

test('AppSec action submits rule namespace and action only after confirmation', async () => {
  const h = harness({ applied: true, message: 'Installed and verified' })
  await h.component.changeRule({ name: 'crowdsecurity/vpatch-example', editable: true }, 'install')
  expect(h.calls).toEqual([])
  await h.confirmed()
  expect(h.calls).toEqual([
    ['crowdsecurity/vpatch-example', 'install'],
  ])
  expect(h.component.resultMessage.value).toBe('Installed and verified')
  expect(h.component.busy.value).toBe('')
})

test('failed or unconfirmed AppSec changes show an error and never claim success', async () => {
  for (const fail of [false, true]) {
    const h = harness({ applied: false, message: 'Reload not confirmed' }, fail)
    await h.component.changeRule({ name: 'crowdsecurity/vpatch-example', editable: true }, 'activate')
    await expect(h.confirmed()).rejects.toThrow(fail ? 'Reload failed' : 'Reload not confirmed')
    expect(h.component.mutationError.value).toBe(fail ? 'Reload failed' : 'Reload not confirmed')
    expect(h.component.resultMessage.value).toBe('')
    expect(h.component.busy.value).toBe('')
  }
})

test('unsupported rules and changed node never send mutations', async () => {
  const h = harness({ applied: true, message: 'done' })
  await h.component.changeRule({ name: 'other/profile', editable: false }, 'install')
  expect(h.hasConfirmation()).toBe(false)
  await h.component.changeRule({ name: 'crowdsecurity/vpatch-example', editable: true }, 'activate')
  h.node.id = 2
  await expect(h.confirmed()).rejects.toThrow()
  expect(h.calls).toEqual([])
})
