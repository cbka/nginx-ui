import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { expect, test } from 'bun:test'

test('installed IIFE registers its own Vue page and can be disabled and re-enabled', () => {
  let definition: { setup: (registry: unknown) => void, teardown: () => void } | undefined
  const provider = { name: 'SharedAppProvider' }
  const vue = new Proxy({}, {
    get: (_target, property) => property === 'h'
      ? (component: unknown, props: unknown, slots: unknown) => ({ component, props, slots })
      : property === 'defineComponent'
        ? (component: unknown) => component
        : () => ({}),
  })
  const source = readFileSync(new URL('../dist/main.js', import.meta.url), 'utf8')
  const runtime = {
    shared: {
      vue,
      antdvNext: { App: provider },
      antdvIcons: {},
      gettext: {
        $gettext: (text: string) => text,
      },
    },
    registerPlugin(id: string, plugin: typeof definition) {
      expect(id).toBe('io.github.mctdatapool.security-center')
      definition = plugin
    },
  }
  runInNewContext(source, {
    window: { NginxUI: runtime },
  })
  expect(!!definition).toBe(true)
  expect(() => definition!.setup({})).toThrow('secure plugin request support')
  const routes: { path: string, component: unknown }[] = []
  const settingsPanels: unknown[] = []
  const registry = {
    host: { nodeId: 0 },
    request: () => Promise.resolve({}),
    registerSettingsPanel: (component: unknown) => settingsPanels.push(component),
    registerRoute: (route: { path: string, component: unknown }) => routes.push(route),
  }
  definition!.setup(registry)
  expect(settingsPanels.length).toBe(1)
  expect(typeof settingsPanels[0]).toBe('object')
  expect(routes[0].path).toBe('security-center')
  expect(typeof routes[0].component).toBe('object')
  const root = routes[0].component as { setup: () => () => { component: unknown, slots: { default: () => { component: unknown } } } }
  const rendered = root.setup()()
  expect(rendered.component).toBe(provider)
  expect(typeof rendered.slots.default().component).toBe('object')
  definition!.teardown()
  definition!.setup(registry)
  expect(routes.length).toBe(2)
  // A shared-runtime bundle should not carry another Vue/Antdv application.
  expect(source.length < 200000).toBe(true)
})
