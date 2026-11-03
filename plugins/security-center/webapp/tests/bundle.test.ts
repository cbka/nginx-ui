import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { expect, test } from 'bun:test'

test('installed IIFE registers its own Vue page and can be disabled and re-enabled', () => {
  let definition: { setup: (registry: unknown) => void, teardown: () => void } | undefined
  const vue = new Proxy({}, {
    get: (_target, property) => property === 'defineComponent'
      ? (component: unknown) => component
      : () => ({}),
  })
  const source = readFileSync(new URL('../dist/main.js', import.meta.url), 'utf8')
  const runtime = {
    shared: {
      vue,
      antdvNext: {},
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
  const registry = {
    host: { nodeId: 0 },
    request: () => Promise.resolve({}),
    registerRoute: (route: { path: string, component: unknown }) => routes.push(route),
  }
  definition!.setup(registry)
  expect(routes[0].path).toBe('security-center')
  expect(typeof routes[0].component).toBe('object')
  definition!.teardown()
  definition!.setup(registry)
  expect(routes.length).toBe(2)
  // A shared-runtime bundle should not carry another Vue/Antdv application.
  expect(source.length < 200000).toBe(true)
})
