import { expect, test } from 'bun:test'
import { normalizeScenarios } from '../src/views/normalize'

test('disabled catalog entries with updates offer installation', () => {
  for (const status of [
    'disabled,update-available',
    'disabled',
    'not-installed',
    'update-available',
  ]) {
    expect(normalizeScenarios([
      { name: 'example/rule', status },
    ])[0].installed).toBe(false)
  }
})

test('explicit installation state takes precedence over status labels', () => {
  expect(normalizeScenarios([
    { name: 'example/rule', installed: false, status: 'enabled' },
  ])[0].installed).toBe(false)
  expect(normalizeScenarios([
    {
      name: 'example/rule',
      local: { installed: false },
      status: 'enabled',
    },
  ])[0].installed).toBe(false)
  expect(normalizeScenarios([
    { name: 'example/rule', installed: true, status: 'tainted' },
  ])[0].installed).toBe(true)
  expect(normalizeScenarios([
    { name: 'example/rule', status: 'enabled,update-available' },
  ])[0].installed).toBe(true)
})
