import { expect, test } from 'bun:test'
import { requiresDisableConfirmation } from '../src/views/system/plugins/lifecycle'

test('live-service deactivation requires confirmation even when usage is empty or unavailable', () => {
  expect(requiresDisableConfirmation(['lifecycle.deactivate'], 0)).toBe(true)
  expect(requiresDisableConfirmation(['lifecycle.deactivate'])).toBe(true)
  expect(requiresDisableConfirmation(['http'], 1)).toBe(true)
  expect(requiresDisableConfirmation(['http'], 0)).toBe(false)
  expect(requiresDisableConfirmation([])).toBe(false)
})
