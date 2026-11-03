import { expect, test } from 'bun:test'
import { pluginRequestPath } from '../src/plugin/request'

test('secure plugin request bridge stays in its own authenticated namespace', () => {
  expect(pluginRequestPath('io.example.security', '/sites/example.conf')).toBe('/plugins/io.example.security/http/sites/example.conf')
  for (const path of [
    '//evil.example/',
    '/../../users',
    '/%2e%2e/users',
    '/%252e%252e/users',
    '/sites?redirect=/users',
    '/a\\b',
    'https://evil.example',
    '/a%3fb',
  ]) {
    expect(() => pluginRequestPath('io.example.security', path)).toThrow()
  }
  expect(() => pluginRequestPath('../other', '/sites')).toThrow()
})
