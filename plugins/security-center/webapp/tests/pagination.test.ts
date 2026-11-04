import { expect, test } from 'bun:test'
import { filterSecurityRows, paginateSecurityRows } from '../src/views/pagination'

const inventory = Array.from({ length: 47 }, (_, index) => ({
  name: `crowdsecurity/rule-${index}`,
  description: index % 2
    ? 'CVE-2026 web exploit'
    : 'CVE-2025 scanner',
}))

test('20 entries per page, with no omissions or duplicates across pages', () => {
  const pages = [1, 2, 3].map(page => paginateSecurityRows(inventory, page))
  expect(pages.map(page => page.rows.length)).toEqual([20, 20, 7])
  expect(pages.flatMap(page => page.rows)).toEqual(inventory)
})

test('search spans every page, normalizes case, and combines terms', () => {
  const found = filterSecurityRows(inventory, '  CVE-2026   WEB ', row => `${row.name} ${row.description}`)
  expect(found.length).toBe(23)
  expect(paginateSecurityRows(found, 2).rows.length).toBe(3)
  expect(filterSecurityRows(inventory, 'rule-46', row => row.name)).toEqual([inventory[46]])
})

test('shrinking refreshed inventories clamp the page and preserve empty state', () => {
  expect(paginateSecurityRows(inventory.slice(0, 7), 3)).toEqual({
    page: 1,
    total: 7,
    rows: inventory.slice(0, 7),
  })
  expect(paginateSecurityRows([], 9)).toEqual({ page: 1, total: 0, rows: [] })
  expect(paginateSecurityRows(inventory, 0).page).toBe(1)
  expect(filterSecurityRows(inventory, 'no-match', row => row.name)).toEqual([])
})
