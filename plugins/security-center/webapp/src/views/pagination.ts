export const SECURITY_PAGE_SIZE = 20

/** Clamp the page when a refreshed inventory or a search has fewer results. */
export function paginateSecurityRows<T>(rows: T[], requestedPage: number) {
  const pages = Math.max(1, Math.ceil(rows.length / SECURITY_PAGE_SIZE))
  const page = Math.min(pages, Math.max(1, Math.trunc(requestedPage) || 1))
  const start = (page - 1) * SECURITY_PAGE_SIZE
  return {
    page,
    total: rows.length,
    rows: rows.slice(start, start + SECURITY_PAGE_SIZE),
  }
}

export function filterSecurityRows<T>(rows: T[], query: string, searchable: (row: T) => string) {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  return rows.filter(row => {
    const text = searchable(row).toLocaleLowerCase()
    return terms.every(term => text.includes(term))
  })
}
