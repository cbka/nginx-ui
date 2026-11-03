/** Keep the secure-session-aware bridge inside this plugin's own HTTP namespace. */
export function pluginRequestPath(pluginId: string, path: string): string {
  if (!/^[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(pluginId) || !path.startsWith('/') || path.startsWith('//') || /[?#\\]/.test(path) || [...path].some(char => char.charCodeAt(0) < 32))
    throw new Error('Invalid plugin request path')
  let decoded: string
  try {
    decoded = decodeURIComponent(path)
  }
  catch { throw new Error('Invalid plugin request encoding') }
  if (/[?#\\%]/.test(decoded) || [...decoded].some(char => char.charCodeAt(0) < 32) || decoded.split('/').some(segment => segment === '.' || segment === '..'))
    throw new Error('Plugin request path must stay inside its namespace')
  return `/plugins/${encodeURIComponent(pluginId)}/http${path}`
}
