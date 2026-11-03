import type { RouteRecordRaw } from 'vue-router'
import { readonly } from 'vue'

interface Registry {
  host: { readonly nodeId: number }
  request: <T>(method: 'get' | 'post' | 'put' | 'delete', path: string, body?: unknown, options?: { params?: Record<string, unknown> }) => Promise<T>
  registerRoute: (route: RouteRecordRaw) => void
}
let registry: Registry | undefined
export function installRuntime(value: Registry) {
  if (typeof value.request !== 'function')
    throw new TypeError('Security Center requires a host with secure plugin request support')
  registry = value
}
export function clearRuntime() {
  registry = undefined
}
export function useSettingsStore() {
  return readonly({
    get node() { return { id: registry?.host.nodeId ?? -1 } },
  })
}
export function $gettext(message: string, params?: Record<string, unknown>): string {
  return window.NginxUI.shared.gettext.$gettext(message, params)
}
export const http = {
  get: <T>(path: string, options?: { params?: Record<string, unknown> }): Promise<T> => request<T>('get', path, undefined, options),
  delete: <T>(path: string, options?: { params?: Record<string, unknown> }): Promise<T> => request<T>('delete', path, undefined, options),
  post: <T>(path: string, body?: unknown, options?: { params?: Record<string, unknown> }): Promise<T> => request<T>('post', path, body, options),
  put: <T>(path: string, body?: unknown, options?: { params?: Record<string, unknown> }): Promise<T> => request<T>('put', path, body, options),
}
function request<T>(method: 'get' | 'post' | 'put' | 'delete', path: string, body?: unknown, options?: { params?: Record<string, unknown> }): Promise<T> {
  if (!registry || registry.host.nodeId !== 0)
    return Promise.reject(new Error('Select the local controller before managing Security Center'))
  return registry.request<T>(method, path, body, options)
}
export function getErrorMessage(error: unknown): string {
  const value = error as { message?: string, code?: string, response?: { data?: { message?: string, code?: string } } }
  const payload = value?.response?.data ?? value
  return payload?.code === 'two_factor_cancelled'
    ? ''
    : payload?.message || $gettext('Server error')
}
