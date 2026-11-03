import type { Component } from 'vue'
import type { RouteRecordRaw } from 'vue-router'

interface PluginRegistry {
  host: { readonly nodeId: number }
  request: <T>(method: 'get' | 'post' | 'put' | 'delete', path: string, body?: unknown, options?: { params?: Record<string, unknown> }) => Promise<T>
  registerRoute: (route: RouteRecordRaw) => void
  registerSettingsPanel: (component: Component) => void
}
declare global {
  interface Window {
    NginxUI: {
      shared: { gettext: { $gettext: (message: string, params?: Record<string, unknown>) => string } }
      registerPlugin: (id: string, definition: { setup: (registry: PluginRegistry) => void, teardown?: () => void }) => void
    }
  }
}
declare module 'vue' {
  interface ComponentCustomProperties {
    $gettext: (message: string, params?: Record<string, unknown>) => string
  }
}
export {}
