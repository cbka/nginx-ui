import { fileURLToPath } from 'node:url'
import { AntdvNextResolver } from '@antdv-next/auto-import-resolver'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { defineConfig } from 'vite'

const root = fileURLToPath(new URL('.', import.meta.url))
const globals: Record<string, string> = {
  'vue': 'window.NginxUI.shared.vue',
  'vue-router': 'window.NginxUI.shared.vueRouter',
  'pinia': 'window.NginxUI.shared.pinia',
  'antdv-next': 'window.NginxUI.shared.antdvNext',
  '@antdv-next/icons': 'window.NginxUI.shared.antdvIcons',
  '@vueuse/core': 'window.NginxUI.shared.vueuse',
}
export default defineConfig({
  root,
  resolve: {
    alias: { '@': `${root}src` },
  },
  plugins: [
    vue(),
    Components({
      resolvers: [
        AntdvNextResolver(),
      ],
      dts: `${root}src/components.d.ts`,
    }),
    AutoImport({
      imports: [
        'vue',
        {
          '@/runtime': ['$gettext'],
          'antdv-next': ['App'],
        },
      ],
      dts: `${root}src/auto-imports.d.ts`,
    }),
  ],
  build: {
    outDir: 'dist',
    cssCodeSplit: false,
    lib: {
      entry: `${root}src/main.ts`,
      name: 'SecurityCenterPlugin',
      formats: ['iife'],
      fileName: () => 'main.js',
      cssFileName: 'style',
    },
    rollupOptions: {
      external: Object.keys(globals),
      output: { globals },
    },
  },
})
