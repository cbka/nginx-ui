import { SafetyCertificateOutlined } from '@antdv-next/icons'
import { App } from 'antdv-next'
import { defineComponent, h } from 'vue'
import { $gettext, clearRuntime, installRuntime } from './runtime'
import SecurityCenter from './views/SecurityCenter.vue'
import SecuritySettings from './views/SecuritySettings.vue'

// Every useApp consumer must be below the same shared App provider.
// Do not resolve AApp through deep component imports: that can create another
// injection context than the host-exported App.useApp used by this plugin.
const SecurityCenterRoot = defineComponent({
  name: 'SecurityCenterRoot',
  setup() {
    return () => h(App, null, {
      default: () => h(SecurityCenter),
    })
  },
})

window.NginxUI.registerPlugin('io.github.mctdatapool.security-center', {
  setup(registry) {
    installRuntime(registry)
    registry.registerSettingsPanel(SecuritySettings)
    registry.registerRoute({
      path: 'security-center',
      name: 'Plugin Security Center',
      component: SecurityCenterRoot,
      meta: {
        name: () => $gettext('Security Center'),
        icon: SafetyCertificateOutlined,
      },
    })
  },
  teardown: clearRuntime,
})
