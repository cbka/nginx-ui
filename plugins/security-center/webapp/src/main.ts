import { SafetyCertificateOutlined } from '@antdv-next/icons'
import { $gettext, clearRuntime, installRuntime } from './runtime'
import SecurityCenter from './views/SecurityCenter.vue'
import SecuritySettings from './views/SecuritySettings.vue'

window.NginxUI.registerPlugin('io.github.mctdatapool.security-center', {
  setup(registry) {
    installRuntime(registry)
    registry.registerSettingsPanel(SecuritySettings)
    registry.registerRoute({
      path: 'security-center',
      name: 'Plugin Security Center',
      component: SecurityCenter,
      meta: {
        name: () => $gettext('Security Center'),
        icon: SafetyCertificateOutlined,
      },
    })
  },
  teardown: clearRuntime,
})
