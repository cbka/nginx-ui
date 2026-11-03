import { SafetyCertificateOutlined } from '@antdv-next/icons'
import { $gettext, clearRuntime, installRuntime } from './runtime'
import SecurityCenter from './views/SecurityCenter.vue'

window.NginxUI.registerPlugin('io.github.mctdatapool.security-center', {
  setup(registry) {
    installRuntime(registry)
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
