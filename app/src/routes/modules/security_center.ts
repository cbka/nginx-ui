import type { RouteRecordRaw } from 'vue-router'
import { SafetyCertificateOutlined } from '@antdv-next/icons'

export const securityCenterRoutes: RouteRecordRaw[] = [
  {
    path: 'security-center',
    name: 'Security Center',
    component: () => import('@/views/security_center/SecurityCenter.vue'),
    meta: {
      name: () => $gettext('Security Center'),
      icon: SafetyCertificateOutlined,
    },
  },
]
