<script setup lang="ts">
import type { CrowdSecSharing } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { canManageSecurity } from './normalize'
import { canApplySharing, sharingConfiguredValue } from './sharing'

const { modal } = App.useApp()
const settings = useSettingsStore()
const status = ref<CrowdSecSharing>()
const desired = ref<boolean | null>(null)
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const configured = computed(() => sharingConfiguredValue(status.value))
let mounted = true
let generation = 0
onBeforeUnmount(() => {
  mounted = false
  generation++
})
async function load() {
  status.value = undefined
  desired.value = null
  const current = ++generation
  if (!canManageSecurity(settings.node.id))
    return
  loading.value = true
  error.value = ''
  try {
    const result = await security.sharing()
    if (!mounted || current !== generation)
      return
    status.value = result
    desired.value = sharingConfiguredValue(result)
  }
  catch (e) { error.value = getErrorMessage(e) }
  finally { loading.value = false }
}
function apply() {
  if (!canApplySharing(status.value, desired.value) || saving.value)
    return
  const enabled = desired.value === true
  const current = generation
  modal.confirm({
    title: enabled
      ? $gettext('Enable global community signal sharing?')
      : $gettext('Disable global community signal sharing?'),
    content: enabled
      ? $gettext('CrowdSec engine alerts may send IP addresses (and geolocation when available), scenario details, timestamps and the instance identifier to CrowdSec’s Central API. This affects all websites using this connected Local API. It does not publish every blocked HTTP request. Local blocking and logs remain active; blocklist pulling, metrics and Console traffic are separate settings. Community list coverage may depend on participation.')
      : $gettext('Stop sending engine alert signals from this connected Local API to the community. Local blocking and logs remain active. This does not change the separate blocklist-pulling setting, but community list coverage may depend on participation.'),
    okText: $gettext('Apply global sharing setting'),
    async onOk() {
      if (!mounted || current !== generation || !canManageSecurity(settings.node.id))
        throw new Error($gettext('The controller changed. Refresh before applying.'))
      saving.value = true
      error.value = ''
      try {
        const result = await security.saveSharing(enabled)
        if (mounted && current === generation) {
          status.value = result
          desired.value = sharingConfiguredValue(result)
        }
      }
      catch (e) {
        error.value = getErrorMessage(e)
        throw e
      }
      finally { saving.value = false }
    },
  })
}
watch(() => settings.node.id, load, { immediate: true })
</script>

<template>
  <ACard :title="$gettext('Community signal sharing — global')" size="small" class="sharing-card">
    <template #extra>
      <AButton :loading="loading" :disabled="saving || !canManageSecurity(settings.node.id)" @click="load">
        {{ $gettext('Refresh status') }}
      </AButton>
    </template>
    <p>{{ $gettext('Engine alert sharing for all websites using the connected CrowdSec Local API. Website enforcement switches and templates do not control community reporting.') }}</p>
    <AAlert v-if="error" type="error" show-icon :message="error" />
    <ASpin :spinning="loading">
      <p><strong>{{ $gettext('Current configuration') }}: </strong>{{ configured === null ? $gettext('Unknown / unavailable') : configured ? $gettext('Enabled') : $gettext('Disabled') }}</p>
      <AAlert v-if="status" :type="status.applied ? 'success' : 'info'" show-icon :message="status.message" />
      <p>{{ $gettext('Configuration status does not verify actual runtime delivery to the community.') }}</p>
      <AAlert v-if="!loading && (!status?.configured || !status.editable)" type="warning" show-icon :message="$gettext('The engine configuration adapter is unavailable or read-only. No enabled/disabled runtime state is assumed.')" />
      <AForm layout="vertical">
        <AFormItem :label="$gettext('Desired community sharing setting')" :help="$gettext('Global für die verbundene Engine. Aktiviert das Senden von Angriffssignalen an CrowdSec; CrowdSec bewertet sie für gemeinsame Sperrlisten. Nicht jede blockierte Anfrage wird gemeldet oder veröffentlicht. Deaktivieren hebt lokale Sperren nicht auf.')">
          <ASwitch :checked="desired === true" :disabled="configured === null || !status?.editable || loading || saving || !canManageSecurity(settings.node.id)" @change="value => desired = !!value" />
          <span class="desired-label">{{ desired === null ? $gettext('Unknown') : desired ? $gettext('Enabled') : $gettext('Disabled') }}</span>
        </AFormItem>
        <AButton type="primary" :loading="saving" :disabled="!canApplySharing(status, desired) || loading || !canManageSecurity(settings.node.id)" @click="apply">
          {{ $gettext('Review and apply') }}
        </AButton>
      </AForm>
    </ASpin>
  </ACard>
</template>

<style scoped>
.sharing-card { margin-block: 16px; }
.desired-label { margin-inline-start: 8px; }
.sharing-card :deep(.ant-alert) { margin-bottom: 12px; }
</style>
