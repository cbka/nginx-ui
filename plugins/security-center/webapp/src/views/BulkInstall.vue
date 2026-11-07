<script setup lang="ts">
import type { SecurityBulkItem, SecurityBulkJob, SecurityBulkKind, SecurityBulkPreview } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { bulkProgress, isBulkRunning } from './bulkInstall'
import { canManageSecurity } from './normalize'
import { filterSecurityRows, paginateSecurityRows, SECURITY_PAGE_SIZE } from './pagination'

const props = defineProps<{ kind: SecurityBulkKind, disabled?: boolean }>()
const emit = defineEmits<{ busy: [value: boolean], completed: [] }>()
const settings = useSettingsStore()
const initialNodeId = settings.node.id
const open = ref(false)
const loading = ref(false)
const starting = ref(false)
const error = ref('')
const preview = ref<SecurityBulkPreview>()
const job = ref<SecurityBulkJob | null>(null)
const search = ref('')
const page = ref(1)
const running = computed(() => isBulkRunning(job.value))
const progress = computed(() => bulkProgress(job.value))
const label = computed(() => (job.value?.kind ?? props.kind) === 'appsec'
  ? $gettext('AppSec-Regeln')
  : $gettext('CrowdSec-Szenarien'))
const rows = computed(() => filterSecurityRows(job.value?.items ?? preview.value?.items ?? [], search.value, item => `${item.name} ${item.reason} ${item.state ?? ''}`))
const paginated = computed(() => paginateSecurityRows(rows.value, page.value))
let mounted = true
let generation = 0
let pollTimer: ReturnType<typeof setTimeout> | undefined
let notifiedJob = ''

function currentNode() {
  return mounted && canManageSecurity(settings.node.id) && settings.node.id === initialNodeId
}
function stopPolling() {
  clearTimeout(pollTimer)
  pollTimer = undefined
}
function acceptJob(value: SecurityBulkJob | null) {
  job.value = value
  emit('busy', isBulkRunning(value))
  if (value?.state === 'succeeded' && value.id !== notifiedJob) {
    notifiedJob = value.id
    emit('completed')
  }
}
function schedulePoll() {
  stopPolling()
  if (currentNode() && isBulkRunning(job.value))
    pollTimer = setTimeout(poll, 1500)
}
async function poll() {
  if (!currentNode() || !job.value)
    return
  const id = job.value.id
  const requestGeneration = generation
  try {
    const result = await security.bulkJob(id)
    if (currentNode() && generation === requestGeneration && job.value?.id === id) {
      acceptJob(result)
      error.value = ''
    }
  }
  catch (e) {
    if (currentNode() && generation === requestGeneration)
      error.value = `${$gettext('Fortschritt derzeit nicht erreichbar. Der Auftrag kann auf der Engine weiterlaufen.')} ${getErrorMessage(e)}`
  }
  finally {
    if (currentNode() && generation === requestGeneration)
      schedulePoll()
  }
}
async function recover() {
  if (!currentNode())
    return
  const requestGeneration = generation
  try {
    const result = await security.currentBulkJob()
    if (currentNode() && generation === requestGeneration) {
      acceptJob(result)
      schedulePoll()
    }
  }
  catch (e) {
    if (currentNode() && generation === requestGeneration)
      error.value = `${$gettext('Der letzte Auftrag konnte nicht geprüft werden.')} ${getErrorMessage(e)}`
    throw e
  }
}
async function show() {
  if (!currentNode())
    return
  const requestGeneration = generation
  open.value = true
  loading.value = true
  error.value = ''
  preview.value = undefined
  search.value = ''
  page.value = 1
  try {
    await recover()
  }
  catch {
    // A missing status must never be treated as permission to start another job.
  }
  finally {
    if (currentNode() && generation === requestGeneration)
      loading.value = false
  }
  if (currentNode() && generation === requestGeneration && !job.value && !error.value && !props.disabled)
    await prepare()
}
async function prepare() {
  if (!currentNode() || props.disabled || loading.value || starting.value || running.value)
    return
  loading.value = true
  error.value = ''
  preview.value = undefined
  const requestGeneration = ++generation
  stopPolling()
  try {
    await recover()
    if (!currentNode() || generation !== requestGeneration || isBulkRunning(job.value))
      return
    const result = await security.bulkPreview(props.kind)
    if (currentNode() && generation === requestGeneration) {
      if (result.kind !== props.kind || !result.preview_id || !Array.isArray(result.items))
        throw new Error($gettext('Die Vorschau ist ungültig. Bitte erneut laden.'))
      job.value = null
      preview.value = result
      search.value = ''
      page.value = 1
    }
  }
  catch (e) {
    if (currentNode() && generation === requestGeneration)
      error.value = getErrorMessage(e)
  }
  finally {
    if (currentNode() && generation === requestGeneration)
      loading.value = false
  }
}
async function start() {
  if (!currentNode() || props.disabled || starting.value || loading.value || running.value || !preview.value?.eligible_count || error.value)
    return
  const confirmed = preview.value
  const requestGeneration = generation
  starting.value = true
  error.value = ''
  try {
    const result = await security.startBulk(props.kind, confirmed.preview_id)
    if (currentNode() && generation === requestGeneration) {
      preview.value = undefined
      acceptJob(result)
      schedulePoll()
    }
  }
  catch (e) {
    if (currentNode() && generation === requestGeneration) {
      preview.value = undefined
      error.value = `${$gettext('Start nicht eindeutig bestätigt. Der letzte Auftrag wird geprüft; bitte nicht erneut starten.')} ${getErrorMessage(e)}`
      try {
        await recover()
      }
      catch { /* Leave the uncertainty visible; never resend the mutation automatically. */ }
    }
  }
  finally {
    if (currentNode() && generation === requestGeneration)
      starting.value = false
  }
}
function stateText(item: SecurityBulkItem) {
  switch (item.state) {
    case 'pending': return $gettext('Wartet')
    case 'installing': return $gettext('Wird installiert')
    case 'staged': return $gettext('Vorbereitet – Prüfung ausstehend')
    case 'succeeded': return $gettext('Installiert und aktiviert')
    case 'skipped': return $gettext('Ausgelassen')
    case 'failed': return $gettext('Fehlgeschlagen')
    case 'rolled_back': return $gettext('Zurückgesetzt')
    default: return item.action === 'skip'
      ? $gettext('Wird ausgelassen')
      : item.action === 'activate'
        ? $gettext('Wird aktiviert')
        : $gettext('Wird installiert und aktiviert')
  }
}
const jobText = computed(() => {
  switch (job.value?.state) {
    case 'queued': return $gettext('Auftrag wartet auf die Engine')
    case 'running': return $gettext('Regeln werden vorbereitet')
    case 'validating': return $gettext('Konfiguration wird geprüft und geladen')
    case 'succeeded': return $gettext('Installation und Aktivierung abgeschlossen')
    case 'failed': return $gettext('Auftrag fehlgeschlagen – Einzelergebnisse beachten')
    case 'interrupted': return $gettext('Auftrag unterbrochen – Engine-Zustand prüfen')
    default: return ''
  }
})
watch(search, () => {
  page.value = 1
}, { flush: 'sync' })
watch(() => settings.node.id, () => {
  generation++
  stopPolling()
  open.value = false
  preview.value = undefined
  job.value = null
  loading.value = false
  starting.value = false
  error.value = ''
  emit('busy', false)
})
onMounted(() => {
  recover().catch(() => {})
})
onBeforeUnmount(() => {
  mounted = false
  generation++
  stopPolling()
})
</script>

<template>
  <div class="bulk-install">
    <AButton :disabled="!canManageSecurity(settings.node.id) || loading || starting" @click="show">
      {{ running ? $gettext('Sammelinstallation – Fortschritt anzeigen') : $gettext('Alle unterstützten Einträge installieren …') }}
    </AButton>
    <span v-if="running" class="bulk-running" role="status">{{ jobText }}</span>
    <AModal v-model:open="open" :title="$gettext('Sammelinstallation: %{name}', { name: label })" :width="960" :footer="null" :mask-closable="false">
      <p>{{ $gettext('Die Engine prüft den gesamten Katalog, unabhängig von Suche und aktueller Tabellenseite. Unterstützte, noch nicht aktive Einträge werden gemeinsam installiert und aktiviert. Bereits aktive, lokal geänderte und nicht unterstützte Einträge werden ausgelassen.') }}</p>
      <p>{{ $gettext('Website-Richtlinien und Ausnahmen bleiben erhalten. CrowdSec-Szenarien können neue IP-Sperren auslösen; ob sie durchgesetzt werden, hängt vom vorhandenen Schutzmodus ab.') }}</p>
      <AAlert v-if="error" role="alert" type="error" show-icon :message="error" class="bulk-gap" />
      <AAlert v-if="job && job.kind !== kind" type="info" show-icon :message="$gettext('Hier wird der zuletzt gestartete Auftrag des anderen Regelbereichs angezeigt. Auf der zentralen Engine kann nur eine Sammelinstallation gleichzeitig laufen.')" class="bulk-gap" />
      <ASpin :spinning="loading">
        <template v-if="job">
          <div aria-live="polite" role="status">
            <h4>{{ jobText }}</h4>
            <p>{{ $gettext('%{done} von %{total} Einträgen bearbeitet', { done: String(job.completed), total: String(job.total) }) }}</p>
          </div>
          <AProgress :percent="progress" :status="job.state === 'failed' || job.state === 'interrupted' ? 'exception' : job.state === 'succeeded' ? 'success' : 'active'" />
          <p v-if="job.message">
            {{ job.message }}
          </p>
          <p v-if="running">
            {{ $gettext('Sie können dieses Fenster schließen. Der Auftrag läuft auf der Engine weiter; der Fortschritt ist beim erneuten Öffnen wieder verfügbar.') }}
          </p>
        </template>
        <p v-else-if="preview" role="status" aria-live="polite">
          {{ $gettext('%{eligible} Einträge werden installiert oder aktiviert; %{skipped} Einträge bleiben unverändert.', { eligible: String(preview.eligible_count), skipped: String(preview.skipped_count) }) }}
        </p>
        <template v-if="job || preview">
          <AInput v-model:value="search" allow-clear :aria-label="$gettext('Sammelinstallation durchsuchen')" :placeholder="$gettext('Name, Ergebnis oder Begründung suchen')" />
          <div class="bulk-table-wrap">
            <table class="bulk-table">
              <caption>{{ $gettext('Einzelergebnisse und ausgeschlossene Einträge') }}</caption>
              <thead>
                <tr>
                  <th scope="col">
                    {{ $gettext('Eintrag') }}
                  </th><th scope="col">
                    {{ $gettext('Aktion / Ergebnis') }}
                  </th><th scope="col">
                    {{ $gettext('Begründung') }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in paginated.rows" :key="item.name">
                  <td>{{ item.name }}</td><td>{{ stateText(item) }}</td><td>{{ item.reason || '—' }}</td>
                </tr>
                <tr v-if="!paginated.total">
                  <td colspan="3">
                    {{ $gettext('Keine passenden Einträge.') }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <APagination :current="paginated.page" :total="paginated.total" :page-size="SECURITY_PAGE_SIZE" :show-size-changer="false" :hide-on-single-page="true" @change="page = $event" />
        </template>
      </ASpin>
      <div class="bulk-actions">
        <AButton @click="open = false">
          {{ $gettext('Schließen') }}
        </AButton>
        <AButton v-if="!running" :loading="loading" :disabled="disabled || starting" @click="prepare">
          {{ $gettext('Vorschau laden') }}
        </AButton>
        <AButton v-if="preview" type="primary" :loading="starting" :disabled="disabled || loading || !!error || !preview.eligible_count || running" @click="start">
          {{ $gettext('%{count} Einträge jetzt installieren und aktivieren', { count: String(preview.eligible_count) }) }}
        </AButton>
      </div>
    </AModal>
  </div>
</template>

<style scoped>
.bulk-install { margin: 16px 0; }
.bulk-running { margin-inline-start: 12px; }
.bulk-gap { margin: 12px 0; }
.bulk-table-wrap { max-height: 420px; overflow: auto; margin: 12px 0; }
.bulk-table { width: 100%; border-collapse: collapse; }
.bulk-table caption { text-align: left; font-weight: 600; padding: 8px 0; }
.bulk-table th, .bulk-table td { text-align: left; vertical-align: top; padding: 10px; border-bottom: 1px solid var(--ant-color-border, #ddd); overflow-wrap: anywhere; }
.bulk-table td:first-child { max-width: 360px; }
.bulk-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; margin-top: 20px; }
</style>
