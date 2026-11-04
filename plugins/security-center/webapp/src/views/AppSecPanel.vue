<script setup lang="ts">
import type { AppSecHubItem, AppSecStatus } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { canManageSecurity } from './normalize'
import { filterSecurityRows, paginateSecurityRows, SECURITY_PAGE_SIZE } from './pagination'

const state = ref<AppSecStatus>()
const loading = ref(false)
const error = ref('')
const mutationError = ref('')
const resultMessage = ref('')
const busy = ref('')
const { modal } = App.useApp()
const search = ref('')
const page = ref(1)
watch(search, () => {
  page.value = 1
}, { flush: 'sync' })
const settings = useSettingsStore()
const initialNodeId = settings.node.id
let mounted = true
let generation = 0
onBeforeUnmount(() => {
  mounted = false
  generation++
})
const rows = computed(() => filterSecurityRows(state.value
  ? [
      ...(state.value.collections ?? []).map(item => ({ ...item, kind: 'collection' })),
      ...(state.value.configs ?? []).map(item => ({ ...item, kind: 'config' })),
      ...(state.value.rules ?? []).map(item => ({ ...item, kind: 'rule' })),
    ]
  : [], search.value, item => `${item.name} ${item.description ?? ''} ${item.kind} ${item.version ?? ''}`))
const paginated = computed(() => paginateSecurityRows(rows.value, page.value))
async function changeRule(item: AppSecHubItem, action: 'install' | 'activate') {
  if (busy.value || loading.value || item.editable !== true)
    return
  modal.confirm({
    title: action === 'install'
      ? $gettext('AppSec-Regel installieren und aktivieren?')
      : $gettext('AppSec-Regel aktivieren?'),
    content: $gettext('Regel: %{name}. Die zentrale Engine lädt ihre Konfiguration neu. Die Website-Richtlinien bestimmen weiterhin, ob Treffer beobachtet oder blockiert werden.', { name: item.name }),
    async onOk() {
      if (!mounted || !canManageSecurity(settings.node.id) || settings.node.id !== initialNodeId)
        throw new Error($gettext('Bitte den lokalen Controller auswählen und das Security Center erneut öffnen.'))
      if (busy.value)
        return
      busy.value = item.name
      mutationError.value = ''
      resultMessage.value = ''
      try {
        const result = await security.changeAppSecRule(item.name, action)
        if (result.applied !== true)
          throw new Error(result.message || $gettext('Die Änderung wurde von der Engine nicht bestätigt.'))
        await refresh()
        if (mounted && settings.node.id === initialNodeId)
          resultMessage.value = result.message
      }
      catch (e) {
        if (mounted && settings.node.id === initialNodeId)
          mutationError.value = getErrorMessage(e)
        throw e
      }
      finally {
        busy.value = ''
      }
    },
  })
}
async function refresh() {
  if (!canManageSecurity(settings.node.id) || settings.node.id !== initialNodeId)
    return
  const requestGeneration = ++generation
  loading.value = true
  error.value = ''
  try {
    const result = await security.appsec()
    if (mounted && generation === requestGeneration && settings.node.id === initialNodeId)
      state.value = result
  }
  catch (e) {
    if (mounted && generation === requestGeneration) {
      state.value = undefined
      error.value = getErrorMessage(e)
    }
  }
  finally {
    if (mounted && generation === requestGeneration)
      loading.value = false
  }
}
onMounted(refresh)
</script>

<template>
  <section class="appsec-panel">
    <div class="appsec-heading">
      <h3>{{ $gettext('AppSec – direkte Anfrageprüfung') }}</h3>
      <AButton :loading="loading" :disabled="!!busy" @click="refresh">
        {{ $gettext('Status aktualisieren') }}
      </AButton>
    </div>
    <p>{{ $gettext('CrowdSec-Szenarien erkennen Muster in Logs. AppSec prüft dagegen einzelne HTTP-Anfragen auf bekannte Angriffe, bevor die Anwendung sie verarbeitet. Die offizielle Virtual-Patching-Sammlung liefert passende Schutzregeln. ModSecurity und vorhandene CrowdSec-IP-Sperren bleiben getrennte Schutzmechanismen.') }}</p>
    <AAlert v-if="error" type="error" show-icon :message="error" />
    <AAlert v-if="mutationError" type="error" show-icon :message="mutationError" />
    <AAlert v-if="resultMessage" type="success" show-icon :message="resultMessage" />
    <ASpin :spinning="loading">
      <template v-if="state">
        <div class="appsec-status">
          <ATag>{{ $gettext('Engine-Konfiguration') }}: {{ state.enabled ? $gettext('Eingeschaltet') : $gettext('Aus') }}</ATag>
          <ATag :color="state.ready ? 'blue' : 'orange'">
            {{ state.ready ? $gettext('Blockierender AppSec-Listener erreichbar') : $gettext('Blockierender AppSec-Listener nicht bestätigt') }}
          </ATag>
          <ATag :color="state.detection_ready === true ? 'blue' : 'orange'">
            {{ state.detection_ready === true ? $gettext('Beobachtungs-Listener erreichbar') : $gettext('Beobachtungs-Listener nicht bestätigt') }}
          </ATag>
          <ATag :color="state.runtime_integration_verified === true ? 'blue' : 'orange'">
            {{ state.runtime_integration_verified === true ? $gettext('Lokale Nginx-Anbindung geprüft') : $gettext('Lokale Nginx-Anbindung nicht bestätigt') }}
          </ATag>
        </div>
        <AAlert type="info" show-icon :message="$gettext('Verfügbar heißt: im Hub bekannt. Installiert heißt: auf der Engine vorhanden. Geladen wird nur angezeigt, wenn die Engine dies ausdrücklich bestätigt. Ein erreichbarer Listener und gespeicherte Richtlinien beweisen noch nicht, dass reale Anfragen geprüft werden. Dafür sind ein kontrollierter Test und passende Ereignisse nötig.')" />
        <p v-if="state.site_counts" class="appsec-counts">
          {{ $gettext('Lokal gespeicherte Website-Richtlinien') }}:
          {{ $gettext('Aus') }} {{ state.site_counts.off }} ·
          {{ $gettext('Beobachten') }} {{ state.site_counts.detection }} ·
          {{ $gettext('Blockieren') }} {{ state.site_counts.block }}.
          {{ $gettext('Diese Zähler bestätigen weder aktivierte Websites noch öffentlichen Datenverkehr oder den Stand anderer Knoten.') }}
        </p>
        <p>{{ $gettext('Bei nicht erreichbarer Prüfung, zu großem Anfrageinhalt oder ungültiger Antwort lässt diese Integration die Anfrage weiterlaufen und protokolliert einen Prüfungsfehler. Bestehende IP-Sperren und ModSecurity bleiben unabhängig wirksam. CrowdSec-IP-Ausnahmen überspringen auch AppSec. Beobachten verwendet einen separaten Listener, damit Treffer keine neuen zentralen Sperren erzeugen.') }}</p>
        <p>{{ $gettext('Installieren und aktivieren legt die Regel auf der Engine ab und lädt sie sofort. Aktivieren lädt bereits installierte Regeln des Virtual-Patching-Profils neu. Sammlungen, Konfigurationen und Regeln anderer Profile werden hier nur angezeigt; ihre Aktivierung erfordert eine passende Engine-Konfiguration. Geladen bedeutet noch nicht Blockieren: Das legt die Website-Richtlinie fest.') }}</p>
        <AInput v-model:value="search" allow-clear :placeholder="$gettext('Sammlungen, Konfigurationen und Regeln suchen')" :aria-label="$gettext('AppSec-Einträge suchen')" class="appsec-search" />
        <p aria-live="polite">
          {{ $gettext('%{count} passende Einträge · 20 pro Seite', { count: String(rows.length) }) }}
        </p>
        <div class="appsec-table-wrap">
          <table class="appsec-table">
            <thead><tr><th>{{ $gettext('Eintrag') }}</th><th>{{ $gettext('Art') }}</th><th>{{ $gettext('Im Hub verfügbar') }}</th><th>{{ $gettext('Installiert') }}</th><th>{{ $gettext('In der Engine geladen') }}</th><th>{{ $gettext('Version') }}</th><th>{{ $gettext('Aktionen') }}</th></tr></thead>
            <tbody>
              <tr v-for="item in paginated.rows" :key="`${item.kind}:${item.name}`">
                <td><strong>{{ item.name }}</strong><small v-if="item.description">{{ item.description }}</small><small v-if="item.tainted">{{ $gettext('Lokal geändert – Update-Verhalten prüfen') }}</small><small v-if="item.update_available">{{ $gettext('Update verfügbar') }}</small></td>
                <td>{{ item.kind === 'collection' ? $gettext('Sammlung') : item.kind === 'config' ? $gettext('Konfiguration') : $gettext('Regel') }}</td>
                <td>{{ item.available === true ? $gettext('Ja') : item.available === false ? $gettext('Nein') : $gettext('Unbekannt') }}</td>
                <td>{{ item.installed === true ? $gettext('Ja') : item.installed === false ? $gettext('Nein') : $gettext('Unbekannt') }}</td>
                <td>{{ item.loaded === true ? $gettext('Bestätigt') : item.loaded === false ? $gettext('Nicht geladen') : $gettext('Nicht bestätigt') }}</td>
                <td>{{ item.version || '—' }}</td>
                <td>
                  <AButton v-if="item.kind === 'rule' && item.editable === true && (!item.installed || item.loaded !== true)" size="small" :loading="busy === item.name" :disabled="!!busy || loading" @click="changeRule(item, item.installed ? 'activate' : 'install')">
                    {{ item.installed ? $gettext('Aktivieren') : $gettext('Installieren und aktivieren') }}
                  </AButton>
                  <ATag v-else-if="item.kind === 'rule' && item.loaded === true" color="green">
                    {{ $gettext('Geladen') }}
                  </ATag>
                  <span v-else>{{ $gettext('Über Engine-Konfiguration verwaltet') }}</span>
                </td>
              </tr>
              <tr v-if="!rows.length">
                <td colspan="7">
                  {{ $gettext('Keine passenden Einträge zurückgegeben. Das ist kein Nachweis für fehlenden Schutz.') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <APagination :current="paginated.page" :total="paginated.total" :page-size="SECURITY_PAGE_SIZE" :show-size-changer="false" :hide-on-single-page="true" class="appsec-pagination" @change="page = $event" />
      </template>
    </ASpin>
  </section>
</template>

<style scoped>
.appsec-pagination { margin-top: 16px; }
.appsec-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }
.appsec-status { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.appsec-counts, .appsec-search { margin: 16px 0; }
.appsec-table-wrap { overflow-x: auto; }
.appsec-table { width: 100%; border-collapse: collapse; }
.appsec-table th, .appsec-table td { padding: 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--ant-color-border, #ddd); }
.appsec-table td:first-child { min-width: 220px; overflow-wrap: anywhere; }
.appsec-table small { display: block; max-width: 540px; margin-top: 4px; opacity: .8; }
</style>
