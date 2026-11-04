<script setup lang="ts">
import type { AppSecStatus } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { canManageSecurity } from './normalize'

const state = ref<AppSecStatus>()
const loading = ref(false)
const error = ref('')
const search = ref('')
const settings = useSettingsStore()
const initialNodeId = settings.node.id
let mounted = true
let generation = 0
onBeforeUnmount(() => {
  mounted = false
  generation++
})
const rows = computed(() => state.value
  ? [
      ...(state.value.collections ?? []).map(item => ({ ...item, kind: 'collection' })),
      ...(state.value.configs ?? []).map(item => ({ ...item, kind: 'config' })),
      ...(state.value.rules ?? []).map(item => ({ ...item, kind: 'rule' })),
    ].filter(item => `${item.name} ${item.description ?? ''}`.toLowerCase().includes(search.value.trim().toLowerCase()))
  : [])
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
      <AButton :loading="loading" @click="refresh">
        {{ $gettext('Status aktualisieren') }}
      </AButton>
    </div>
    <p>{{ $gettext('CrowdSec-Szenarien erkennen Muster in Logs. AppSec prüft dagegen einzelne HTTP-Anfragen auf bekannte Angriffe, bevor die Anwendung sie verarbeitet. Die offizielle Virtual-Patching-Sammlung liefert passende Schutzregeln. ModSecurity und vorhandene CrowdSec-IP-Sperren bleiben getrennte Schutzmechanismen.') }}</p>
    <AAlert v-if="error" type="error" show-icon :message="error" />
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
        <AInput v-model:value="search" allow-clear :placeholder="$gettext('Sammlungen, Konfigurationen und Regeln suchen')" :aria-label="$gettext('AppSec-Einträge suchen')" class="appsec-search" />
        <div class="appsec-table-wrap">
          <table class="appsec-table">
            <thead><tr><th>{{ $gettext('Eintrag') }}</th><th>{{ $gettext('Art') }}</th><th>{{ $gettext('Im Hub verfügbar') }}</th><th>{{ $gettext('Installiert') }}</th><th>{{ $gettext('In der Engine geladen') }}</th><th>{{ $gettext('Version') }}</th></tr></thead>
            <tbody>
              <tr v-for="item in rows" :key="`${item.kind}:${item.name}`">
                <td><strong>{{ item.name }}</strong><small v-if="item.description">{{ item.description }}</small><small v-if="item.tainted">{{ $gettext('Lokal geändert – Update-Verhalten prüfen') }}</small><small v-if="item.update_available">{{ $gettext('Update verfügbar') }}</small></td>
                <td>{{ item.kind === 'collection' ? $gettext('Sammlung') : item.kind === 'config' ? $gettext('Konfiguration') : $gettext('Regel') }}</td>
                <td>{{ item.available === true ? $gettext('Ja') : item.available === false ? $gettext('Nein') : $gettext('Unbekannt') }}</td>
                <td>{{ item.installed === true ? $gettext('Ja') : item.installed === false ? $gettext('Nein') : $gettext('Unbekannt') }}</td>
                <td>{{ item.loaded === true ? $gettext('Bestätigt') : item.loaded === false ? $gettext('Nicht geladen') : $gettext('Nicht bestätigt') }}</td>
                <td>{{ item.version || '—' }}</td>
              </tr>
              <tr v-if="!rows.length">
                <td colspan="6">
                  {{ $gettext('Keine passenden Einträge zurückgegeben. Das ist kein Nachweis für fehlenden Schutz.') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </ASpin>
  </section>
</template>

<style scoped>
.appsec-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }
.appsec-status { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.appsec-counts, .appsec-search { margin: 16px 0; }
.appsec-table-wrap { overflow-x: auto; }
.appsec-table { width: 100%; border-collapse: collapse; }
.appsec-table th, .appsec-table td { padding: 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--ant-color-border, #ddd); }
.appsec-table td:first-child { min-width: 220px; overflow-wrap: anywhere; }
.appsec-table small { display: block; max-width: 540px; margin-top: 4px; opacity: .8; }
</style>
