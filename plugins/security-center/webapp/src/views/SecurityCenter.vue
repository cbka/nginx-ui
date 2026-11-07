<script setup lang="ts">
import type { Decision, Scenario } from './normalize'
import type { ModSecurityConfig, SecurityEvent, SecuritySite, SecurityStatus } from '@/api/security_center'
import { ReloadOutlined } from '@antdv-next/icons'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import AppSecPanel from './AppSecPanel.vue'
import BulkInstall from './BulkInstall.vue'
import CommunitySharing from './CommunitySharing.vue'
import { canManageSecurity, crowdsecListResult, normalizeDecisions, normalizeScenarios, parseExcludedRules } from './normalize'
import { filterSecurityRows, paginateSecurityRows, SECURITY_PAGE_SIZE } from './pagination'
import SecurityEvents from './SecurityEvents.vue'
import { validAllowlistDraft } from './sitePolicy'
import SiteProtection from './SiteProtection.vue'

const { message, modal } = App.useApp()
const settings = useSettingsStore()
const initialNodeId = settings.node.id
let mounted = true
onBeforeUnmount(() => {
  mounted = false
})
function assertCurrentNode() {
  if (!mounted || !canManageSecurity(settings.node.id) || settings.node.id !== initialNodeId)
    throw new Error($gettext('Select the local controller and reopen Security Center before making changes.'))
}
const status = ref<SecurityStatus>()
const loading = ref(false)
const busy = ref(false)
const scenarioBulkBusy = ref(false)
const appsecBulkBusy = ref(false)
const error = ref('')
const decisionsError = ref('')
const scenariosError = ref('')
const wafError = ref('')
const decisions = ref<Decision[]>([])
const scenarios = ref<Scenario[]>([])
const scenarioSearch = ref('')
const scenarioPage = ref(1)
watch(scenarioSearch, () => {
  scenarioPage.value = 1
}, { flush: 'sync' })
const filteredScenarios = computed(() => filterSecurityRows(scenarios.value, scenarioSearch.value, item => `${item.name} ${item.status ?? ''} ${item.version ?? ''}`))
const paginatedScenarios = computed(() => paginateSecurityRows(filteredScenarios.value, scenarioPage.value))
const waf = ref<ModSecurityConfig>()
const savedWaf = ref('')
const exclusions = ref('')
const modsecurityAllowlist = ref('')
const crowdsecAllowlist = ref('')
function parseAllowlist(value: string) {
  return value.split(/[\s,]+/).filter(Boolean)
}
const applied = ref<string>()
const ban = reactive({ ip: '', duration: '4h', reason: '' })
const scenarioName = ref('')
const search = ref('')
const activeTab = ref('crowdsec')
const eventDraft = ref<{ site: string, event: SecurityEvent, action: 'exception' | 'block', revision: number }>()
const sites = ref<SecuritySite[]>([])
const siteError = ref('')
const selectedSite = ref('')
watch(selectedSite, () => {
  eventDraft.value = undefined
}, { flush: 'sync' })
const siteDirty = ref(false)
const siteBusy = ref(false)
const scopeOptions = computed(() => [
  {
    value: '',
    label: $gettext('Global defaults'),
  },
  ...sites.value.map(site => ({
    value: site.name,
    label: site.server_names.length
      ? `${site.name} — ${site.server_names.join(', ')}`
      : site.name,
  })),
])
const visibleDecisions = computed(() => decisions.value.filter(item =>
  `${item.value} ${item.reason} ${item.origin}`.toLowerCase().includes(search.value.toLowerCase()),
))
const excludedIds = computed(() => parseExcludedRules(exclusions.value))
const wafPayload = computed(() => waf.value && excludedIds.value
  ? {
      ...waf.value,
      excluded_rule_ids: excludedIds.value,
      modsecurity_allowlist: parseAllowlist(modsecurityAllowlist.value),
      crowdsec_allowlist: parseAllowlist(crowdsecAllowlist.value),
    }
  : undefined)
const wafDirty = computed(() => JSON.stringify(wafPayload.value) !== savedWaf.value)
const unsaved = computed(() => siteDirty.value || (wafDirty.value && !!waf.value))
const wafValid = computed(() => {
  const config = wafPayload.value
  return !!config && ['off', 'detection', 'block'].includes(config.appsec_mode ?? 'off') && validAllowlistDraft(config.modsecurity_allowlist) && validAllowlistDraft(config.crowdsec_allowlist) && [1, 2, 3, 4].includes(config.paranoia_level)
    && Number.isInteger(config.inbound_threshold) && config.inbound_threshold >= 1 && config.inbound_threshold <= 1000
    && Number.isInteger(config.outbound_threshold) && config.outbound_threshold >= 1 && config.outbound_threshold <= 1000
})
const canWaf = computed(() => !!status.value?.enabled && !!status.value?.modsecurity_enabled)
const canCrowdsec = computed(() => !!status.value?.enabled && !!status.value?.crowdsec_enabled)

async function loadCrowdsec() {
  decisionsError.value = ''
  scenariosError.value = ''
  const results = await Promise.allSettled([
    security.decisions(),
    security.scenarios(),
  ])
  const decisionResult = crowdsecListResult(results[0], normalizeDecisions, getErrorMessage)
  const scenarioResult = crowdsecListResult(results[1], normalizeScenarios, getErrorMessage)
  decisions.value = decisionResult.items
  decisionsError.value = decisionResult.error
  scenarios.value = scenarioResult.items
  scenariosError.value = scenarioResult.error
}

async function loadWaf() {
  wafError.value = ''
  try {
    waf.value = await security.modsecurity()
    waf.value.appsec_mode ??= 'off'
    exclusions.value = (waf.value.excluded_rule_ids ?? []).join(', ')
    modsecurityAllowlist.value = (waf.value.modsecurity_allowlist ?? []).join('\n')
    crowdsecAllowlist.value = (waf.value.crowdsec_allowlist ?? []).join('\n')
    savedWaf.value = JSON.stringify(wafPayload.value)
  }
  catch (e) {
    waf.value = undefined
    wafError.value = getErrorMessage(e)
  }
}

async function loadSites() {
  siteError.value = ''
  try {
    sites.value = (await security.sites()).items ?? []
  }
  catch (e) {
    siteError.value = getErrorMessage(e)
  }
}

async function refresh() {
  if (!canManageSecurity(settings.node.id))
    return
  loading.value = true
  error.value = ''
  applied.value = undefined
  try {
    status.value = await security.status()
    if (!canWaf.value) {
      sites.value = []
      selectedSite.value = ''
      eventDraft.value = undefined
      siteDirty.value = false
      siteError.value = ''
      waf.value = undefined
      wafError.value = ''
    }
    if (!canCrowdsec.value) {
      decisions.value = []
      scenarios.value = []
      decisionsError.value = ''
      scenariosError.value = ''
    }
    await Promise.all([
      canWaf.value
        ? loadSites()
        : Promise.resolve(),
      canCrowdsec.value
        ? loadCrowdsec()
        : Promise.resolve(),
      canWaf.value
        ? loadWaf()
        : Promise.resolve(),
    ])
  }
  catch (e) {
    status.value = undefined
    error.value = getErrorMessage(e)
  }
  finally {
    loading.value = false
  }
}

async function mutate(action: () => Promise<unknown>, reload: () => Promise<void>) {
  busy.value = true
  try {
    assertCurrentNode()
    await action()
    await reload()
    message.success($gettext('Change completed.'))
  }
  catch (e) {
    const detail = getErrorMessage(e)
    if (detail)
      message.error(detail)
    throw e
  }
  finally {
    busy.value = false
  }
}

function addBan() {
  if (busy.value || loading.value || !ban.ip.trim() || !ban.duration.trim() || !ban.reason.trim())
    return
  modal.confirm({
    title: $gettext('Block this IP address?'),
    content: $gettext('This may immediately interrupt access, including your own connection. IP: %{ip}', { ip: ban.ip }),
    okText: $gettext('Block IP'),
    okButtonProps: { danger: true },
    async onOk() {
      await mutate(() => security.addDecision({
        ip: ban.ip.trim(),
        duration: ban.duration.trim(),
        reason: ban.reason.trim(),
      }), loadCrowdsec)
      ban.ip = ''
      ban.reason = ''
    },
  })
}

function removeBan(item: Decision) {
  modal.confirm({
    title: $gettext('Remove this decision?'),
    content: $gettext('The decision for %{ip} will be removed. Other decisions may still apply, and CrowdSec can create new decisions.', { ip: item.value }),
    okText: $gettext('Remove decision'),
    okButtonProps: { danger: true },
    onOk: () => mutate(() => security.deleteDecision(item.id), loadCrowdsec),
  })
}

function changeScenario(name: string, action: 'install' | 'remove') {
  if (scenarioBulkBusy.value || appsecBulkBusy.value)
    return
  modal.confirm({
    title: action === 'remove'
      ? $gettext('Remove scenario?')
      : $gettext('Install scenario?'),
    content: $gettext('Scenario: %{name}. CrowdSec will reload its configuration. Removing a scenario disables its future detections.', { name }),
    okText: action === 'remove'
      ? $gettext('Remove')
      : $gettext('Install'),
    okButtonProps: { danger: action === 'remove' },
    async onOk() {
      if (scenarioBulkBusy.value || appsecBulkBusy.value)
        throw new Error($gettext('Bitte die laufende Sammelinstallation zuerst abschließen lassen.'))
      await mutate(() => security.changeScenario(name.trim(), action), loadCrowdsec)
      scenarioName.value = ''
    },
  })
}

function saveWaf() {
  if (!wafPayload.value || !wafValid.value)
    return
  const payload = {
    ...wafPayload.value,
    excluded_rule_ids: [...wafPayload.value.excluded_rule_ids],
    modsecurity_allowlist: [...wafPayload.value.modsecurity_allowlist],
    crowdsec_allowlist: [...wafPayload.value.crowdsec_allowlist],
  }
  modal.confirm({
    title: $gettext('Apply WAF configuration?'),
    content: $gettext('Nginx configuration will be checked and reloaded. Off disables inspection; DetectionOnly records matches without blocking. Excluded rule IDs no longer protect requests. The CrowdSec and AppSec defaults apply to websites that inherit them. AppSec detection records matches without blocking; block can reject requests. All global draft changes are saved together. IP allowlists bypass the respective protection; global allowlists also apply to websites with explicit settings.'),
    okText: $gettext('Validate and apply'),
    okButtonProps: { danger: payload.mode !== 'On' || !payload.crowdsec_enabled || payload.excluded_rule_ids.length > 0 || payload.modsecurity_allowlist.length > 0 || payload.crowdsec_allowlist.length > 0 },
    async onOk() {
      busy.value = true
      applied.value = undefined
      try {
        assertCurrentNode()
        const result = await security.saveModsecurity(payload)
        await loadWaf()
        applied.value = result.applied === true
          ? $gettext('Global defaults validated; Nginx reload requested locally. Synchronize each affected website to update its configured peers. Verify protection with traffic.')
          : $gettext('Configuration saved. Runtime application has not been confirmed.')
      }
      catch (e) {
        wafError.value = getErrorMessage(e)
        throw e
      }
      finally {
        busy.value = false
      }
    },
  })
}

function draftFromEvent(event: SecurityEvent, action: 'exception' | 'block') {
  if (unsaved.value || busy.value || siteBusy.value) {
    message.warning($gettext('Apply or discard current changes before preparing an event-based rule.'))
    return
  }
  if (!sites.value.some(site => site.name === event.vhost)) {
    message.warning($gettext('This event has no known website configuration. Select a verified website before creating rules.'))
    return
  }
  selectedSite.value = event.vhost
  eventDraft.value = {
    site: event.vhost,
    event,
    action,
    revision: Date.now(),
  }
  activeTab.value = 'modsecurity'
}

function prepareEventBan(event: SecurityEvent) {
  if (!event.client_ip)
    return
  ban.ip = event.client_ip
  ban.reason = `${event.scenario || event.message} (${event.vhost})`.slice(0, 200)
  activeTab.value = 'crowdsec'
  message.info($gettext('Global ban draft prepared. Check the IP, duration and reason before submitting; this can affect other websites.'))
}

onMounted(refresh)
</script>

<template>
  <ACard :title="$gettext('Security Center')" class="security-center">
    <template #extra>
      <AButton :loading="loading" :disabled="!canManageSecurity(settings.node.id) || busy || siteBusy || unsaved" @click="refresh">
        <template #icon>
          <ReloadOutlined />
        </template>
        {{ $gettext('Refresh') }}
      </AButton>
    </template>
    <details class="quick-help section-gap">
      <summary>{{ $gettext('Wie beginne ich? Schutz in drei Schritten') }}</summary>
      <ol>
        <li>{{ $gettext('Website auswählen, ModSecurity zunächst nur beobachten lassen und mit Paranoia-Level 1 beginnen.') }}</li>
        <li>{{ $gettext('Normale Abläufe testen: Anmeldung, Uploads und APIs. Treffer in den Ereignissen prüfen und belegte Fehlalarme möglichst eng ausnehmen.') }}</li>
        <li>{{ $gettext('Danach bei Bedarf blockieren. Speichern wirkt lokal; anschließend die gespeicherte Website-Richtlinie synchronisieren und jeden Peer bestätigen lassen. CrowdSec-Sperren separat prüfen.') }}</li>
      </ol>
    </details>
    <p class="muted">
      {{ $gettext('Manage CrowdSec decisions and OWASP CRS protection on the local controller. Edits apply locally; synchronize saved website policies to configured peers explicitly. Configured does not mean every website is protected.') }}
    </p>
    <AAlert v-if="!canManageSecurity(settings.node.id)" type="info" show-icon :message="$gettext('Security Center manages the local controller only. Select the local node to view or change its security settings.')" />
    <AAlert v-if="error" type="error" show-icon :message="error" />
    <ASpin :spinning="loading">
      <AAlert v-if="status && !status.enabled" type="info" show-icon :message="$gettext('The Security Center backend is not active on this node. An installed plugin alone does not confirm that protection is running.')" />
      <AAlert v-if="status?.enabled" type="info" show-icon :message="$gettext('Security Center is running. Engine integrations and website enforcement must be configured separately; this does not confirm that traffic is protected.')" class="section-gap" />
      <AAlert v-if="status?.enabled && !canCrowdsec" type="warning" show-icon :message="$gettext('CrowdSec integration is unavailable. Decisions and scenarios cannot be inspected or managed on this node.')" class="section-gap" />
      <AAlert v-if="status?.enabled && !canWaf" type="warning" show-icon :message="$gettext('ModSecurity integration is unavailable. Website policies and WAF settings cannot be inspected or managed on this node.')" class="section-gap" />
      <AAlert v-if="canWaf && !status?.runtime_integration_verified" type="warning" show-icon :message="$gettext('ModSecurity configuration integration has not been verified. Saved settings do not establish that the WAF is inspecting requests.')" class="section-gap" />
      <ATabs v-if="status?.enabled" v-model:active-key="activeTab">
        <ATabPane key="events" :tab="$gettext('Cluster events')">
          <AAlert v-if="!status.events_configured" type="info" show-icon :message="$gettext('Central event logging is not configured. Event availability is unknown; this does not mean no security events occurred.')" />
          <SecurityEvents v-else :sites="sites" @exclude="draftFromEvent($event, 'exception')" @block="draftFromEvent($event, 'block')" @ban="prepareEventBan" />
        </ATabPane>
        <ATabPane key="crowdsec" :tab="$gettext('CrowdSec')">
          <AAlert v-if="!canCrowdsec" type="info" show-icon :message="$gettext('CrowdSec is not configured on this node.')" />
          <template v-else>
            <CommunitySharing />
            <h3>{{ $gettext('Global active decisions') }}</h3>
            <AAlert v-if="decisionsError" type="error" show-icon :message="decisionsError" class="section-gap" />
            <p class="muted">
              {{ $gettext('Up to 100 local alerts are shown. Central API and simulated decisions are excluded. This is not a complete blocklist.') }}
            </p>
            <AInput v-model:value="search" :placeholder="$gettext('Filter by IP, reason or origin')" :aria-label="$gettext('Filter decisions')" allow-clear class="section-gap" />
            <div class="table-scroll">
              <table class="security-table decision-table">
                <thead><tr><th>{{ $gettext('IP / value') }}</th><th>{{ $gettext('Type / scope') }}</th><th>{{ $gettext('Reason') }}</th><th>{{ $gettext('Origin') }}</th><th>{{ $gettext('Remaining') }}</th><th>{{ $gettext('Actions') }}</th></tr></thead>
                <tbody>
                  <tr v-for="item in visibleDecisions" :key="item.id">
                    <td><code>{{ item.value }}</code></td><td>{{ item.type }} / {{ item.scope }}</td><td>{{ item.reason }}</td><td>{{ item.origin }}</td><td>{{ item.duration }}</td>
                    <td>
                      <AButton danger size="small" :disabled="busy || loading" @click="removeBan(item)">
                        {{ $gettext('Remove') }}
                      </AButton>
                    </td>
                  </tr>
                  <tr v-if="!visibleDecisions.length">
                    <td colspan="6">
                      {{ decisionsError ? $gettext('Decision list unavailable or incomplete.') : $gettext('No matching decisions.') }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <h3>{{ $gettext('Block an IP address') }}</h3>
            <AForm layout="vertical" @submit="addBan">
              <div class="form-grid">
                <AFormItem :label="$gettext('IP address')" :help="$gettext('Einzelne IPv4- oder IPv6-Adresse. Die Sperre gilt für alle Websites mit aktivierter CrowdSec-Durchsetzung, nicht nur für einen VHost.')">
                  <AInput v-model:value="ban.ip" placeholder="192.0.2.10" :maxlength="45" />
                </AFormItem>
                <AFormItem :label="$gettext('Duration')" :help="$gettext('Gültigkeitsdauer, z. B. 15m für 15 Minuten oder 4h für vier Stunden. Danach läuft die Sperre automatisch ab.')">
                  <AInput v-model:value="ban.duration" placeholder="4h" :maxlength="20" />
                </AFormItem>
                <AFormItem :label="$gettext('Reason')" :help="$gettext('Kurze Begründung für spätere Nachvollziehbarkeit, z. B. wiederholte Anmeldeversuche. Keine Passwörter oder personenbezogenen Inhalte eintragen.')">
                  <AInput v-model:value="ban.reason" :maxlength="200" />
                </AFormItem>
              </div>
              <AButton html-type="submit" danger :disabled="busy || loading || !ban.ip.trim() || !ban.duration.trim() || !ban.reason.trim()">
                {{ $gettext('Block IP') }}
              </AButton>
            </AForm>
            <h3>{{ $gettext('Global detection scenarios') }}</h3>
            <AAlert v-if="scenariosError" type="error" show-icon :message="scenariosError" class="section-gap" />
            <p class="muted">
              {{ $gettext('Szenarien erkennen Angriffsmuster in den gesammelten Logs, z. B. viele fehlgeschlagene Anmeldungen. Sie gelten für die zentrale Engine. Die Installation allein garantiert weder passende Eingangsdaten noch eine Sperre auf jeder Website. Verwende den exakten Namen aus dem CrowdSec Hub, z. B. crowdsecurity/http-probing.') }}
            </p>
            <AAlert v-if="!status.scenario_changes_enabled" type="info" show-icon :message="$gettext('Scenario changes are unavailable until a CrowdSec reload command is configured.')" class="section-gap" />
            <BulkInstall kind="scenarios" :disabled="busy || loading || appsecBulkBusy || !status.scenario_changes_enabled" @busy="scenarioBulkBusy = $event" @completed="loadCrowdsec" />
            <div class="inline-form section-gap">
              <AInput v-model:value="scenarioName" placeholder="crowdsecurity/http-probing" :aria-label="$gettext('Scenario name')" />
              <AButton :disabled="busy || loading || scenarioBulkBusy || appsecBulkBusy || !status.scenario_changes_enabled || !scenarioName.trim()" @click="changeScenario(scenarioName, 'install')">
                {{ $gettext('Install') }}
              </AButton>
            </div>
            <AInput v-model:value="scenarioSearch" allow-clear :placeholder="$gettext('Szenarien suchen')" :aria-label="$gettext('Szenarien suchen')" class="section-gap" />
            <p aria-live="polite">
              {{ $gettext('%{count} passende Einträge · 20 pro Seite', { count: String(filteredScenarios.length) }) }}
            </p>
            <div class="table-scroll">
              <table class="security-table">
                <thead><tr><th>{{ $gettext('Name') }}</th><th>{{ $gettext('Status') }}</th><th>{{ $gettext('Version') }}</th><th>{{ $gettext('Actions') }}</th></tr></thead>
                <tbody>
                  <tr v-for="item in paginatedScenarios.rows" :key="item.name">
                    <td>{{ item.name }}</td><td>{{ item.status || (item.installed ? $gettext('Installed') : $gettext('Available')) }}</td><td>{{ item.version }}</td>
                    <td>
                      <AButton :danger="item.installed" size="small" :disabled="busy || loading || scenarioBulkBusy || appsecBulkBusy || !status.scenario_changes_enabled" @click="changeScenario(item.name, item.installed ? 'remove' : 'install')">
                        {{ item.installed ? $gettext('Remove') : $gettext('Install') }}
                      </AButton>
                    </td>
                  </tr>
                  <tr v-if="!filteredScenarios.length">
                    <td colspan="4">
                      {{ scenariosError ? $gettext('Scenario list unavailable or incomplete.') : $gettext('Keine passenden Szenarien gefunden.') }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <APagination :current="paginatedScenarios.page" :total="paginatedScenarios.total" :page-size="SECURITY_PAGE_SIZE" :show-size-changer="false" :hide-on-single-page="true" class="section-gap" @change="scenarioPage = $event" />
          </template>
        </ATabPane>
        <ATabPane key="appsec" :tab="$gettext('CrowdSec AppSec')">
          <AAlert v-if="!canCrowdsec" type="info" show-icon :message="$gettext('CrowdSec ist auf diesem Knoten nicht eingerichtet.')" />
          <template v-else>
            <AAlert v-if="wafError" type="error" show-icon :message="wafError" class="section-gap" />
            <AAlert v-if="applied" type="warning" show-icon :message="applied" class="section-gap" />
            <AForm v-if="canWaf && waf" layout="vertical" class="section-gap" @submit="saveWaf">
              <AFormItem :label="$gettext('Globaler AppSec-Standard')" :help="$gettext('Gilt für Websites mit geerbtem AppSec-Modus. Aus beendet nur AppSec; Beobachten protokolliert ohne zu blockieren; Blockieren kann Angriffe abweisen. Dies schaltet nicht die zentrale Engine aus. Eigene Website-Einstellungen findest du unter WAF & website protection; AppSec ist dort unabhängig vom ModSecurity-Modus einstellbar.')">
                <ASelect v-model:value="waf.appsec_mode" :disabled="busy || siteBusy || loading" :options="[{ value: 'off', label: $gettext('Aus') }, { value: 'detection', label: $gettext('Beobachten – nicht blockieren') }, { value: 'block', label: $gettext('Blockieren') }]" />
              </AFormItem>
              <p class="muted">
                {{ $gettext('Beim Anwenden werden alle offenen globalen Änderungen gemeinsam gespeichert, auch aus dem WAF-Reiter. Anschließend betroffene Websites synchronisieren und die Prüfung mit Testverkehr bestätigen.') }}
              </p>
              <AButton type="primary" html-type="submit" :loading="busy" :disabled="loading || siteBusy || !wafValid || !wafDirty">
                {{ $gettext('Validate and apply') }}
              </AButton>
              <AButton class="unsaved" :disabled="busy || loading || !wafDirty" @click="loadWaf">
                {{ $gettext('Discard changes') }}
              </AButton>
            </AForm>
            <AAlert v-else type="info" show-icon :message="$gettext('Die Richtlinienverwaltung benötigt die vollständige Sicherheitsintegration auf diesem Knoten. Der AppSec-Bestand darunter bleibt unabhängig davon lesbar.')" class="section-gap" />
            <AppSecPanel class="section-gap" :other-busy="scenarioBulkBusy" @bulk-busy="appsecBulkBusy = $event" />
          </template>
        </ATabPane>
        <ATabPane key="modsecurity" :tab="$gettext('WAF & website protection')">
          <AFormItem :label="$gettext('Configuration scope')" :help="$gettext('Globale Vorgaben gelten für Websites, die sie erben. Wähle eine Website, um nur deren Schutz anzupassen.')">
            <ASelect v-model:value="selectedSite" :options="scopeOptions" show-search option-filter-prop="label" :disabled="!canWaf || busy || loading || siteBusy || unsaved" />
          </AFormItem>
          <p v-if="unsaved" class="muted">
            {{ $gettext('Apply or discard changes before switching scope.') }}
          </p>
          <AAlert v-if="siteError" type="warning" show-icon :message="siteError" class="section-gap" />
          <SiteProtection v-if="canWaf && selectedSite" :key="`${selectedSite}:${eventDraft?.revision ?? 0}`" :name="selectedSite" :draft="eventDraft?.site === selectedSite ? eventDraft : undefined" @busy="siteBusy = $event" @dirty="siteDirty = $event" />
          <template v-else>
            <AAlert v-if="!status.modsecurity_enabled" type="info" show-icon :message="$gettext('ModSecurity is not configured on this node.')" />
            <template v-else>
              <AAlert v-if="wafError" type="error" show-icon :message="wafError" class="section-gap" />
              <AAlert v-if="applied" type="warning" show-icon :message="applied" class="section-gap" />
              <AForm v-if="waf" layout="vertical" @submit="saveWaf">
                <AAlert type="info" show-icon :message="$gettext('These are configured settings. Protection also requires the ModSecurity connector and CRS includes to be enabled in each relevant website.')" class="section-gap" />
                <AFormItem :label="$gettext('Global CrowdSec enforcement default')" :help="$gettext('Applies to managed websites that inherit the global value. This does not start or stop the CrowdSec engine.')">
                  <ASwitch v-model:checked="waf.crowdsec_enabled" />
                </AFormItem>
                <div class="form-grid">
                  <AFormItem :label="$gettext('Inspection mode')" :help="$gettext('Zum Einstieg: nur beobachten. ModSecurity protokolliert dann Treffer ohne zu blockieren. CrowdSec-Sperren bleiben unabhängig davon wirksam. Aus beendet nur die ModSecurity-Prüfung.')">
                    <ASelect v-model:value="waf.mode" :options="[{ value: 'DetectionOnly', label: $gettext('Detection only — log without blocking') }, { value: 'On', label: $gettext('On — inspect and block') }, { value: 'Off', label: $gettext('Off — no inspection') }]" />
                  </AFormItem>
                  <AFormItem :label="$gettext('OWASP paranoia level')" :help="$gettext('Prüfstrenge: Stufe 1 ist der empfohlene Einstieg. Höhere Stufen aktivieren zusätzliche Regeln und können mehr berechtigte Anfragen beanstanden. Erst Fehlalarme prüfen, dann erhöhen.')">
                    <ASelect v-model:value="waf.paranoia_level" :options="[{ value: 1, label: $gettext('1 – Basis (Einstieg)') }, { value: 2, label: $gettext('2 – Erweitert') }, { value: 3, label: $gettext('3 – Streng') }, { value: 4, label: $gettext('4 – Sehr streng') }]" />
                  </AFormItem>
                  <AFormItem :label="$gettext('Inbound anomaly threshold')" :help="$gettext('Punktegrenze für eingehende Anfragen, Standard 5. Regeltreffer addieren Punkte; ab dieser Grenze wird im blockierenden Modus gesperrt. Höher bedeutet weniger Blockierungen, nicht stärkeren Schutz.')">
                    <AInputNumber v-model:value="waf.inbound_threshold" :min="1" :max="1000" :precision="0" />
                  </AFormItem>
                  <AFormItem :label="$gettext('Outbound anomaly threshold')" :help="$gettext('Punktegrenze für Antworten der Anwendung, Standard 4. Im blockierenden Modus können verdächtige Antworten zurückgehalten werden. Die Anfrage kann bereits verarbeitet worden sein.')">
                    <AInputNumber v-model:value="waf.outbound_threshold" :min="1" :max="1000" :precision="0" />
                  </AFormItem>
                </div>
                <p class="muted">
                  {{ $gettext('Paranoia-Level bestimmt, welche Regeln prüfen. Die Punktegrenze bestimmt, ab wann Treffer zur Sperre führen. Beides ist weder ein Prozentwert noch die Anzahl erlaubter Angriffe.') }}
                </p>
                <h3>{{ $gettext('Globale vertrauenswürdige IP-Adressen und Netze') }}</h3>
                <p class="muted">
                  {{ $gettext('Gilt zusätzlich für alle verwalteten Websites, auch mit eigenen Schutzwerten. Pro Zeile eine IPv4-/IPv6-Adresse oder ein CIDR-Netz; höchstens 400 Einträge pro Liste. Beispiele: 192.0.2.10, 192.0.2.0/24, 2001:db8::/64. Die Gültigkeit wird vor dem Anwenden serverseitig geprüft.') }}
                </p>
                <AFormItem :label="$gettext('ModSecurity: IP-Ausnahmen (Whitelist)')" :help="!validAllowlistDraft(parseAllowlist(modsecurityAllowlist)) ? $gettext('Bitte höchstens 400 IPv4-/IPv6-Adressen oder CIDR-Netze eingeben, ohne Hostnamen oder Regeltext.') : $gettext('Anfragen dieser Quelladressen überspringen die ModSecurity-Prüfung vollständig, einschließlich eigener Pfadsperren. CrowdSec bleibt unabhängig davon wirksam.')" :validate-status="!validAllowlistDraft(parseAllowlist(modsecurityAllowlist)) ? 'error' : undefined">
                  <ATextarea v-model:value="modsecurityAllowlist" :rows="3" placeholder="192.0.2.10&#10;2001:db8::/64" />
                </AFormItem>
                <AFormItem :label="$gettext('CrowdSec: IP-Ausnahmen (Whitelist)')" :help="!validAllowlistDraft(parseAllowlist(crowdsecAllowlist)) ? $gettext('Bitte höchstens 400 IPv4-/IPv6-Adressen oder CIDR-Netze eingeben, ohne Hostnamen oder Regeltext.') : $gettext('Für diese Quelladressen überspringt Nginx CrowdSec-IP-Sperren und die AppSec-Anfrageprüfung. Zentrale Entscheidungen, Erkennung und Community-Meldungen werden dadurch nicht gelöscht oder abgeschaltet. ModSecurity bleibt unabhängig aktiv.')" :validate-status="!validAllowlistDraft(parseAllowlist(crowdsecAllowlist)) ? 'error' : undefined">
                  <ATextarea v-model:value="crowdsecAllowlist" :rows="3" placeholder="192.0.2.10&#10;2001:db8::/64" />
                </AFormItem>
                <p class="muted">
                  {{ $gettext('Entscheidend ist die von Nginx ermittelte Client-IP. Hinter einem Proxy muss die vertrauenswürdige Weitergabe der echten Client-IP korrekt eingerichtet sein. Wird nur die NAT-Gateway-Adresse angezeigt, diese nicht freigeben: Sonst umgehen alle Besucher hinter diesem Gateway den jeweiligen Schutz. 0.0.0.0/0 nimmt alle IPv4-Adressen aus, ::/0 alle IPv6-Adressen.') }}
                </p>
                <AFormItem :label="$gettext('Excluded rule IDs')" :validate-status="excludedIds === undefined ? 'error' : undefined" :help="excludedIds === undefined ? $gettext('Use up to 200 OWASP CRS rule IDs (900000–999999), separated by commas or spaces.') : $gettext('Diese Regelnummern werden global ausgenommen. Bevorzuge bei Fehlalarmen eine Ausnahme nur für die betroffene Website, den Pfad und gegebenenfalls den Parameter. Kommagetrennte IDs, z. B. 942100; kein freier Regeltext.')">
                  <ATextarea v-model:value="exclusions" :rows="3" placeholder="920350, 942100" />
                </AFormItem>
                <AButton type="primary" html-type="submit" :loading="busy" :disabled="loading || !wafValid">
                  {{ $gettext('Validate and apply') }}
                </AButton>
                <AButton :disabled="busy || loading || !wafDirty" class="unsaved" @click="loadWaf">
                  {{ $gettext('Discard changes') }}
                </AButton>
                <span v-if="wafDirty" class="unsaved">{{ $gettext('Unsaved changes') }}</span>
              </AForm>
            </template>
          </template>
        </ATabPane>
      </ATabs>
    </ASpin>
  </ACard>
</template>

<style lang="less" scoped>
.security-center { min-width: 0; }
.quick-help summary { cursor: pointer; font-weight: 600; }
.quick-help li { margin-block: 8px; max-width: 85ch; }
.muted { color: var(--ant-color-text-secondary); }
.section-gap { margin-bottom: 16px; }
h3 { margin-top: 24px; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); gap: 0 16px; }
.inline-form { display: flex; gap: 8px; max-width: 600px; }
.table-scroll { overflow-x: auto; max-width: 100%; }
.security-table { width: 100%; border-collapse: collapse; text-align: left; }
.security-table th, .security-table td { padding: 12px; border-bottom: 1px solid var(--ant-color-border-secondary); vertical-align: top; overflow-wrap: anywhere; }
.decision-table { min-width: 710px; }
.decision-table td:nth-child(1), .decision-table td:nth-child(2), .decision-table td:nth-child(4), .decision-table td:nth-child(5), .decision-table td:nth-child(6) { white-space: nowrap; overflow-wrap: normal; }
.security-table th { color: var(--ant-color-text-secondary); font-weight: 500; }
.unsaved { margin-left: 12px; color: var(--ant-color-warning); }
</style>
