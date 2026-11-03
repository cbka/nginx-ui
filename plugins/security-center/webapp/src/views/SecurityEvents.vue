<script setup lang="ts">
import type { SecurityEvent, SecurityEvents, SecuritySite } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { canManageSecurity } from './normalize'

const props = defineProps<{ sites: SecuritySite[] }>()
const emit = defineEmits<{ exclude: [event: SecurityEvent], block: [event: SecurityEvent], ban: [event: SecurityEvent] }>()
const settings = useSettingsStore()
const { modal, message } = App.useApp()
const source = ref('modsecurity')
const vhost = ref('')
const since = ref('1h')
const node = ref('')
const observedNodes = ref<string[]>([])
const nodeOptions = computed(() => observedNodes.value.map(value => ({ value })))
const result = ref<SecurityEvents>()
const loading = ref(false)
const error = ref('')
let generation = 0
let mounted = true
onBeforeUnmount(() => {
  mounted = false
  generation++
})
const siteOptions = computed(() => [
  {
    value: '',
    label: $gettext('All websites'),
  },
  ...props.sites.map(site => ({ value: site.name, label: site.name })),
])
const siteNames = computed(() => new Set(props.sites.map(site => site.name)))
function canDraftExclusion(event: SecurityEvent) {
  return siteNames.value.has(event.vhost) && Number.isInteger(event.rule_id) && event.rule_id! >= 900000 && event.rule_id! <= 999999
}
function displayTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.valueOf())
    ? value
    : date.toLocaleString()
}
async function inspectRule(event: SecurityEvent) {
  if (!event.rule_id)
    return
  try {
    const catalog = await security.rules()
    const rule = catalog.items.find(item => item.id === event.rule_id)
    modal.info({
      title: $gettext('OWASP CRS rule %{id}', {
        id: String(event.rule_id),
      }),
      content: rule
        ? `${rule.message} — ${rule.file}`
        : $gettext('No matching rule was returned by the configured rule catalog. Do not assume the rule is absent when the catalog is truncated.'),
    })
  }
  catch (e) {
    const detail = getErrorMessage(e)
    if (detail)
      message.error(detail)
  }
}

async function load() {
  if (!canManageSecurity(settings.node.id))
    return
  const current = ++generation
  loading.value = true
  error.value = ''
  try {
    const response = await security.events({
      source: source.value,
      vhost: vhost.value || undefined,
      node: node.value.trim() || undefined,
      since: since.value,
      limit: 100,
    })
    if (mounted && current === generation) {
      result.value = response
      observedNodes.value = [
        ...new Set([
          ...observedNodes.value,
          ...response.items.map(event => event.node).filter(Boolean),
        ]),
      ].sort()
    }
  }
  catch (e) {
    if (mounted && current === generation) {
      result.value = undefined
      error.value = getErrorMessage(e)
    }
  }
  finally {
    if (current === generation)
      loading.value = false
  }
}
watch([source, vhost, since], load, { immediate: true })
</script>

<template>
  <div>
    <p class="muted">
      {{ $gettext('Events are queried from the central log service. Node and website identities come from collector labels, not from the untrusted request Host header.') }}
    </p>
    <AForm layout="vertical">
      <div class="filters">
        <AFormItem :label="$gettext('Source')" :help="$gettext('ModSecurity zeigt Regeltreffer an einzelnen Anfragen; CrowdSec zeigt die erfassten CrowdSec-Ereignisse. Ein Treffer ist nicht automatisch eine Blockierung.')">
          <ASelect v-model:value="source" :options="[{ value: 'modsecurity', label: 'ModSecurity / OWASP CRS' }, { value: 'crowdsec', label: 'CrowdSec' }]" />
        </AFormItem>
        <AFormItem :label="$gettext('Website')" :help="$gettext('Grenzt die Anzeige auf einen VHost ein. Ändert keine Schutzrichtlinien und macht eine IP-Sperre nicht websitebezogen.')">
          <ASelect v-model:value="vhost" :options="siteOptions" show-search option-filter-prop="label" />
        </AFormItem>
        <AFormItem :label="$gettext('Node (apply with refresh)')" :help="$gettext('Leer zeigt alle erfassten Knoten. Einen Namen auswählen oder eingeben und aktualisieren, um eine Instanz zu untersuchen.')">
          <AAutoComplete v-model:value="node" :options="nodeOptions" :placeholder="$gettext('All nodes')" allow-clear @select="load" />
        </AFormItem>
        <AFormItem :label="$gettext('Time range')" :help="$gettext('Zeitraum der Suche. Die Anzeige ist begrenzt; keine Treffer bedeuten nicht automatisch, dass keine Angriffe stattgefunden haben.')">
          <ASelect v-model:value="since" :options="[{ value: '1h', label: $gettext('Last hour') }, { value: '6h', label: $gettext('Last 6 hours') }, { value: '24h', label: $gettext('Last 24 hours') }]" />
        </AFormItem>
      </div>
      <AButton :loading="loading" @click="load">
        {{ $gettext('Refresh events') }}
      </AButton>
    </AForm>
    <AAlert v-if="error" type="error" show-icon :message="error" class="section-gap" />
    <AAlert v-if="result && !result.cluster_completeness_verified" type="warning" show-icon :message="$gettext('Complete coverage of all cluster nodes has not been verified. No events does not prove that no requests were blocked.')" class="section-gap" />
    <ASpin :spinning="loading">
      <p v-if="result" class="muted">
        {{ $gettext('Showing %{count} events, limited to %{limit} for the selected period.', { count: String(result.items.length), limit: String(result.limit) }) }}
      </p>
      <AEmpty v-if="result && !result.items.length" :description="$gettext('No events returned for these filters.')" />
      <article v-for="event in result?.items ?? []" :key="`${event.node}:${event.event_id}:${event.timestamp}`" class="event">
        <div class="event-head">
          <strong>{{ event.vhost || $gettext('Website not attributed') }}</strong>
          <span class="muted">{{ displayTime(event.timestamp) }}</span>
        </div>
        <div class="tags">
          <ATag class="source-ip">{{ $gettext('Quell-IP') }}: <code>{{ event.client_ip || $gettext('Nicht im Ereignis enthalten') }}</code></ATag><ATag>{{ event.node || $gettext('Node unknown') }}</ATag><ATag :color="event.source === 'modsecurity' ? 'orange' : 'blue'">
            {{ event.source }}
          </ATag><ATag v-if="event.rule_id">
            {{ $gettext('Rule') }} {{ event.rule_id }}
          </ATag><ATag v-if="event.scenario">
            {{ event.scenario }}
          </ATag><ATag v-if="event.action">
            {{ event.action }}
          </ATag>
        </div>
        <p class="event-message">
          {{ event.message }}
        </p>
        <div class="request">
          <code>{{ event.method || '—' }} {{ event.path || '—' }}</code>
        </div>
        <details>
          <summary>{{ $gettext('Request details') }}</summary>
          <dl><dt>{{ $gettext('Parameter') }}</dt><dd>{{ event.parameter || '—' }}</dd><dt>{{ $gettext('Request / transaction ID') }}</dt><dd>{{ event.transaction_id || '—' }}</dd><dt>{{ $gettext('Event ID') }}</dt><dd>{{ event.event_id }}</dd></dl>
        </details>
        <div class="actions">
          <AButton v-if="event.rule_id" @click="inspectRule(event)">
            {{ $gettext('Inspect rule') }}
          </AButton>
          <AButton v-if="event.source === 'modsecurity'" :disabled="!canDraftExclusion(event)" @click="emit('exclude', event)">
            {{ $gettext('Draft scoped exception') }}
          </AButton>
          <AButton v-if="event.path" :disabled="!siteNames.has(event.vhost)" @click="emit('block', event)">
            {{ $gettext('Draft WAF path block') }}
          </AButton>
          <AButton v-if="event.source === 'crowdsec'" :disabled="!event.client_ip" @click="emit('ban', event)">
            {{ $gettext('Prepare global IP ban') }}
          </AButton>
          <span class="muted">{{ event.source === 'modsecurity' ? $gettext('Draft only: inspect the website scope and apply explicitly. Review the exact URI and parameter scope before applying.') : $gettext('A global decision can affect every website enforcing CrowdSec. Review before submitting.') }}</span>
        </div>
      </article>
    </ASpin>
  </div>
</template>

<style scoped>
.muted { color: var(--ant-color-text-secondary); }
.filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); gap: 0 16px; }
.section-gap { margin-top: 16px; margin-bottom: 16px; }
.event { padding: 18px; border: 1px solid var(--ant-color-border-secondary); border-radius: 8px; margin-bottom: 12px; }
.event-head, .request { display: flex; flex-wrap: wrap; gap: 8px 20px; justify-content: space-between; }
.tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 10px; }
.event-message, code, dd { overflow-wrap: anywhere; }
.source-ip { white-space: normal; max-width: 100%; }
details { margin-top: 12px; } summary { cursor: pointer; color: var(--ant-color-text-secondary); }
dl { display: grid; grid-template-columns: minmax(120px, 180px) minmax(0,1fr); gap: 8px; } dd { margin: 0; }
.actions { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.actions span { font-size: 12px; flex: 1 1 260px; }
</style>
