<script setup lang="ts">
import type { SecurityEvent, SiteSecurityPolicy, SiteSecurityState, SiteSyncResult } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage } from '@/lib/http'
import { useSettingsStore } from '@/pinia'
import { canManageSecurity, parseExcludedRules } from './normalize'
import SecurityTemplates from './SecurityTemplates.vue'
import { canSyncSavedPolicy, exceptionFromEvent, inheritedSitePolicy, validExactPath, validException, validSitePolicy } from './sitePolicy'

const props = defineProps<{ name: string, draft?: { event: SecurityEvent, action: 'exception' | 'block' } }>()
const emit = defineEmits<{ busy: [value: boolean], dirty: [value: boolean] }>()
const { modal } = App.useApp()
const settings = useSettingsStore()
const state = ref<SiteSecurityState>()
const policy = ref<SiteSecurityPolicy>()
const exclusions = ref('')
const blockedPaths = ref('')
let draftConsumed = false
const loading = ref(false)
const saving = ref(false)
const syncing = ref(false)
const syncResult = ref<SiteSyncResult>()
const error = ref('')
const resultText = ref('')
const templateNotice = ref('')
let generation = 0
let mounted = true
onBeforeUnmount(() => {
  mounted = false
  generation++
  emit('dirty', false)
  emit('busy', false)
})
const ids = computed(() => parseExcludedRules(exclusions.value))
const payload = computed(() => policy.value && ids.value
  ? {
      ...policy.value,
      excluded_rule_ids: ids.value,
      blocked_paths: blockedPaths.value.split(/\r?\n/).map(path => path.trim()).filter(Boolean),
    }
  : undefined)
const dirty = computed(() => JSON.stringify(payload.value) !== JSON.stringify(state.value?.policy))
const valid = computed(() => validSitePolicy(payload.value))
const syncAllowed = computed(() => canSyncSavedPolicy(state.value, dirty.value))
watch(dirty, value => emit('dirty', value))
watch([loading, saving, syncing], ([isLoading, isSaving, isSyncing]) => emit('busy', isLoading || isSaving || isSyncing))

function restoreForm() {
  resultText.value = ''
  templateNotice.value = ''
  if (!state.value)
    return
  policy.value = {
    ...state.value.policy,
    exceptions: state.value.policy.exceptions.map(item => ({ ...item })),
    blocked_paths: [...state.value.policy.blocked_paths],
    excluded_rule_ids: [
      ...(state.value.policy.excluded_rule_ids ?? []),
    ],
  }
  exclusions.value = policy.value.excluded_rule_ids.join(', ')
  blockedPaths.value = policy.value.blocked_paths.join('\n')
}

async function load() {
  if (!canManageSecurity(settings.node.id))
    return
  const currentGeneration = ++generation
  const name = props.name
  loading.value = true
  error.value = ''
  try {
    const response = await security.site(name)
    if (!mounted || currentGeneration !== generation)
      return
    state.value = response
    state.value.policy.excluded_rule_ids ??= []
    state.value.policy.exceptions ??= []
    state.value.policy.blocked_paths ??= []
    restoreForm()
    if (props.draft && !draftConsumed && policy.value && !state.value.replica) {
      draftConsumed = true
      if (props.draft.action === 'exception') {
        policy.value.exceptions.push(exceptionFromEvent(props.draft.event))
      }
      else {
        const path = props.draft.event.path?.split('?')[0] || ''
        blockedPaths.value = [...policy.value.blocked_paths, path].join('\n')
      }
      resultText.value = $gettext('Event-based draft prepared. Review the website, exact path and parameter below. Nothing has been applied yet.')
    }
  }
  catch (e) {
    if (currentGeneration === generation) {
      error.value = getErrorMessage(e)
      state.value = undefined
      policy.value = undefined
    }
  }
  finally {
    if (currentGeneration === generation)
      loading.value = false
  }
}

function templateDraft(next: SiteSecurityPolicy) {
  policy.value = next
  exclusions.value = next.excluded_rule_ids.join(', ')
  blockedPaths.value = next.blocked_paths.join('\n')
  resultText.value = $gettext('Unsaved template draft. Review all changes, then validate and apply to this website.')
}

function inheritDefaults() {
  if (state.value?.replica || syncing.value)
    return
  templateNotice.value = ''
  policy.value = inheritedSitePolicy()
  exclusions.value = ''
  blockedPaths.value = ''
  resultText.value = $gettext('Inherited defaults selected. Validate and apply to save this change.')
}

function apply() {
  if (!payload.value || !valid.value || state.value?.replica || syncing.value)
    return
  const name = props.name
  const change = {
    ...payload.value,
    excluded_rule_ids: [...payload.value.excluded_rule_ids],
    exceptions: payload.value.exceptions.map(item => ({ ...item })),
    blocked_paths: [...payload.value.blocked_paths],
  }
  modal.confirm({
    title: $gettext('Apply protection to %{name}?', { name }),
    content: $gettext('This changes every server block in this website configuration. Nginx will validate and reload. Disabling inspection or CrowdSec enforcement reduces protection; exclusions are added to global exclusions. Exact path block rules deny matching requests with HTTP 403 when WAF blocking is active.'),
    okText: $gettext('Validate and apply'),
    okButtonProps: { danger: change.modsecurity !== 'On' || change.crowdsec === 'off' || change.excluded_rule_ids.length > 0 || change.exceptions.length > 0 || change.blocked_paths.length > 0 },
    async onOk() {
      if (!mounted || props.name !== name || !canManageSecurity(settings.node.id))
        throw new Error($gettext('The website or controller changed. Reopen the policy before applying it.'))
      saving.value = true
      error.value = ''
      resultText.value = ''
      try {
        const result = await security.saveSite(name, change)
        await load()
        resultText.value = result.applied === true
          ? $gettext('Website configuration validated; Nginx reload requested locally. Synchronize the saved policy to update configured peers, then verify protection with actual traffic.')
          : $gettext('Policy saved; runtime application has not been confirmed.')
      }
      catch (e) {
        error.value = getErrorMessage(e)
        throw e
      }
      finally {
        saving.value = false
      }
    },
  })
}
function synchronize() {
  if (!syncAllowed.value || syncing.value)
    return
  const name = props.name
  modal.confirm({
    title: $gettext('Synchronize saved website protection?'),
    content: $gettext('The saved policy is sent only to this website’s configured node targets. This is not an atomic cluster update: some nodes may succeed while others fail. Review every result.'),
    okText: $gettext('Synchronize saved policy'),
    async onOk() {
      if (!mounted || props.name !== name || !canManageSecurity(settings.node.id))
        throw new Error($gettext('The website or controller changed. Reopen the policy before synchronizing.'))
      syncing.value = true
      error.value = ''
      syncResult.value = undefined
      try {
        syncResult.value = await security.syncSite(name)
      }
      catch (e) {
        error.value = getErrorMessage(e)
        throw e
      }
      finally {
        syncing.value = false
      }
    },
  })
}

watch(() => props.name, () => {
  resultText.value = ''
  void load()
}, { immediate: true })
</script>

<template>
  <ASpin :spinning="loading">
    <AAlert v-if="error" type="error" show-icon :message="error" class="section-gap" />
    <AAlert v-if="resultText" type="info" show-icon :message="resultText" class="section-gap" />
    <template v-if="state && policy">
      <AAlert v-if="state.replica" type="info" show-icon :message="$gettext('Read-only replica. Edit and synchronize this policy from its owner: %{owner}', { owner: state.owner })" class="section-gap" />
      <AAlert type="info" show-icon :message="$gettext('One policy applies to every server block and server name in this website file. Inherited settings follow future global changes; explicit values override them.')" class="section-gap" />
      <div class="effective section-gap">
        <strong>{{ $gettext('Effective saved policy') }}</strong>
        <div class="effective-tags">
          <ATag>{{ $gettext('WAF') }}: {{ state.effective.modsecurity.mode }}</ATag>
          <ATag>{{ $gettext('Paranoia') }}: {{ state.effective.modsecurity.paranoia_level }}</ATag>
          <ATag>{{ $gettext('Thresholds') }}: {{ state.effective.modsecurity.inbound_threshold }} / {{ state.effective.modsecurity.outbound_threshold }}</ATag>
          <ATag :color="state.effective.crowdsec ? 'green' : 'orange'">
            CrowdSec: {{ state.effective.crowdsec ? $gettext('Enforced') : $gettext('Not enforced') }}
          </ATag>
        </div>
        <p class="muted">
          {{ $gettext('Combined excluded rule IDs') }}: {{ state.effective.modsecurity.excluded_rule_ids?.join(', ') || $gettext('None') }}
        </p>
      </div>
      <SecurityTemplates v-model:notice="templateNotice" :name="name" :policy="payload" :disabled="state.replica || syncing || saving || loading" @draft="templateDraft" />
      <AForm layout="vertical" :disabled="state.replica || syncing" @finish="apply">
        <div class="policy-grid">
          <AFormItem :label="$gettext('WAF mode for this website')">
            <ASelect v-model:value="policy.modsecurity" :options="[{ value: 'inherit', label: $gettext('Inherit global setting') }, { value: 'DetectionOnly', label: $gettext('Detection only') }, { value: 'On', label: $gettext('On — inspect and block') }, { value: 'Off', label: $gettext('Off — no inspection') }]" />
          </AFormItem>
          <AFormItem :label="$gettext('CrowdSec enforcement for this website')">
            <ASelect v-model:value="policy.crowdsec" :options="[{ value: 'inherit', label: $gettext('Inherit global setting') }, { value: 'on', label: $gettext('Enforce CrowdSec decisions') }, { value: 'off', label: $gettext('Do not enforce CrowdSec decisions') }]" />
          </AFormItem>
          <AFormItem :label="$gettext('Paranoia level override')" :help="$gettext('Leave empty to inherit the global value.')">
            <AInputNumber v-model:value="policy.paranoia_level" :min="1" :max="4" :precision="0" :placeholder="$gettext('Inherit')" />
          </AFormItem>
          <AFormItem :label="$gettext('Inbound threshold override')" :help="$gettext('Leave empty to inherit the global value.')">
            <AInputNumber v-model:value="policy.inbound_threshold" :min="1" :max="1000" :precision="0" :placeholder="$gettext('Inherit')" />
          </AFormItem>
          <AFormItem :label="$gettext('Outbound threshold override')" :help="$gettext('Leave empty to inherit the global value.')">
            <AInputNumber v-model:value="policy.outbound_threshold" :min="1" :max="1000" :precision="0" :placeholder="$gettext('Inherit')" />
          </AFormItem>
        </div>
        <p class="muted">
          {{ $gettext('This CrowdSec setting controls request enforcement only. Decisions and detection scenarios remain global and can still protect other websites.') }}
        </p>
        <AFormItem :label="$gettext('Additional rule exclusions for this website')" :validate-status="ids === undefined ? 'error' : undefined" :help="ids === undefined ? $gettext('Use up to 200 OWASP CRS rule IDs (900000–999999), separated by commas or spaces.') : $gettext('These IDs are added to global exclusions. Clearing this list does not remove global exclusions.')">
          <ATextarea v-model:value="exclusions" :rows="3" placeholder="942100" />
        </AFormItem>
        <h3>{{ $gettext('Scoped rule exceptions') }}</h3>
        <p class="muted">
          {{ $gettext('Exclude a CRS rule for an exact path, a specific query/body parameter, or both. Parameter names refer to ARGS only; header exceptions are not supported. Paths omit query strings.') }}
        </p>
        <div v-for="(exception, index) in policy.exceptions" :key="index" class="exception-row">
          <div class="policy-grid">
            <AFormItem :label="$gettext('Rule ID')">
              <AInputNumber v-model:value="exception.rule_id" :min="900000" :max="999999" :precision="0" />
            </AFormItem>
            <AFormItem :label="$gettext('Exact path (optional)')">
              <AInput v-model:value="exception.path" placeholder="/api/search" :maxlength="512" />
            </AFormItem>
            <AFormItem :label="$gettext('ARGS parameter (optional)')">
              <AInput v-model:value="exception.parameter" placeholder="q" :maxlength="100" />
            </AFormItem>
          </div>
          <p v-if="!validException(exception)" class="invalid">
            {{ $gettext('Enter a CRS rule ID and at least one valid exact path or ARGS parameter. Quotes, query strings and configuration directives are not allowed.') }}
          </p>
          <p v-else class="muted">
            {{ $gettext('Draft scope') }}: {{ name }} · {{ $gettext('Rule') }} {{ exception.rule_id }} · {{ exception.path || $gettext('All paths') }} · {{ exception.parameter ? `ARGS:${exception.parameter}` : $gettext('All rule targets') }}
          </p>
          <AButton size="small" :disabled="saving || state.replica || syncing" @click="policy.exceptions.splice(index, 1)">
            {{ $gettext('Remove from draft') }}
          </AButton>
        </div>
        <AButton :disabled="saving || state.replica || syncing || policy.exceptions.length >= 100" @click="policy.exceptions.push({ rule_id: 0, path: '', parameter: '' })">
          {{ $gettext('Add scoped exception') }}
        </AButton>
        <h3>{{ $gettext('Custom exact-path block rules') }}</h3>
        <AFormItem :label="$gettext('Paths to deny with HTTP 403')" :help="$gettext('One exact path per line, without a query string. Applies to this website only. DetectionOnly logs matches without blocking; Off disables inspection.')" :validate-status="payload?.blocked_paths.some(path => !validExactPath(path)) ? 'error' : undefined">
          <ATextarea v-model:value="blockedPaths" :rows="3" placeholder="/private/export" />
        </AFormItem>
        <AAlert v-if="payload && !valid" type="warning" show-icon :message="$gettext('The draft contains invalid values. Check rule IDs, path and parameter formats, duplicate paths and the maximum of 100 exceptions or path rules.')" class="section-gap" />
        <ASpace wrap>
          <AButton type="primary" html-type="submit" :loading="saving" :disabled="loading || !valid || state.replica || syncing">
            {{ $gettext('Validate and apply') }}
          </AButton>
          <AButton :disabled="loading || saving || state.replica || syncing" @click="inheritDefaults">
            {{ $gettext('Use inherited defaults') }}
          </AButton>
          <AButton :disabled="loading || saving || !dirty || state.replica || syncing" @click="restoreForm">
            {{ $gettext('Discard changes') }}
          </AButton>
          <span v-if="dirty" class="muted">{{ $gettext('Unsaved changes') }}</span>
        </ASpace>
      </AForm>
      <section class="sync-section">
        <h3>{{ $gettext('Synchronize saved policy') }}</h3>
        <p class="muted">
          {{ $gettext('Saving applies locally. This separate action distributes the saved website policy to its configured peers; results can differ per node.') }}
        </p>
        <p v-if="state.revision" class="muted">
          {{ $gettext('Saved revision') }}: <code>{{ state.revision }}</code>
        </p>
        <AButton :loading="syncing" :disabled="loading || saving || !syncAllowed" @click="synchronize">
          {{ $gettext('Synchronize to configured peers') }}
        </AButton>
        <AAlert v-if="syncResult" :type="syncResult.results.some(item => item.status === 'failed' || item.status === 'unsupported') ? 'warning' : 'info'" show-icon :message="syncResult.message" class="section-gap" />
        <p v-if="syncResult && !syncResult.results.length" class="muted">
          {{ $gettext('No peer results returned. No cluster-wide application has been confirmed.') }}
        </p>
        <div v-for="item in syncResult?.results ?? []" :key="item.node_id" class="peer-result">
          <strong>{{ item.node }}</strong>
          <ATag :color="item.status === 'applied' ? 'green' : item.status === 'failed' ? 'red' : 'orange'">
            {{ item.status }}
          </ATag>
          <span>{{ item.message }}</span>
          <code v-if="item.revision">{{ item.revision.slice(0, 12) }}</code>
        </div>
      </section>
    </template>
  </ASpin>
</template>

<style scoped>
.peer-result { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 12px 0; border-bottom: 1px solid var(--ant-color-border-secondary); }
.sync-section code { overflow-wrap: anywhere; }
.exception-row { padding: 16px; border: 1px solid var(--ant-color-border-secondary); border-radius: 8px; margin-bottom: 12px; }
.invalid { color: var(--ant-color-error); }
h3 { margin-top: 24px; }
.section-gap { margin-bottom: 16px; }
.muted { color: var(--ant-color-text-secondary); }
.policy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); gap: 0 16px; }
.effective { padding: 16px; border: 1px solid var(--ant-color-border-secondary); border-radius: 8px; }
.effective-tags { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 6px; }
</style>
