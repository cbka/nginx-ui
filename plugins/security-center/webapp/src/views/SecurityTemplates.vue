<script setup lang="ts">
import type { SecurityTemplate, SiteSecurityPolicy } from '@/api/security_center'
import security from '@/api/security_center'
import { getErrorMessage, useSettingsStore } from '@/runtime'
import { canManageSecurity } from './normalize'
import { cloneSitePolicy, templateChanges, validTemplatePolicy } from './sitePolicy'

const props = defineProps<{ name: string, policy?: SiteSecurityPolicy, disabled: boolean }>()
const emit = defineEmits<{ draft: [policy: SiteSecurityPolicy] }>()
const { modal } = App.useApp()
const settings = useSettingsStore()
const templates = ref<SecurityTemplate[]>([])
const selected = ref<string>()
const loading = ref(false)
const error = ref('')
const notice = defineModel<string>('notice', { default: '' })
const custom = reactive({ id: '', name: '', description: '' })
let mounted = true
onBeforeUnmount(() => {
  mounted = false
})
const chosen = computed(() => templates.value.find(item => item.id === selected.value))
const changes = computed(() => chosen.value && props.policy
  ? templateChanges(props.policy, chosen.value.policy)
  : [])
const canSave = computed(() => validTemplatePolicy(props.policy) && /^[a-z][a-z0-9-]{0,63}$/.test(custom.id) && custom.name.trim().length > 0 && custom.name.length <= 100 && custom.description.length <= 1000 && !templates.value.some(item => item.id === custom.id))
function guard(name: string) {
  if (!mounted || props.name !== name || props.disabled || !canManageSecurity(settings.node.id))
    throw new Error($gettext('The website or controller changed. Reopen the template before continuing.'))
}
async function load() {
  if (!canManageSecurity(settings.node.id))
    return
  loading.value = true
  try {
    templates.value = (await security.templates()).items
  }
  catch (e) { error.value = getErrorMessage(e) }
  finally { loading.value = false }
}
function draft() {
  if (!chosen.value || props.disabled)
    return
  const name = props.name
  const template = chosen.value
  const policy = cloneSitePolicy(template.policy)
  modal.confirm({
    title: $gettext('Replace the draft for %{name}?', { name }),
    content: $gettext('This replaces all fields of the current website policy draft, including WAF mode, CrowdSec enforcement, exceptions and blocked paths. Off or DetectionOnly modes and exclusions can reduce protection. Review the before/after table first. Global defaults and other websites are unchanged. Nothing is applied until you validate and apply the website policy.'),
    okText: $gettext('Use as unsaved draft'),
    onOk() {
      guard(name)
      emit('draft', policy)
      notice.value = $gettext('Template copied into the website draft. Review and validate before applying; peers require a separate synchronization.')
    },
  })
}
function save() {
  if (!canSave.value || !props.policy || props.disabled)
    return
  const name = props.name
  const id = custom.id
  const body = {
    name: custom.name.trim(),
    description: custom.description.trim(),
    policy: cloneSitePolicy(props.policy),
  }
  modal.confirm({
    title: $gettext('Save reusable security template?'),
    content: $gettext('The current draft will be stored as a custom template on this controller. No website configuration is applied.'),
    async onOk() {
      guard(name)
      loading.value = true
      error.value = ''
      try {
        await security.saveTemplate(id, body)
        await load()
        selected.value = id
        notice.value = $gettext('Custom template saved. No website was changed.')
        custom.id = ''
      }
      catch (e) {
        error.value = getErrorMessage(e)
        throw e
      }
      finally { loading.value = false }
    },
  })
}
function remove() {
  const template = chosen.value
  if (!template || template.builtin || props.disabled)
    return
  const name = props.name
  modal.confirm({
    title: $gettext('Delete custom template %{name}?', { name: template.name }),
    content: $gettext('Existing website policies remain unchanged.'),
    okButtonProps: { danger: true },
    async onOk() {
      guard(name)
      loading.value = true
      error.value = ''
      try {
        await security.deleteTemplate(template.id)
        selected.value = undefined
        await load()
      }
      catch (e) {
        error.value = getErrorMessage(e)
        throw e
      }
      finally { loading.value = false }
    },
  })
}
onMounted(load)
</script>

<template>
  <ACollapse class="templates">
    <ACollapsePanel key="templates" :header="$gettext('Reusable security templates')">
      <AAlert type="info" show-icon :message="$gettext('Security policy starters only: these do not configure proxy upstreams, TLS, Exchange endpoints or GitLab. Built-in templates are conservative starting points, not compatibility guarantees. Test your application after applying.')" />
      <AAlert v-if="error" type="error" show-icon :message="error" />
      <AAlert v-if="notice" type="info" show-icon :message="notice" />
      <AForm layout="vertical" :disabled="disabled || loading">
        <AFormItem :label="$gettext('Choose a built-in or custom template')">
          <ASelect v-model:value="selected" show-search option-filter-prop="label" :loading="loading" :options="templates.map(item => ({ value: item.id, label: `${item.name} (${item.builtin ? $gettext('Built-in') : $gettext('Custom')})` }))" />
        </AFormItem>
        <template v-if="chosen">
          <p>{{ chosen.description }}</p>
          <p><strong>{{ $gettext('Target website') }}: {{ name }}</strong></p>
          <ATable size="small" :data-source="changes" :pagination="false" row-key="field" :scroll="{ x: 650 }" :columns="[{ title: $gettext('Setting'), dataIndex: 'field' }, { title: $gettext('Current draft'), dataIndex: 'before' }, { title: $gettext('Template draft'), dataIndex: 'after' }]" />
          <ASpace wrap>
            <AButton @click="draft">
              {{ $gettext('Use as unsaved draft') }}
            </AButton>
            <AButton v-if="!chosen.builtin" danger @click="remove">
              {{ $gettext('Delete custom template') }}
            </AButton>
          </ASpace>
        </template>
        <ADivider>{{ $gettext('Save current policy as a custom template') }}</ADivider>
        <p>{{ $gettext('The complete current policy is saved, including disabled protection and exclusions. Review carefully before reusing it. Inherited values remain inherited.') }}</p>
        <AFormItem :label="$gettext('Unique template ID')">
          <AInput v-model:value="custom.id" :maxlength="64" placeholder="my-gitlab-policy" />
        </AFormItem>
        <AFormItem :label="$gettext('Name')">
          <AInput v-model:value="custom.name" :maxlength="100" />
        </AFormItem>
        <AFormItem :label="$gettext('Description')">
          <ATextarea v-model:value="custom.description" :maxlength="1000" />
        </AFormItem>
        <AButton :disabled="!canSave || disabled || loading" @click="save">
          {{ $gettext('Save custom template') }}
        </AButton>
      </AForm>
    </ACollapsePanel>
  </ACollapse>
</template>

<style scoped>
.templates { margin-block: 16px; }
.templates :deep(.ant-alert), .templates :deep(.ant-table-wrapper) { margin-bottom: 16px; }
.templates :deep(.ant-table-cell) { overflow-wrap: anywhere; }
</style>
