<script setup lang="ts">
import { $gettext } from '../runtime'
</script>

<template>
  <section>
    <h3>{{ $gettext('Security Center settings') }}</h3>
    <p>{{ $gettext('Manage website policies, global ModSecurity rules, exceptions, templates and cluster events in Security Center.') }}</p>
    <p>{{ $gettext('The plugin switch controls the Security Center lifecycle. ModSecurity and CrowdSec require their server integrations; their availability is shown separately in Security Center.') }}</p>
    <AButton type="primary" href="#/security-center">
      {{ $gettext('Open Security Center') }}
    </AButton>
  </section>
</template>
