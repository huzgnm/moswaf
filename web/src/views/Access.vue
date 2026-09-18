<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { t } from '../i18n'
import Segmented from '../components/Segmented.vue'
import Icon from '../components/Icon.vue'
import AccessRules from './AccessRules.vue'
import IPListPanel from '../components/IPListPanel.vue'

// Three ways to say "let this through" or "do not", under one heading.
//
// They were two entries in the sidebar and both of them read as "block or
// allow", so the first thing an operator had to work out was which page their
// question belonged on. The difference is real but it is about *how*, not about
// *what*, so it belongs inside the page: an address list is one address and no
// order, a custom rule combines conditions and is evaluated in the order the
// operator arranged.
const route = useRoute()
const router = useRouter()

const TABS = [
  { value: 'rules', label: 'access.tab.rules' },
  { value: 'black', label: 'access.tab.block' },
  { value: 'white', label: 'access.tab.allow' },
]

// The tab lives in the query string so a link to one of them is a link to one of
// them, and the back button walks between them.
const tab = computed(() => (TABS.some((x) => x.value === route.query.tab) ? route.query.tab : 'rules'))
const options = computed(() => TABS.map((x) => ({ value: x.value, label: t(x.label) })))

function setTab(value) {
  router.replace({ path: '/access', query: value === 'rules' ? {} : { tab: value } })
}
</script>

<template>
  <div class="tabs-row">
    <Segmented :model-value="tab" :options="options" :aria-label="t('nav.access')" @update:model-value="setTab" />

    <!-- Where this page sits in the sequence. Without it, a rule that never
         fires looks broken rather than out-ranked: the lists above it already
         answered, and nothing on the rule's own row can say so. -->
    <div class="order-note">
      <Icon name="info" />
      <div>
        <p>{{ t('access.pipeline') }}</p>
        <p class="allow-note">{{ t('access.pipelineAllow') }}</p>
      </div>
    </div>
  </div>

  <AccessRules v-if="tab === 'rules'" />
  <template v-else>
    <div class="page-head">
      <div>
        <h2>{{ t(tab === 'black' ? 'ips.blocklist' : 'ips.allowlist') }}</h2>
        <p class="page-sub">{{ t(tab === 'black' ? 'ips.blockSub' : 'ips.allowSub') }}</p>
      </div>
    </div>
    <IPListPanel :kind="tab" />
  </template>
</template>

<style scoped>
.tabs-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; min-width: 0; }
/* Three tabs are wider than a phone, so they scroll rather than stretch the page */
.tabs-row :deep(.seg) { max-width: 100%; overflow-x: auto; }
.order-note {
  display: flex; align-items: flex-start; gap: 8px; margin: 0;
  font-size: 12px; color: var(--ink-3); line-height: 1.55; max-width: 78ch;
}
.order-note p { margin: 0; }
.order-note .allow-note { margin-top: 4px; color: var(--ink-2); }
.order-note .ico { width: 14px; height: 14px; margin-top: 2px; color: var(--line-3); }
</style>
