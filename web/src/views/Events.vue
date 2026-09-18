<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { api, notify, fmtTime, fmtNumber, actionLabel } from '../api'
import { t } from '../i18n'
import Icon from '../components/Icon.vue'

const route = useRoute()

const items = ref([])
const total = ref(0)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const auto = ref(true)
const expanded = ref(null)
let timer = null

// Filters can arrive in the URL - the overview links here with ?ip=... so an
// address in a ranking is one click from its log.
const q = route.query
const filters = ref({
  q: typeof q.q === 'string' ? q.q : '',
  ip: typeof q.ip === 'string' ? q.ip : '',
  action: typeof q.action === 'string' ? q.action : '',
  severity: typeof q.severity === 'string' ? q.severity : '',
  hours: Number(q.hours) || 24,
})
const page = ref(0)
const LIMIT = 50

async function load(spinner = false) {
  if (spinner) loading.value = true
  else refreshing.value = true
  const params = new URLSearchParams({
    limit: String(LIMIT),
    offset: String(page.value * LIMIT),
    hours: String(filters.value.hours),
  })
  for (const k of ['q', 'ip', 'action', 'severity']) {
    if (filters.value[k]) params.set(k, filters.value[k])
  }
  try {
    const res = await api.get(`/api/events?${params}`)
    items.value = res.items || []
    total.value = res.total || 0
    error.value = ''
  } catch (e) {
    error.value = e.message
    if (!spinner) notify(e.message, true)
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

function applyFilters() {
  page.value = 0
  load(true)
}

function clearFilters() {
  filters.value = { q: '', ip: '', action: '', severity: '', hours: 24 }
  applyFilters()
}

const hasFilters = () => filters.value.q || filters.value.ip || filters.value.action || filters.value.severity

async function banIP(ip) {
  if (!confirm(t('events.blockConfirm', { ip }))) return
  try {
    await api.post('/api/ips', { cidr: ip, kind: 'black', reason: t('events.blockReason') })
    notify(t('events.blocked', { ip }))
  } catch (e) {
    notify(e.message, true)
  }
}

function filterByIP(ip) {
  filters.value.ip = ip
  applyFilters()
}

function toggleRow(e) {
  expanded.value = expanded.value === e.id ? null : e.id
}

onMounted(() => {
  load(true)
  timer = setInterval(() => { if (auto.value && page.value === 0) load(false) }, 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('events.title') }}</h2>
      <p class="page-sub">{{ t('events.sub') }}</p>
    </div>
    <div class="page-actions">
      <label class="switch">
        <input v-model="auto" type="checkbox" />
        <span class="track"></span>
        <span class="sub">{{ t('events.autoRefresh') }}</span>
      </label>
    </div>
  </div>

  <form class="filter-bar" @submit.prevent="applyFilters">
    <div class="grow search">
      <Icon name="search" />
      <input v-model="filters.q" class="input" :placeholder="t('events.search')" />
    </div>
    <input v-model="filters.ip" class="input mono" style="width:160px" :placeholder="t('events.col.ip')" />
    <select v-model="filters.action" class="select" style="width:150px" :aria-label="t('events.col.action')">
      <option value="">{{ t('events.anyAction') }}</option>
      <option value="deny">{{ t('action.deny') }}</option>
      <option value="challenge">{{ t('action.challenge') }}</option>
      <option value="monitor">{{ t('action.monitor') }}</option>
      <option value="log">{{ t('action.log') }}</option>
    </select>
    <select v-model="filters.severity" class="select" style="width:150px" :aria-label="t('events.col.severity')">
      <option value="">{{ t('events.anySeverity') }}</option>
      <option value="critical">{{ t('severity.critical') }}</option>
      <option value="high">{{ t('severity.high') }}</option>
      <option value="medium">{{ t('severity.medium') }}</option>
      <option value="low">{{ t('severity.low') }}</option>
    </select>
    <select v-model="filters.hours" class="select" style="width:130px" :aria-label="t('overview.rangeLabel')">
      <option :value="1">{{ t('range.1h') }}</option>
      <option :value="24">{{ t('range.24h') }}</option>
      <option :value="72">{{ t('range.3d') }}</option>
      <option :value="168">{{ t('range.7d') }}</option>
    </select>
    <button type="submit" class="btn btn-primary"><Icon name="filter" />{{ t('common.filter') }}</button>
    <button v-if="hasFilters()" type="button" class="btn btn-ghost btn-sm" @click="clearFilters">{{ t('common.clear') }}</button>
  </form>

  <div class="card" :class="{ 'is-refreshing': refreshing }">
    <div v-if="loading" class="skel-rows">
      <div v-for="i in 8" :key="i" class="skel skel-line"></div>
    </div>

    <div v-else-if="error" class="empty">
      <Icon name="alert" />
      <b>{{ t('events.loadFailed') }}</b>
      <span class="empty-hint">{{ error }}</span>
      <button type="button" class="btn btn-sm" @click="load(true)"><Icon name="refresh" />{{ t('common.retry') }}</button>
    </div>

    <div v-else-if="!items.length" class="empty">
      <Icon name="shieldOk" />
      <b>{{ hasFilters() ? t('events.empty') : t('events.emptyAll') }}</b>
      <span class="empty-hint">{{ hasFilters() ? t('events.emptyHint') : t('events.emptyAllHint') }}</span>
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width:150px">{{ t('events.col.time') }}</th>
            <th style="width:140px">{{ t('events.col.ip') }}</th>
            <th style="width:120px">{{ t('events.col.action') }}</th>
            <th>{{ t('events.col.request') }}</th>
            <th>{{ t('events.col.rule') }}</th>
            <th style="width:100px">{{ t('events.col.severity') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="e in items" :key="e.id">
            <tr class="clickable" :aria-expanded="expanded === e.id ? 'true' : 'false'" tabindex="0" @click="toggleRow(e)" @keydown.enter.prevent="toggleRow(e)" @keydown.space.prevent="toggleRow(e)">
              <td class="sub nowrap">{{ fmtTime(e.ts) }}</td>
              <td class="mono">{{ e.ip }}<span v-if="e.country" class="dim"> · {{ e.country }}</span></td>
              <td>
                <span class="tag" :class="`tag-${e.action}`">
                  <span class="dot"></span>{{ actionLabel(e.action) }}
                </span>
              </td>
              <td class="mono truncate"><span class="dim">{{ e.method }}</span> {{ e.uri }}</td>
              <td class="truncate">{{ e.rule_name || e.reason }}</td>
              <td><span v-if="e.severity" class="tag" :class="`tag-${e.severity}`">{{ t(`severity.${e.severity}`) }}</span><span v-else class="dim">-</span></td>
              <td class="actions">
                <button type="button" class="btn btn-sm btn-ghost" :title="t('events.filterIP')" @click.stop="filterByIP(e.ip)"><Icon name="filter" /></button>
                <button type="button" class="btn btn-sm btn-danger" @click.stop="banIP(e.ip)">{{ t('events.blockIP') }}</button>
              </td>
            </tr>
            <tr v-if="expanded === e.id" class="detail">
              <td colspan="7">
                <div class="detail-grid">
                  <div><span>{{ t('events.detail.id') }}</span><b class="mono">{{ e.ray || '-' }}</b></div>
                  <div><span>{{ t('events.detail.host') }}</span><b class="mono">{{ e.host }}</b></div>
                  <div><span>{{ t('events.detail.path') }}</span><b class="mono">{{ e.uri }}</b></div>
                  <div><span>{{ t('events.detail.ua') }}</span><b class="mono">{{ e.ua || t('events.detail.emptyUA') }}</b></div>
                  <div><span>{{ t('events.detail.referer') }}</span><b class="mono">{{ e.referer || '-' }}</b></div>
                  <div><span>{{ t('events.detail.reason') }}</span><b>{{ e.reason || '-' }}</b></div>
                  <div><span>{{ t('events.detail.ruleId') }}</span><b class="mono">{{ e.rule_id || '-' }}</b></div>
                  <div><span>{{ t('events.detail.severity') }}</span><b>{{ e.severity ? t(`severity.${e.severity}`) : '-' }}</b></div>
                  <div><span>{{ t('events.detail.status') }}</span><b class="mono">{{ e.status }}</b></div>
                  <div v-if="e.country"><span>{{ t('events.detail.country') }}</span><b class="mono">{{ e.country }}</b></div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <div v-if="!loading && !error && items.length" class="card-foot">
      <span>{{ t('events.total', { count: fmtNumber(total) }) }}</span>
      <div class="spacer"></div>
      <button type="button" class="btn btn-sm" :disabled="page === 0" @click="page--; load(true)">{{ t('common.previous') }}</button>
      <span>{{ t('events.page', { n: page + 1 }) }}</span>
      <button type="button" class="btn btn-sm" :disabled="(page + 1) * LIMIT >= total" @click="page++; load(true)">{{ t('common.next') }}</button>
    </div>
  </div>
</template>

<style scoped>
.search { position: relative; }
.search .ico { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 15px; height: 15px; color: var(--ink-3); pointer-events: none; }
.search .input { padding-left: 32px; }
.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }
.detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 24px; padding: 6px 0; }
.detail-grid > div { display: flex; gap: 10px; font-size: 12.5px; min-width: 0; }
.detail-grid span { color: var(--ink-3); width: 130px; flex: 0 0 130px; }
.detail-grid b { font-weight: 500; word-break: break-all; }
@media (max-width: 760px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
