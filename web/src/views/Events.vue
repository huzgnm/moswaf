<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, notify, fmtTime, fmtNumber, actionLabel } from '../api'
import { t } from '../i18n'

const items = ref([])
const total = ref(0)
const loading = ref(true)
const auto = ref(true)
const expanded = ref(null)
let timer = null

const filters = ref({ q: '', ip: '', action: '', severity: '', hours: 24 })
const page = ref(0)
const LIMIT = 50

async function load(spinner = false) {
  if (spinner) loading.value = true
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
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  page.value = 0
  load(true)
}

async function banIP(ip) {
  if (!confirm(t('events.blockConfirm', { ip }))) return
  try {
    await api.post('/api/ips', { cidr: ip, kind: 'black', reason: t('events.blockReason') })
    notify(t('events.blocked', { ip }))
  } catch (e) {
    notify(e.message, true)
  }
}

onMounted(() => {
  load(true)
  timer = setInterval(() => { if (auto.value && page.value === 0) load(false) }, 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('events.title') }}</div>
        <div class="card-sub">{{ t('events.sub') }}</div>
      </div>
      <label class="switch">
        <input v-model="auto" type="checkbox" />
        <span class="track"></span>
        <span class="card-sub">{{ t('events.autoRefresh') }}</span>
      </label>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filters.q" class="input grow" :placeholder="t('events.search')" @keyup.enter="applyFilters" />
      <input v-model="filters.ip" class="input mono" style="width:150px" :placeholder="t('events.col.ip')" @keyup.enter="applyFilters" />
      <select v-model="filters.action" class="select" style="width:140px">
        <option value="">{{ t('events.anyAction') }}</option>
        <option value="deny">{{ t('action.deny') }}</option>
        <option value="challenge">{{ t('action.challenge') }}</option>
        <option value="monitor">{{ t('action.monitor') }}</option>
        <option value="log">{{ t('action.log') }}</option>
      </select>
      <select v-model="filters.severity" class="select" style="width:140px">
        <option value="">{{ t('events.anySeverity') }}</option>
        <option value="critical">{{ t('severity.critical') }}</option>
        <option value="high">{{ t('severity.high') }}</option>
        <option value="medium">{{ t('severity.medium') }}</option>
        <option value="low">{{ t('severity.low') }}</option>
      </select>
      <select v-model="filters.hours" class="select" style="width:130px">
        <option :value="1">{{ t('range.1h') }}</option>
        <option :value="24">{{ t('range.24h') }}</option>
        <option :value="72">{{ t('range.3d') }}</option>
        <option :value="168">{{ t('range.7d') }}</option>
      </select>
      <button class="btn btn-primary" @click="applyFilters">{{ t('common.filter') }}</button>
    </div>

    <div v-if="loading" class="empty">{{ t('common.loading') }}</div>
    <div v-else-if="!items.length" class="empty">{{ t('events.empty') }}</div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width:150px">{{ t('events.col.time') }}</th>
            <th style="width:130px">{{ t('events.col.ip') }}</th>
            <th style="width:110px">{{ t('events.col.action') }}</th>
            <th>{{ t('events.col.request') }}</th>
            <th>{{ t('events.col.rule') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="e in items" :key="e.id">
            <tr @click="expanded = expanded === e.id ? null : e.id" style="cursor:pointer">
              <td class="card-sub">{{ fmtTime(e.ts) }}</td>
              <td class="mono">{{ e.ip }}</td>
              <td>
                <span class="tag" :class="`tag-${e.action}`">
                  <span class="dot"></span>{{ actionLabel(e.action) }}
                </span>
              </td>
              <td class="mono truncate">{{ e.method }} {{ e.uri }}</td>
              <td class="truncate">{{ e.rule_name || e.reason }}</td>
              <td style="text-align:right">
                <button class="btn btn-sm btn-danger" @click.stop="banIP(e.ip)">{{ t('events.blockIP') }}</button>
              </td>
            </tr>
            <tr v-if="expanded === e.id">
              <td colspan="6" style="background:var(--surface-2)">
                <div class="detail">
                  <div><span>{{ t('events.detail.id') }}</span><b class="mono">{{ e.ray || '-' }}</b></div>
                  <div><span>{{ t('events.detail.host') }}</span><b class="mono">{{ e.host }}</b></div>
                  <div><span>{{ t('events.detail.path') }}</span><b class="mono">{{ e.uri }}</b></div>
                  <div><span>{{ t('events.detail.ua') }}</span><b class="mono">{{ e.ua || t('events.detail.emptyUA') }}</b></div>
                  <div><span>{{ t('events.detail.referer') }}</span><b class="mono">{{ e.referer || '-' }}</b></div>
                  <div><span>{{ t('events.detail.reason') }}</span><b>{{ e.reason || '-' }}</b></div>
                  <div><span>{{ t('events.detail.ruleId') }}</span><b class="mono">{{ e.rule_id || '-' }}</b></div>
                  <div><span>{{ t('events.detail.severity') }}</span><b>{{ e.severity ? t(`severity.${e.severity}`) : '-' }}</b></div>
                  <div><span>{{ t('events.detail.status') }}</span><b class="mono">{{ e.status }}</b></div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <div class="row" style="margin-top:14px">
      <span class="card-sub">{{ t('events.total', { count: fmtNumber(total) }) }}</span>
      <div class="spacer"></div>
      <button class="btn btn-sm" :disabled="page === 0" @click="page--; load(true)">{{ t('common.previous') }}</button>
      <span class="card-sub">{{ t('events.page', { n: page + 1 }) }}</span>
      <button class="btn btn-sm" :disabled="(page + 1) * 50 >= total" @click="page++; load(true)">{{ t('common.next') }}</button>
    </div>
  </div>
</template>

<style scoped>
.detail { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 24px; padding: 6px 0; }
.detail > div { display: flex; gap: 10px; font-size: 12.5px; min-width: 0; }
.detail span { color: var(--text-muted); width: 130px; flex: 0 0 130px; }
.detail b { font-weight: 500; word-break: break-all; }
</style>
