<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, notify, fmtTime, fmtNumber, ACTION_LABELS } from '../api'

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
  if (!confirm(`Permanently block IP ${ip}?`)) return
  try {
    await api.post('/api/ips', { cidr: ip, kind: 'black', reason: 'Blocked from the attack log' })
    notify(`${ip} added to the blocklist`)
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
        <div class="card-title">Attack log</div>
        <div class="card-sub">
          Only requests that were blocked, challenged or matched a rule - normal traffic is not recorded
        </div>
      </div>
      <label class="switch">
        <input v-model="auto" type="checkbox" />
        <span class="track"></span>
        <span class="card-sub">Auto refresh</span>
      </label>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filters.q" class="input grow" placeholder="Search path, User-Agent or rule name" @keyup.enter="applyFilters" />
      <input v-model="filters.ip" class="input mono" style="width:150px" placeholder="IP" @keyup.enter="applyFilters" />
      <select v-model="filters.action" class="select" style="width:140px">
        <option value="">Any action</option>
        <option value="deny">Blocked</option>
        <option value="challenge">Challenge</option>
        <option value="monitor">Monitored</option>
        <option value="log">Logged</option>
      </select>
      <select v-model="filters.severity" class="select" style="width:140px">
        <option value="">Any severity</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select v-model="filters.hours" class="select" style="width:130px">
        <option :value="1">1 hour</option>
        <option :value="24">24 hours</option>
        <option :value="72">3 days</option>
        <option :value="168">7 days</option>
      </select>
      <button class="btn btn-primary" @click="applyFilters">Filter</button>
    </div>

    <div v-if="loading" class="empty">Loading...</div>
    <div v-else-if="!items.length" class="empty">No events match these filters</div>

    <table v-else class="table">
      <thead>
        <tr>
          <th style="width:150px">Time</th>
          <th style="width:130px">IP</th>
          <th style="width:110px">Action</th>
          <th>Request</th>
          <th>Rule / reason</th>
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
                <span class="dot"></span>{{ ACTION_LABELS[e.action] || e.action }}
              </span>
            </td>
            <td class="mono truncate">{{ e.method }} {{ e.uri }}</td>
            <td class="truncate">{{ e.rule_name || e.reason }}</td>
            <td style="text-align:right">
              <button class="btn btn-sm btn-danger" @click.stop="banIP(e.ip)">Block IP</button>
            </td>
          </tr>
          <tr v-if="expanded === e.id">
            <td colspan="6" style="background:var(--surface-2)">
              <div class="detail">
                <div><span>Event id</span><b class="mono">{{ e.ray || '-' }}</b></div>
                <div><span>Host</span><b class="mono">{{ e.host }}</b></div>
                <div><span>Full path</span><b class="mono">{{ e.uri }}</b></div>
                <div><span>User-Agent</span><b class="mono">{{ e.ua || '(empty)' }}</b></div>
                <div><span>Referer</span><b class="mono">{{ e.referer || '-' }}</b></div>
                <div><span>Reason</span><b>{{ e.reason || '-' }}</b></div>
                <div><span>Rule id</span><b class="mono">{{ e.rule_id || '-' }}</b></div>
                <div><span>Severity</span><b>{{ e.severity || '-' }}</b></div>
                <div><span>Status code</span><b class="mono">{{ e.status }}</b></div>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>

    <div class="row" style="margin-top:14px">
      <span class="card-sub">{{ fmtNumber(total) }} events in total</span>
      <div class="spacer"></div>
      <button class="btn btn-sm" :disabled="page === 0" @click="page--; load(true)">Previous</button>
      <span class="card-sub">Page {{ page + 1 }}</span>
      <button class="btn btn-sm" :disabled="(page + 1) * 50 >= total" @click="page++; load(true)">Next</button>
    </div>
  </div>
</template>

<style scoped>
.detail { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 24px; padding: 6px 0; }
.detail > div { display: flex; gap: 10px; font-size: 12.5px; min-width: 0; }
.detail span { color: var(--text-muted); width: 130px; flex: 0 0 130px; }
.detail b { font-weight: 500; word-break: break-all; }
</style>
