<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtNumber, notify } from '../api'
import { t } from '../i18n'
import TrafficChart from '../components/TrafficChart.vue'

const router = useRouter()
const hours = ref(6)
const overview = ref(null)
const series = ref([])
const status = ref(null)
const loading = ref(true)
let timer = null

const RANGES = [
  { h: 1, label: 'range.1h' },
  { h: 6, label: 'range.6h' },
  { h: 24, label: 'range.24h' },
  { h: 72, label: 'range.3d' },
]

// A minute with no data means no requests arrived -> fill it with 0 so the
// line stays true to real time instead of collapsing.
function densify(points, rangeHours) {
  const step = 60_000
  const end = Math.floor(Date.now() / step) * step
  const start = end - rangeHours * 3600_000
  const map = new Map()
  for (const p of points) {
    map.set(Math.floor(new Date(p.minute).getTime() / step) * step, p)
  }
  // Over longer ranges, bucket several minutes into one point to keep the chart light
  const bucket = rangeHours > 24 ? 15 : rangeHours > 6 ? 5 : 1
  const out = []
  for (let ms = start; ms <= end; ms += step * bucket) {
    let total = 0, blocked = 0, challenged = 0
    for (let k = 0; k < bucket; k++) {
      const p = map.get(ms + k * step)
      if (p) {
        total += p.total
        blocked += p.blocked
        challenged += p.challenged
      }
    }
    out.push({ minute: ms, total, blocked, challenged })
  }
  return out
}

const tiles = computed(() => {
  const o = overview.value
  if (!o) return []
  const blockRate = o.requests > 0 ? ((o.blocked / o.requests) * 100).toFixed(1) : '0.0'
  return [
    {
      label: t('overview.tile.requests'),
      value: fmtNumber(o.requests),
      sub: t('overview.tile.requestsSub', { hours: o.hours }),
    },
    {
      label: t('overview.tile.blocked'),
      value: fmtNumber(o.blocked),
      sub: t('overview.tile.blockedSub', { percent: blockRate }),
      tone: 'serious',
    },
    {
      label: t('overview.tile.challenged'),
      value: fmtNumber(o.challenged),
      sub: t('overview.tile.challengedSub'),
      tone: 'good',
    },
    {
      label: t('overview.tile.sites'),
      value: `${o.sites_active}/${o.sites_total}`,
      sub: t('overview.tile.sitesSub'),
    },
  ]
})

async function load(showSpinner = false) {
  if (showSpinner) loading.value = true
  try {
    const [o, ts, st] = await Promise.all([
      api.get(`/api/stats/overview?hours=${hours.value}`),
      api.get(`/api/stats/timeseries?hours=${hours.value}`),
      api.get('/api/system/status'),
    ])
    overview.value = o
    series.value = densify(ts, hours.value)
    status.value = st
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

function setRange(h) {
  hours.value = h
  load(true)
}

onMounted(() => {
  load(true)
  timer = setInterval(() => load(false), 15000)
})
onUnmounted(() => clearInterval(timer))

const dataplaneOk = computed(() => {
  const d = status.value?.dataplane
  return d && typeof d === 'object' && d.status === 'ok'
})

// Horizontal bars comparing magnitude within one ranking
function barWidth(b, list) {
  const max = Math.max(...list.map((x) => x.count), 1)
  return `${Math.max(3, (b.count / max) * 100)}%`
}
</script>

<template>
  <div v-if="overview?.under_attack" class="alert">
    {{ t('overview.alert') }}
  </div>

  <div class="grid grid-4">
    <div v-for="tile in tiles" :key="tile.label" class="card tile">
      <div class="tile-label">{{ tile.label }}</div>
      <div class="tile-value" :class="tile.tone">{{ tile.value }}</div>
      <div class="tile-sub">{{ tile.sub }}</div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('overview.traffic.title') }}</div>
        <div class="card-sub">{{ t('overview.traffic.sub') }}</div>
      </div>
      <div class="row">
        <button
          v-for="r in RANGES" :key="r.h"
          class="btn btn-sm"
          :style="hours === r.h ? 'border-color: var(--series-1); color: var(--text-primary)' : ''"
          @click="setRange(r.h)"
        >{{ t(r.label) }}</button>
      </div>
    </div>
    <TrafficChart :points="series" :loading="loading" />
  </div>

  <div class="grid grid-2" style="margin-top:16px">
    <div class="card">
      <div class="card-head">
        <div class="card-title">{{ t('overview.topIPs') }}</div>
        <button class="btn btn-sm" @click="router.push('/ips')">{{ t('overview.manageIPs') }}</button>
      </div>
      <div v-if="!overview?.top_attackers?.length" class="empty">{{ t('overview.noIPs') }}</div>
      <div v-else>
        <div v-for="b in overview.top_attackers" :key="b.key" class="bar-row">
          <span class="mono bar-label">{{ b.key }}</span>
          <span class="bar-track">
            <span class="bar-fill" :style="{ width: barWidth(b, overview.top_attackers) }"></span>
          </span>
          <span class="bar-val">{{ fmtNumber(b.count) }}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">{{ t('overview.topRules') }}</div>
        <button class="btn btn-sm" @click="router.push('/rules')">{{ t('overview.viewRules') }}</button>
      </div>
      <div v-if="!overview?.top_rules?.length" class="empty">{{ t('overview.noRules') }}</div>
      <div v-else>
        <div v-for="b in overview.top_rules" :key="b.key" class="bar-row">
          <span class="bar-label">{{ b.label }}</span>
          <span class="bar-track">
            <span class="bar-fill" :style="{ width: barWidth(b, overview.top_rules) }"></span>
          </span>
          <span class="bar-val">{{ fmtNumber(b.count) }}</span>
        </div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="card-head">
      <div class="card-title">{{ t('overview.system') }}</div>
      <div class="card-sub">{{ t('overview.configVersion', { version: status?.config_version ?? '-' }) }}</div>
    </div>
    <div class="row" style="gap:26px">
      <span class="tag" :class="status?.database === 'ok' ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>Postgres
      </span>
      <span class="tag" :class="status?.redis === 'ok' ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>Redis
      </span>
      <span class="tag" :class="dataplaneOk ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>{{ t('overview.dataplane') }}
      </span>
      <span class="card-sub">{{ t('overview.eventQueue', { count: fmtNumber(status?.event_queue ?? 0) }) }}</span>
    </div>
  </div>
</template>

<style scoped>
.alert {
  background: #2a1616; border: 1px solid #5a2a2a; color: #f3b9b9;
  padding: 11px 15px; border-radius: 10px; font-size: 13px; margin-bottom: 16px;
}
.tile-label { font-size: 12px; color: var(--text-secondary); }
.tile-value {
  font-size: 28px; font-weight: 600; margin: 6px 0 2px;
  font-variant-numeric: tabular-nums; letter-spacing: -.02em;
}
.tile-value.serious { color: var(--serious); }
.tile-value.good { color: var(--good); }
.tile-sub { font-size: 11.5px; color: var(--text-muted); }

.bar-row { display: flex; align-items: center; gap: 12px; padding: 6px 0; font-size: 12.5px; }
.bar-label { width: 150px; flex: 0 0 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary); }
.bar-track { flex: 1; height: 8px; background: var(--surface-2); border-radius: 4px; overflow: hidden; }
.bar-fill { display: block; height: 100%; background: var(--series-1); border-radius: 4px; }
.bar-val { width: 62px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-secondary); }
</style>
