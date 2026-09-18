<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtNumber, fmtTime, actionLabel } from '../api'
import { t, intlTag } from '../i18n'
import { setScope, clearScope } from '../ui'
import TrafficChart from '../components/TrafficChart.vue'
import DefenseRing from '../components/DefenseRing.vue'
import Sparkline from '../components/Sparkline.vue'
import Segmented from '../components/Segmented.vue'
import RankList from '../components/RankList.vue'
import Icon from '../components/Icon.vue'

const router = useRouter()

// The window every figure on this page is measured over. One control, above
// everything it scopes, so the hero, the band, the chart and the tables always
// agree with each other.
const hours = ref(24)
const RANGES = [
  { value: 1,  label: 'range.1h' },
  { value: 6,  label: 'range.6h' },
  { value: 24, label: 'range.24h' },
  { value: 72, label: 'range.3d' },
]
const rangeOptions = computed(() => RANGES.map((r) => ({ value: r.value, label: t(r.label) })))
const rangeLabel = computed(() => t(RANGES.find((r) => r.value === hours.value)?.label || 'range.24h'))

const overview = ref(null)
const series = ref([])
const previous = ref(null)      // totals of the window before this one, for deltas
const status = ref(null)
const recent = ref([])
const loading = ref(true)       // nothing on screen yet
const refreshing = ref(false)   // there is a frame; hold it while new data arrives
const error = ref('')
const updatedAt = ref(null)
let timer = null

const MAX_HOURS = 168   // the server clamps here; asking for more returns less than asked

// How many minutes one point on the chart covers. Longer ranges bucket several
// minutes together to keep the line light enough to read.
function bucketFor(rangeHours) {
  return rangeHours > 24 ? 15 : rangeHours > 6 ? 5 : 1
}

// The last bucket that has finished. The one in progress is left out of every
// figure on this page on purpose: it holds a fraction of a bucket's traffic, so
// plotting it draws a cliff at the right-hand edge and reading it back as "the
// latest minute" reports a number that is always too low.
function lastCompleteBucket(rangeHours) {
  const size = bucketFor(rangeHours) * 60_000
  return Math.floor(Date.now() / size) * size - size
}

// A minute with no data means no requests arrived -> fill it with 0 so the
// line stays true to real time instead of collapsing.
function densify(points, rangeHours, endMs) {
  const step = 60_000
  const end = endMs
  const start = end - rangeHours * 3600_000
  const map = new Map()
  for (const p of points) map.set(Math.floor(new Date(p.minute).getTime() / step) * step, p)
  const bucket = bucketFor(rangeHours)
  const out = []
  for (let ms = start; ms <= end; ms += step * bucket) {
    let total = 0, blocked = 0, challenged = 0
    for (let k = 0; k < bucket; k++) {
      const p = map.get(ms + k * step)
      if (p) { total += p.total; blocked += p.blocked; challenged += p.challenged }
    }
    out.push({ minute: ms, total, blocked, challenged })
  }
  return out
}

// Sum of the window before the current one, from the same fetch. Only possible
// when twice the range still fits in what the server will return.
function sumBefore(points, rangeHours, endMs) {
  const start = endMs - rangeHours * 3600_000
  const prevStart = start - rangeHours * 3600_000
  let total = 0, blocked = 0, any = false
  for (const p of points) {
    const ms = new Date(p.minute).getTime()
    if (ms >= prevStart && ms < start) { total += p.total; blocked += p.blocked; any = true }
  }
  return any ? { total, blocked } : null
}

async function load(first = false) {
  if (first) { loading.value = true; error.value = '' }
  else refreshing.value = true
  const h = hours.value
  const fetchHours = Math.min(h * 2, MAX_HOURS)
  try {
    const [o, ts, st, ev] = await Promise.all([
      api.get(`/api/stats/overview?hours=${h}`),
      api.get(`/api/stats/timeseries?hours=${fetchHours}`),
      api.get('/api/system/status'),
      api.get(`/api/events?hours=${h}&limit=8`),
    ])
    // Guard against a slow response landing after the range changed
    if (h !== hours.value) return
    const end = lastCompleteBucket(h)
    overview.value = o
    series.value = densify(ts, h, end)
    previous.value = fetchHours >= h * 2 ? sumBefore(ts, h, end) : null
    status.value = st
    recent.value = ev.items || []
    updatedAt.value = new Date()
    error.value = ''
    setScope(rangeLabel.value, updatedAt.value)
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

function setRange(h) {
  hours.value = h
  load(!overview.value)
}

onMounted(() => {
  load(true)
  timer = setInterval(() => load(false), 15000)
})
onUnmounted(() => { clearInterval(timer); clearScope() })

// ---------------------------------------------------------------- derived

const dataplaneOk = computed(() => {
  const d = status.value?.dataplane
  return d && typeof d === 'object' && d.status === 'ok'
})

// The hero answers "is the site protected right now" in one line. Priority:
// an attack in progress, then a data plane that is not filtering, then nothing
// to protect, then the good case.
const state = computed(() => {
  const o = overview.value
  if (!o) return { tone: 'idle', icon: 'shield', title: t('overview.state.loading'), desc: '' }
  if (o.under_attack) {
    return { tone: 'attack', icon: 'alert', title: t('overview.state.attack'), desc: t('overview.state.attackDesc') }
  }
  if (status.value && !dataplaneOk.value) {
    return { tone: 'warn', icon: 'shieldOff', title: t('overview.state.dataplane'), desc: t('overview.state.dataplaneDesc') }
  }
  if (!o.sites_active) {
    return { tone: 'warn', icon: 'shieldOff', title: t('overview.state.noSites'), desc: t('overview.state.noSitesDesc') }
  }
  return {
    tone: 'ok', icon: 'shieldOk',
    title: t('overview.state.ok', { active: o.sites_active, total: o.sites_total }),
    desc: t('overview.state.okDesc', { hours: rangeLabel.value }),
  }
})

const ringState = computed(() => {
  if (!overview.value || !overview.value.requests) return 'idle'
  return state.value.tone === 'idle' ? 'ok' : state.value.tone
})

const challengedRate = computed(() => {
  const o = overview.value
  if (!o || !o.requests) return 0
  return Math.round((o.challenged / o.requests) * 1000) / 10
})

function pct(n) {
  return `${(n ?? 0).toLocaleString(intlTag(), { maximumFractionDigits: 1 })}%`
}

// Sparklines: about two dozen points from whatever bucket the chart uses
function spark(key) {
  const pts = series.value
  if (pts.length < 2) return []
  const want = 24
  const per = Math.max(1, Math.ceil(pts.length / want))
  const out = []
  for (let i = 0; i < pts.length; i += per) {
    let s = 0
    for (let k = i; k < Math.min(pts.length, i + per); k++) s += pts[k][key]
    out.push(s)
  }
  return out
}

// Change against the previous window of the same length. Null when the previous
// window has no data - a delta against nothing is not a trend.
function delta(cur, prev) {
  if (prev === null || prev === undefined || prev <= 0) return null
  const d = ((cur - prev) / prev) * 100
  if (Math.abs(d) < 0.5) return { dir: 'flat', text: '0%' }
  return { dir: d > 0 ? 'up' : 'down', text: `${d > 0 ? '+' : '−'}${Math.abs(d).toLocaleString(intlTag(), { maximumFractionDigits: 0 })}%` }
}
const reqDelta = computed(() => delta(overview.value?.requests, previous.value?.total))
const blockedDelta = computed(() => delta(overview.value?.blocked, previous.value?.blocked))

// Requests per second is shown with the precision it has: 0.3 is informative,
// 1,284.29 is not.
function fmtQps(q) {
  if (q === null || q === undefined) return '0'
  return Number(q).toLocaleString(intlTag(), { maximumFractionDigits: q >= 10 ? 0 : 1 })
}

// A two-letter code is what the dataset stores; the browser knows the names, in
// whatever language the dashboard is in.
const countryNames = computed(() => {
  try { return new Intl.DisplayNames([intlTag()], { type: 'region' }) } catch { return null }
})
function countryName(item) {
  if (!item.key) return '?'
  try { return countryNames.value?.of(item.key) || item.key } catch { return item.key }
}

const geoReady = computed(() => status.value?.geoip && status.value.geoip.ranges > 0)

// Action counts for the window, in a fixed order, only the ones that happened
const actionCounts = computed(() => {
  const ev = overview.value?.events || {}
  return ['deny', 'challenge', 'monitor', 'log', 'verify']
    .filter((a) => ev[a] > 0)
    .map((a) => ({ action: a, count: ev[a] }))
})

function investigateIP(item) {
  router.push({ path: '/events', query: { ip: item.key } })
}
function openEvent(e) {
  router.push({ path: '/events', query: { ip: e.ip } })
}

function severityClass(sev) {
  return sev ? `tag-${sev}` : 'tag-low'
}
</script>

<template>
  <!-- filters: one row, above everything they scope -->
  <div class="filter-bar">
    <span class="filter-label">{{ t('overview.rangeLabel') }}</span>
    <Segmented v-model="hours" :options="rangeOptions" :aria-label="t('overview.rangeLabel')" @update:model-value="setRange" />
    <div class="meta">
      <template v-if="updatedAt">
        <span class="live" aria-hidden="true"></span>
        <span>{{ t('overview.autoRefresh', { time: fmtTime(updatedAt) }) }}</span>
      </template>
      <span v-else>{{ t('common.loading') }}</span>
    </div>
  </div>

  <div v-if="error && !overview" class="alert alert-critical" role="alert">
    <Icon name="alert" />
    <div class="alert-body">
      <b>{{ t('overview.loadFailed') }}</b> {{ error }}
      <div style="margin-top:8px"><button type="button" class="btn btn-sm" @click="load(true)"><Icon name="refresh" />{{ t('common.retry') }}</button></div>
    </div>
  </div>
  <div v-else-if="error" class="alert alert-warn" role="status">
    <Icon name="alert" />
    <div class="alert-body">{{ t('overview.refreshFailed', { error }) }}</div>
  </div>

  <!-- hero: the defence centre -->
  <section class="hero" :class="[state.tone, { 'is-refreshing': refreshing }]" aria-live="polite">
    <div class="hero-main">
      <div class="hero-eyebrow"><Icon name="shield" style="width:13px;height:13px" />{{ t('overview.hero.eyebrow') }}</div>
      <div class="hero-state" :class="state.tone">
        <Icon :name="state.icon" />
        <span v-if="loading" class="skel" style="width:260px">&nbsp;</span>
        <span v-else>{{ state.title }}</span>
      </div>
      <p class="hero-desc" v-if="!loading">{{ state.desc }}</p>

      <div class="hero-figure">
        <span v-if="loading" class="hero-number skel" style="width:200px">&nbsp;</span>
        <span v-else class="hero-number">{{ fmtNumber(overview.requests) }}</span>
        <span class="hero-number-label">{{ t('overview.hero.requestsIn', { range: rangeLabel }) }}</span>
      </div>

      <div class="hero-stats">
        <div class="hero-stat">
          <span class="k"><span class="key" style="background:var(--series-2)"></span>{{ t('overview.hero.blocked') }}</span>
          <span v-if="loading" class="v skel" style="width:80px">&nbsp;</span>
          <span v-else class="v">{{ fmtNumber(overview.blocked) }}<small>{{ pct(overview.blocked_rate) }}</small></span>
        </div>
        <div class="hero-stat">
          <span class="k"><span class="key" style="background:var(--series-3)"></span>{{ t('overview.hero.challenged') }}</span>
          <span v-if="loading" class="v skel" style="width:80px">&nbsp;</span>
          <span v-else class="v">{{ fmtNumber(overview.challenged) }}<small>{{ pct(challengedRate) }}</small></span>
        </div>
        <div class="hero-stat">
          <span class="k">{{ t('overview.hero.qps') }}</span>
          <span v-if="loading" class="v skel" style="width:60px">&nbsp;</span>
          <span v-else class="v">{{ fmtQps(overview.qps) }}<small>req/s</small></span>
        </div>
        <div class="hero-stat" v-if="reqDelta">
          <span class="k">{{ t('overview.hero.trend') }}</span>
          <span class="v"><span class="delta" :class="reqDelta.dir">{{ reqDelta.text }}</span></span>
        </div>
      </div>

      <div class="hero-actions">
        <router-link class="btn btn-sm" to="/events"><Icon name="events" />{{ t('overview.hero.openLog') }}</router-link>
        <router-link v-if="overview && !overview.sites_total" class="btn btn-sm btn-primary" to="/sites"><Icon name="plus" />{{ t('overview.hero.addSite') }}</router-link>
        <router-link v-else class="btn btn-sm" to="/access"><Icon name="ban" />{{ t('overview.hero.openIPs') }}</router-link>
      </div>
    </div>

    <div class="hero-art">
      <DefenseRing
        :blocked-rate="overview?.blocked_rate || 0"
        :challenged-rate="challengedRate"
        :state="ringState"
        :center-label="t('overview.hero.ringLabel')"
      />
    </div>
  </section>

  <!-- primary figures -->
  <section class="card stat-band" :class="{ 'is-refreshing': refreshing }" :aria-label="t('overview.kpi.aria')">
    <div class="stat-cell">
      <div class="stat-label">{{ t('overview.tile.requests') }}</div>
      <div class="stat-value" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.requests) }}</div>
      <div class="stat-meta">
        <span v-if="reqDelta" class="delta" :class="reqDelta.dir">{{ reqDelta.text }}</span>
        <span>{{ reqDelta ? t('overview.tile.vsPrevious') : t('overview.tile.requestsSub', { hours: rangeLabel }) }}</span>
      </div>
      <div class="stat-spark"><Sparkline :values="spark('total')" color="var(--series-1)" wash="var(--series-1-wash)" /></div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">{{ t('overview.tile.blocked') }}</div>
      <div class="stat-value serious" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.blocked) }}</div>
      <div class="stat-meta">
        <span v-if="blockedDelta" class="delta bad" :class="blockedDelta.dir">{{ blockedDelta.text }}</span>
        <span>{{ overview ? t('overview.tile.blockedSub', { percent: pct(overview.blocked_rate) }) : '' }}</span>
      </div>
      <div class="stat-spark"><Sparkline :values="spark('blocked')" color="var(--series-2)" wash="rgba(194, 65, 12, .08)" /></div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">{{ t('overview.tile.qps') }}</div>
      <div class="stat-value" :class="{ skel: loading }">{{ loading ? '' : fmtQps(overview.qps) }}</div>
      <div class="stat-meta"><span>{{ t('overview.tile.qpsSub') }}</span></div>
      <div class="stat-spark"><Sparkline :values="spark('challenged')" color="var(--series-3)" wash="rgba(100, 116, 139, .1)" /></div>
      <div class="stat-meta"><span class="key-inline"></span>{{ t('overview.tile.sparkChallenged') }}</div>
    </div>
    <div class="stat-cell">
      <div class="stat-label">{{ t('overview.tile.visitors') }}</div>
      <div class="stat-value" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.visitors) }}</div>
      <div class="stat-meta"><span>{{ t('overview.tile.visitorsSub') }}</span></div>
      <div class="stat-meta" v-if="overview"><span>{{ t('overview.tile.uniqueIPsInline', { n: fmtNumber(overview.unique_ips) }) }}</span></div>
    </div>
  </section>

  <!-- secondary figures -->
  <section class="card stat-strip" :class="{ 'is-refreshing': refreshing }">
    <div class="strip-cell">
      <span class="k" :title="t('overview.tile.pageViews')">{{ t('overview.tile.pageViews') }}</span>
      <span class="v" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.page_views) }}</span>
    </div>
    <div class="strip-cell">
      <span class="k" :title="t('overview.tile.uniqueIPs')">{{ t('overview.tile.uniqueIPs') }}</span>
      <span class="v" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.unique_ips) }}</span>
    </div>
    <div class="strip-cell" :title="t('overview.tile.errors4xxHint')">
      <span class="k" :title="t('overview.tile.errors4xx')">{{ t('overview.tile.errors4xx') }}</span>
      <span class="v" :class="{ skel: loading, serious: overview && overview.rate_4xx >= 20 }">{{ loading ? '' : fmtNumber(overview.errors_4xx) }}<small v-if="overview">{{ pct(overview.rate_4xx) }}</small></span>
    </div>
    <div class="strip-cell" :title="t('overview.tile.blocked4xxSub')">
      <span class="k" :title="t('overview.tile.blocked4xx')">{{ t('overview.tile.blocked4xx') }}</span>
      <span class="v good" :class="{ skel: loading }">{{ loading ? '' : fmtNumber(overview.blocked_4xx) }}</span>
    </div>
    <div class="strip-cell" :title="t('overview.tile.errors5xxHint')">
      <span class="k" :title="t('overview.tile.errors5xx')">{{ t('overview.tile.errors5xx') }}</span>
      <span class="v" :class="{ skel: loading, serious: overview && overview.errors_5xx > 0 }">{{ loading ? '' : fmtNumber(overview.errors_5xx) }}<small v-if="overview">{{ pct(overview.rate_5xx) }}</small></span>
    </div>
    <div class="strip-cell">
      <span class="k" :title="t('overview.tile.sites')">{{ t('overview.tile.sites') }}</span>
      <span class="v" :class="{ skel: loading }">{{ loading ? '' : `${overview.sites_active}/${overview.sites_total}` }}</span>
    </div>
  </section>

  <!-- traffic -->
  <section class="card">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('overview.traffic.title') }}</div>
        <div class="card-sub">{{ t('overview.traffic.sub', { range: rangeLabel }) }}</div>
      </div>
    </div>
    <TrafficChart :points="series" :loading="loading" :refreshing="refreshing" :error="!overview ? error : ''" :hours="hours" @retry="load(true)" />
  </section>

  <!-- threats -->
  <section class="grid grid-3" :class="{ 'is-refreshing': refreshing }">
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('overview.topRules') }}</div>
          <div class="card-sub">{{ t('overview.topRulesSub') }}</div>
        </div>
        <router-link class="btn-link" to="/rules">{{ t('overview.viewRules') }}<Icon name="arrowR" /></router-link>
      </div>
      <div v-if="loading" class="skel-list"><div v-for="i in 4" :key="i" class="skel skel-line"></div></div>
      <div v-else-if="!overview?.top_rules?.length" class="empty compact"><Icon name="rules" />{{ t('overview.noRules') }}</div>
      <RankList v-else :items="overview.top_rules.slice(0, 6)" tone="serious" />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('overview.topIPs') }}</div>
          <div class="card-sub">{{ t('overview.topIPsSub') }}</div>
        </div>
        <router-link class="btn-link" to="/access">{{ t('overview.manageIPs') }}<Icon name="arrowR" /></router-link>
      </div>
      <div v-if="loading" class="skel-list"><div v-for="i in 4" :key="i" class="skel skel-line"></div></div>
      <div v-else-if="!overview?.top_attackers?.length" class="empty compact"><Icon name="ban" />{{ t('overview.noIPs') }}</div>
      <RankList v-else :items="overview.top_attackers.slice(0, 6)" mono clickable @pick="investigateIP" />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('overview.topCountries') }}</div>
          <div class="card-sub">{{ t('overview.topCountriesSub') }}</div>
        </div>
        <a class="btn-link dim" href="https://db-ip.com" target="_blank" rel="noopener noreferrer">{{ t('overview.geoAttribution') }}<Icon name="external" /></a>
      </div>
      <div v-if="loading" class="skel-list"><div v-for="i in 4" :key="i" class="skel skel-line"></div></div>
      <div v-else-if="!overview?.top_countries?.length" class="empty compact">
        <Icon name="globe" />
        <span>{{ geoReady ? t('overview.noCountries') : t('overview.geoMissing') }}</span>
      </div>
      <RankList v-else :items="overview.top_countries.slice(0, 6)" tone="violet" :label-of="countryName" />
    </div>
  </section>

  <!-- recent activity -->
  <section class="card" :class="{ 'is-refreshing': refreshing }">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('overview.recent.title') }}</div>
        <div class="card-sub">
          <template v-if="actionCounts.length">
            <span v-for="(a, i) in actionCounts" :key="a.action">{{ i ? ' · ' : '' }}{{ fmtNumber(a.count) }} {{ actionLabel(a.action).toLowerCase() }}</span>
            {{ ' ' }}{{ t('overview.recent.inRange', { range: rangeLabel }) }}
          </template>
          <template v-else>{{ t('overview.recent.sub') }}</template>
        </div>
      </div>
      <router-link class="btn btn-sm" to="/events"><Icon name="events" />{{ t('overview.recent.openAll') }}</router-link>
    </div>

    <div v-if="loading" class="skel-list"><div v-for="i in 5" :key="i" class="skel skel-line"></div></div>
    <div v-else-if="!recent.length" class="empty">
      <Icon name="shieldOk" />
      <b>{{ t('overview.recent.empty') }}</b>
      <span class="empty-hint">{{ t('overview.recent.emptyHint') }}</span>
    </div>
    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('events.col.time') }}</th>
            <th>{{ t('events.col.ip') }}</th>
            <th>{{ t('events.col.site') }}</th>
            <th>{{ t('events.col.rule') }}</th>
            <th>{{ t('events.col.action') }}</th>
            <th>{{ t('events.col.severity') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in recent" :key="e.id" class="clickable" tabindex="0" @click="openEvent(e)" @keydown.enter="openEvent(e)">
            <td class="sub nowrap">{{ fmtTime(e.ts) }}</td>
            <td class="mono">{{ e.ip }}</td>
            <td class="mono truncate" style="max-width:180px">{{ e.host || '-' }}</td>
            <td class="truncate">{{ e.rule_name || e.reason || '-' }}</td>
            <td><span class="tag" :class="`tag-${e.action}`"><span class="dot"></span>{{ actionLabel(e.action) }}</span></td>
            <td><span v-if="e.severity" class="tag" :class="severityClass(e.severity)">{{ t(`severity.${e.severity}`) }}</span><span v-else class="dim">-</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- system -->
  <section class="card system" :class="{ 'is-refreshing': refreshing }">
    <div class="card-head" style="margin-bottom:10px">
      <div class="card-title">{{ t('overview.system') }}</div>
      <div class="card-sub">{{ t('overview.configVersion', { version: status?.config_version ?? '-' }) }}</div>
    </div>
    <div class="sys-row">
      <span class="sys-item"><Icon name="db" /><span>Postgres</span><span class="tag" :class="status?.database === 'ok' ? 'tag-ok' : 'tag-deny'"><span class="dot"></span>{{ status ? (status.database === 'ok' ? t('overview.sys.ok') : t('overview.sys.error')) : '…' }}</span></span>
      <span class="sys-item"><Icon name="server" /><span>Redis</span><span class="tag" :class="status?.redis === 'ok' ? 'tag-ok' : 'tag-deny'"><span class="dot"></span>{{ status ? (status.redis === 'ok' ? t('overview.sys.ok') : t('overview.sys.error')) : '…' }}</span></span>
      <span class="sys-item"><Icon name="shield" /><span>{{ t('overview.dataplane') }}</span><span class="tag" :class="dataplaneOk ? 'tag-ok' : 'tag-deny'"><span class="dot"></span>{{ status ? (dataplaneOk ? t('overview.sys.ok') : t('overview.sys.unreachable')) : '…' }}</span></span>
      <span class="sys-item"><Icon name="inbox" /><span>{{ t('overview.eventQueue', { count: fmtNumber(status?.event_queue ?? 0) }) }}</span></span>
      <span class="sys-item" v-if="status?.geoip"><Icon name="globe" /><span>{{ geoReady ? t('overview.sys.geoReady', { n: fmtNumber(status.geoip.ranges) }) : t('overview.sys.geoPending') }}</span></span>
    </div>
  </section>
</template>

<style scoped>
.skel-list { display: flex; flex-direction: column; gap: 12px; padding: 6px 0; }
.skel-list .skel-line:nth-child(2) { width: 85%; }
.skel-list .skel-line:nth-child(3) { width: 70%; }
.skel-list .skel-line:nth-child(4) { width: 60%; }
.key-inline { width: 10px; height: 2px; display: inline-block; margin-right: 6px; background: var(--series-3); }
.sys-row { display: flex; gap: 22px; flex-wrap: wrap; font-size: 12.5px; color: var(--ink-2); }
.sys-item { display: inline-flex; align-items: center; gap: 8px; }
.sys-item .ico { width: 15px; height: 15px; color: var(--ink-3); }
.hero-main { min-width: 0; }
.card-head .btn-link.dim { color: var(--ink-3); font-size: 11.5px; }
</style>
