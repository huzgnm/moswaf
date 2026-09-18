<script setup>
import { ref, computed } from 'vue'
import { fmtNumber, fmtShortTime, fmtTime } from '../api'
import { t } from '../i18n'
import Icon from './Icon.vue'

const props = defineProps({
  points: { type: Array, default: () => [] },   // [{ minute, total, blocked, challenged }]
  loading: { type: Boolean, default: false },   // first load: nothing to show yet
  refreshing: { type: Boolean, default: false },// background refresh: keep the frame
  error: { type: String, default: '' },
  hours: { type: Number, default: 6 },
})
const emit = defineEmits(['retry'])

// All three series share the same unit (requests), so they share one y axis.
// Colours are fixed to their meaning, never cycled.
const SERIES = [
  { key: 'total',      label: 'chart.total',      color: 'var(--series-1)', area: true },
  { key: 'blocked',    label: 'chart.blocked',    color: 'var(--series-2)' },
  { key: 'challenged', label: 'chart.challenged', color: 'var(--series-3)' },
]

const hidden = ref(new Set())
function toggle(key) {
  const next = new Set(hidden.value)
  // Never hide the last visible series - an empty plot answers nothing
  if (next.has(key)) next.delete(key)
  else if (next.size < SERIES.length - 1) next.add(key)
  hidden.value = next
}
const visible = computed(() => SERIES.filter((s) => !hidden.value.has(s.key)))

const W = 900, H = 280
const PAD = { top: 18, right: 18, bottom: 30, left: 56 }
const plotW = W - PAD.left - PAD.right
const plotH = H - PAD.top - PAD.bottom

const svgEl = ref(null)
const hoverIdx = ref(-1)
const showTable = ref(false)

// Tidy tick steps: 1, 2, 5 times a power of ten, so the axis reads 0/500/1,000
function niceStep(max, ticks) {
  const raw = max / ticks
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)))
  const n = raw / mag
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10
  return step * mag
}

const yMax = computed(() => {
  let m = 0
  for (const p of props.points) for (const s of visible.value) m = Math.max(m, p[s.key] || 0)
  if (m <= 0) return 10
  const step = niceStep(m, 4)
  return Math.ceil(m / step) * step
})

const yTicks = computed(() => {
  const step = yMax.value / 4
  const out = []
  for (let i = 0; i <= 4; i++) out.push({ v: step * i, y: yAt(step * i) })
  return out
})

function xAt(i) {
  const n = props.points.length
  if (n <= 1) return PAD.left + plotW / 2
  return PAD.left + (i / (n - 1)) * plotW
}
function yAt(v) {
  return PAD.top + plotH - (Math.min(v || 0, yMax.value) / yMax.value) * plotH
}

function linePath(key) {
  return props.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(p[key]).toFixed(1)}`).join(' ')
}
function areaPath(key) {
  if (!props.points.length) return ''
  const baseY = (PAD.top + plotH).toFixed(1)
  return `${linePath(key)} L${xAt(props.points.length - 1).toFixed(1)},${baseY} L${xAt(0).toFixed(1)},${baseY} Z`
}

// Beyond a day the hour alone is ambiguous, so ticks carry the date too
const longRange = computed(() => props.hours > 24)
function tickLabel(ms) {
  if (!longRange.value) return fmtShortTime(ms)
  const d = new Date(ms)
  return `${d.getDate()}/${d.getMonth() + 1} ${fmtShortTime(ms)}`
}

const xTicks = computed(() => {
  const n = props.points.length
  if (n < 2) return []
  const want = Math.min(6, n)
  const out = []
  for (let i = 0; i < want; i++) {
    const idx = Math.round((i / (want - 1)) * (n - 1))
    out.push({ idx, x: xAt(idx), label: tickLabel(props.points[idx].minute) })
  }
  return out
})

const hovered = computed(() => (hoverIdx.value >= 0 ? props.points[hoverIdx.value] : null))

// Position the tooltip by width percentage so it never spills outside the frame
const tipStyle = computed(() => {
  if (hoverIdx.value < 0) return {}
  const pct = (xAt(hoverIdx.value) / W) * 100
  return { left: `${pct}%`, transform: pct > 62 ? 'translate(calc(-100% - 14px), 0)' : 'translate(14px, 0)' }
})

function idxFromClientX(clientX) {
  const rect = svgEl.value.getBoundingClientRect()
  const rel = ((clientX - rect.left) / rect.width) * W
  const n = props.points.length
  const ratio = (rel - PAD.left) / plotW
  return Math.max(0, Math.min(n - 1, Math.round(ratio * (n - 1))))
}
function onMove(e) {
  if (!props.points.length) return
  hoverIdx.value = idxFromClientX(e.clientX)
}
// Keyboard readers walk the same crosshair with the arrow keys
function onKey(e) {
  const n = props.points.length
  if (!n) return
  if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
    e.preventDefault()
    const cur = hoverIdx.value < 0 ? n - 1 : hoverIdx.value
    hoverIdx.value = Math.max(0, Math.min(n - 1, cur + (e.key === 'ArrowLeft' ? -1 : 1)))
  } else if (e.key === 'Home') { e.preventDefault(); hoverIdx.value = 0 }
  else if (e.key === 'End') { e.preventDefault(); hoverIdx.value = n - 1 }
  else if (e.key === 'Escape') { hoverIdx.value = -1 }
}

const lastPoint = computed(() => props.points[props.points.length - 1] || null)
const peak = computed(() => {
  let best = null
  for (const p of props.points) if (!best || p.total > best.total) best = p
  return best && best.total > 0 ? best : null
})

// The table twin: the same buckets, newest first, so nothing is hover-only
const tableRows = computed(() => props.points.slice().reverse().slice(0, 48))

// How wide one bucket is in minutes, to name the unit honestly
const bucketMinutes = computed(() => {
  const p = props.points
  if (p.length < 2) return 1
  return Math.round((p[1].minute - p[0].minute) / 60000) || 1
})
</script>

<template>
  <div class="chart-wrap" :class="{ 'is-refreshing': refreshing }">
    <div class="chart-top">
      <div class="legend" role="group" :aria-label="t('chart.legend')">
        <button
          v-for="s in SERIES" :key="s.key" type="button"
          class="legend-item" :class="{ off: hidden.has(s.key) }"
          :aria-pressed="hidden.has(s.key) ? 'false' : 'true'"
          @click="toggle(s.key)"
        >
          <span class="swatch" :class="{ line: !s.area }" :style="{ background: s.color }"></span>{{ t(s.label) }}
        </button>
      </div>
      <button type="button" class="btn-link" :aria-pressed="showTable ? 'true' : 'false'" @click="showTable = !showTable">
        <Icon name="events" />{{ showTable ? t('chart.hideTable') : t('chart.showTable') }}
      </button>
    </div>

    <!-- states: skeleton keeps the plot's height so the page does not jump -->
    <div v-if="loading" class="plot-skeleton" aria-busy="true">
      <div class="skel skel-plot"></div>
    </div>

    <div v-else-if="error" class="empty">
      <Icon name="alert" />
      <b>{{ t('chart.error') }}</b>
      <span class="empty-hint">{{ error }}</span>
      <button type="button" class="btn btn-sm" @click="emit('retry')"><Icon name="refresh" />{{ t('common.retry') }}</button>
    </div>

    <div v-else-if="!points.length || !peak" class="empty">
      <Icon name="activity" />
      <b>{{ t('chart.empty') }}</b>
      <span class="empty-hint">{{ t('chart.emptyHint') }}</span>
    </div>

    <div v-else class="plot">
      <svg
        ref="svgEl" :viewBox="`0 0 ${W} ${H}`" tabindex="0" role="img"
        :aria-label="t('chart.aria', { total: fmtNumber(peak.total), time: fmtShortTime(peak.minute) })"
        @mousemove="onMove" @mouseleave="hoverIdx = -1" @keydown="onKey" @blur="hoverIdx = -1"
      >
        <!-- recessive grid -->
        <g>
          <line
            v-for="tick in yTicks" :key="'g' + tick.v"
            :x1="PAD.left" :x2="W - PAD.right" :y1="tick.y" :y2="tick.y"
            stroke="var(--line)" stroke-width="1"
          />
        </g>

        <!-- area + lines. The fill is one flat wash of the line's own ink, only
             under the total, so the other two series stay readable across it. -->
        <path v-if="!hidden.has('total')" :d="areaPath('total')" fill="var(--series-1-wash)" />
        <path
          v-for="s in visible" :key="s.key"
          :d="linePath(s.key)" fill="none" :stroke="s.color"
          stroke-width="2" stroke-linejoin="round" stroke-linecap="round"
          vector-effect="non-scaling-stroke"
        />

        <!-- end markers: the latest value, readable without the tooltip -->
        <g v-if="lastPoint && hoverIdx < 0">
          <circle
            v-for="s in visible" :key="'e' + s.key"
            :cx="xAt(points.length - 1)" :cy="yAt(lastPoint[s.key])" r="3.5"
            :fill="s.color" stroke="var(--surface)" stroke-width="2"
          />
        </g>

        <!-- crosshair -->
        <g v-if="hoverIdx >= 0">
          <line
            :x1="xAt(hoverIdx)" :x2="xAt(hoverIdx)" :y1="PAD.top" :y2="PAD.top + plotH"
            stroke="var(--ink-3)" stroke-width="1" vector-effect="non-scaling-stroke"
          />
          <circle
            v-for="s in visible" :key="'h' + s.key"
            :cx="xAt(hoverIdx)" :cy="yAt(points[hoverIdx][s.key])" r="4"
            :fill="s.color" stroke="var(--surface)" stroke-width="2"
          />
        </g>
      </svg>

      <div class="y-axis" aria-hidden="true">
        <span v-for="tick in yTicks" :key="'y' + tick.v" :style="{ top: `${(tick.y / H) * 100}%` }">
          {{ fmtNumber(Math.round(tick.v)) }}
        </span>
      </div>
      <div class="x-axis" aria-hidden="true">
        <span v-for="tick in xTicks" :key="'x' + tick.idx" :style="{ left: `${(tick.x / W) * 100}%` }">
          {{ tick.label }}
        </span>
      </div>

      <div v-if="hovered" class="tooltip" :style="tipStyle" role="status">
        <div class="tip-time">{{ longRange ? fmtTime(hovered.minute) : fmtShortTime(hovered.minute) }} <span class="dim">· {{ t('chart.perBucket', { n: bucketMinutes }) }}</span></div>
        <div v-for="s in visible" :key="'t' + s.key" class="tip-row">
          <span class="key" :style="{ background: s.color }"></span>
          <span class="tip-val">{{ fmtNumber(hovered[s.key]) }}</span>
          <span class="tip-label">{{ t(s.label) }}</span>
        </div>
      </div>
    </div>

    <div v-if="!loading && !error && peak" class="chart-foot">
      <span>{{ t('chart.latestMinute', { total: fmtNumber(lastPoint.total), blocked: fmtNumber(lastPoint.blocked), challenged: fmtNumber(lastPoint.challenged) }) }}</span>
      <span class="dotsep"></span>
      <span>{{ t('chart.peak', { total: fmtNumber(peak.total), time: longRange ? fmtTime(peak.minute) : fmtShortTime(peak.minute) }) }}</span>
    </div>

    <div v-if="showTable && points.length" class="table-wrap chart-table">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('chart.colTime') }}</th>
            <th class="num">{{ t('chart.total') }}</th>
            <th class="num">{{ t('chart.blocked') }}</th>
            <th class="num">{{ t('chart.challenged') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in tableRows" :key="p.minute">
            <td class="sub">{{ fmtTime(p.minute) }}</td>
            <td class="num">{{ fmtNumber(p.total) }}</td>
            <td class="num">{{ fmtNumber(p.blocked) }}</td>
            <td class="num">{{ fmtNumber(p.challenged) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.chart-wrap { position: relative; }
.chart-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }

.legend { display: flex; gap: 4px; flex-wrap: wrap; }
.legend-item {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 4px 8px; border-radius: var(--radius); font-size: 12px; color: var(--ink-2);
  background: transparent; border: 1px solid transparent;
  transition: background var(--dur-1), color var(--dur-1), opacity var(--dur-1);
}
.legend-item:hover { background: var(--surface-2); color: var(--ink); }
.legend-item.off { opacity: .45; text-decoration: line-through; }
.swatch { width: 10px; height: 10px; display: inline-block; }
.swatch.line { height: 2px; }

.plot-skeleton { padding-bottom: 20px; }
.skel-plot { width: 100%; aspect-ratio: 900 / 280; border-radius: 8px; }

.plot { position: relative; padding-bottom: 20px; }
svg { width: 100%; height: auto; display: block; overflow: visible; border-radius: 6px; }
svg:focus-visible { box-shadow: var(--focus); outline: none; }

.y-axis { position: absolute; inset: 0; pointer-events: none; }
.y-axis span {
  position: absolute; left: 0; transform: translateY(-50%);
  font-family: var(--mono); font-size: 10.5px; color: var(--ink-3); font-variant-numeric: tabular-nums;
}
.x-axis { position: absolute; left: 0; right: 0; bottom: 0; height: 18px; pointer-events: none; }
.x-axis span {
  position: absolute; transform: translateX(-50%); white-space: nowrap;
  font-family: var(--mono); font-size: 10.5px; color: var(--ink-3); font-variant-numeric: tabular-nums;
}
.x-axis span:first-child { transform: translateX(0); }
.x-axis span:last-child { transform: translateX(-100%); }

.tooltip {
  position: absolute; top: 6px;
  background: var(--surface); border: 1px solid var(--line-2);
  border-radius: var(--radius); padding: 9px 12px; min-width: 190px;
  box-shadow: var(--shadow-lg); pointer-events: none; font-size: 12px; z-index: 2;
}
.tip-time { font-family: var(--mono); color: var(--ink-3); font-size: 10.5px; margin-bottom: 7px; white-space: nowrap; }
.tip-row { display: flex; align-items: center; gap: 8px; margin-top: 4px; }
.tip-row .key { width: 12px; height: 2px; flex: 0 0 12px; }
.tip-val { font-family: var(--mono); font-variant-numeric: tabular-nums; color: var(--ink); font-weight: 500; min-width: 52px; }
.tip-label { color: var(--ink-2); }

.chart-foot { margin-top: 8px; font-size: 12px; color: var(--ink-3); display: flex; gap: 8px; flex-wrap: wrap; }
.chart-foot .dotsep::before { content: '·'; }
.chart-table { margin-top: 14px; max-height: 320px; overflow: auto; }

@media (max-width: 760px) {
  .x-axis span:nth-child(even) { display: none; }
  .tooltip { min-width: 150px; }
}
</style>
