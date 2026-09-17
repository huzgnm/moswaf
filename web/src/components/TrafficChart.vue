<script setup>
import { ref, computed } from 'vue'
import { fmtNumber, fmtShortTime } from '../api'

const props = defineProps({
  points: { type: Array, default: () => [] },   // [{ minute, total, blocked, challenged }]
  loading: { type: Boolean, default: false },
})

// All three series share the same unit (requests), so they share one y axis.
// Colours are taken in fixed palette order, never cycled.
const SERIES = [
  { key: 'total',      label: 'Total requests', color: 'var(--series-1)', area: true },
  { key: 'blocked',    label: 'Blocked',      color: 'var(--series-2)' },
  { key: 'challenged', label: 'Challenged',    color: 'var(--series-3)' },
]

const W = 900, H = 260
const PAD = { top: 16, right: 18, bottom: 28, left: 52 }
const plotW = W - PAD.left - PAD.right
const plotH = H - PAD.top - PAD.bottom

const svgEl = ref(null)
const hoverIdx = ref(-1)

const yMax = computed(() => {
  let m = 0
  for (const p of props.points) m = Math.max(m, p.total || 0, p.blocked || 0, p.challenged || 0)
  if (m <= 0) return 10
  // round up so the y axis lands on tidy numbers
  const mag = Math.pow(10, Math.floor(Math.log10(m)))
  return Math.ceil(m / mag) * mag
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
  const top = props.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(p[key]).toFixed(1)}`).join(' ')
  const baseY = (PAD.top + plotH).toFixed(1)
  return `${top} L${xAt(props.points.length - 1).toFixed(1)},${baseY} L${xAt(0).toFixed(1)},${baseY} Z`
}

const yTicks = computed(() => {
  const out = []
  for (let i = 0; i <= 3; i++) {
    const v = (yMax.value / 3) * i
    out.push({ v, y: yAt(v) })
  }
  return out
})

const xTicks = computed(() => {
  const n = props.points.length
  if (n < 2) return []
  const want = Math.min(6, n)
  const out = []
  for (let i = 0; i < want; i++) {
    const idx = Math.round((i / (want - 1)) * (n - 1))
    out.push({ idx, x: xAt(idx), label: fmtShortTime(props.points[idx].minute) })
  }
  return out
})

const hovered = computed(() => (hoverIdx.value >= 0 ? props.points[hoverIdx.value] : null))

// Position the tooltip by width percentage so it never spills outside the frame
const tipStyle = computed(() => {
  if (hoverIdx.value < 0) return {}
  const pct = (xAt(hoverIdx.value) / W) * 100
  return {
    left: `${pct}%`,
    transform: pct > 62 ? 'translate(-108%, 0)' : 'translate(8%, 0)',
  }
})

function onMove(e) {
  const rect = svgEl.value.getBoundingClientRect()
  const rel = ((e.clientX - rect.left) / rect.width) * W
  const n = props.points.length
  if (n === 0) return
  const ratio = (rel - PAD.left) / plotW
  hoverIdx.value = Math.max(0, Math.min(n - 1, Math.round(ratio * (n - 1))))
}

// Direct label for the last point: readable without matching colours to the legend
const lastPoint = computed(() => props.points[props.points.length - 1] || null)
</script>

<template>
  <div class="chart-wrap">
    <div class="legend">
      <span v-for="s in SERIES" :key="s.key" class="legend-item">
        <span class="swatch" :style="{ background: s.color }"></span>{{ s.label }}
      </span>
    </div>

    <div v-if="loading" class="empty">Loading data...</div>
    <div v-else-if="!points.length" class="empty">No traffic has passed through MosWAF yet</div>

    <div v-else class="plot">
      <svg
        ref="svgEl" :viewBox="`0 0 ${W} ${H}`"
        @mousemove="onMove" @mouseleave="hoverIdx = -1"
      >
        <!-- recessive grid -->
        <g>
          <line
            v-for="t in yTicks" :key="'g' + t.v"
            :x1="PAD.left" :x2="W - PAD.right" :y1="t.y" :y2="t.y"
            stroke="var(--line)" stroke-width="1"
          />
        </g>

        <!-- area + lines -->
        <path :d="areaPath('total')" fill="var(--series-1)" opacity="0.13" />
        <path
          v-for="s in SERIES" :key="s.key"
          :d="linePath(s.key)" fill="none" :stroke="s.color"
          stroke-width="2" stroke-linejoin="round" stroke-linecap="round"
          vector-effect="non-scaling-stroke"
        />

        <!-- crosshair -->
        <g v-if="hoverIdx >= 0">
          <line
            :x1="xAt(hoverIdx)" :x2="xAt(hoverIdx)" :y1="PAD.top" :y2="PAD.top + plotH"
            stroke="var(--line-2)" stroke-width="1" vector-effect="non-scaling-stroke"
          />
          <circle
            v-for="s in SERIES" :key="'h' + s.key"
            :cx="xAt(hoverIdx)" :cy="yAt(points[hoverIdx][s.key])" r="4"
            :fill="s.color" stroke="var(--surface-1)" stroke-width="2"
          />
        </g>
      </svg>

      <!-- y axis labels -->
      <div class="y-axis">
        <span v-for="t in yTicks" :key="'y' + t.v" :style="{ top: `${(t.y / H) * 100}%` }">
          {{ fmtNumber(Math.round(t.v)) }}
        </span>
      </div>

      <!-- x axis labels -->
      <div class="x-axis">
        <span v-for="t in xTicks" :key="'x' + t.idx" :style="{ left: `${(t.x / W) * 100}%` }">
          {{ t.label }}
        </span>
      </div>

      <div v-if="hovered" class="tooltip" :style="tipStyle">
        <div class="tip-time">{{ fmtShortTime(hovered.minute) }}</div>
        <div v-for="s in SERIES" :key="'t' + s.key" class="tip-row">
          <span class="swatch" :style="{ background: s.color }"></span>
          <span class="tip-label">{{ s.label }}</span>
          <span class="tip-val">{{ fmtNumber(hovered[s.key]) }}</span>
        </div>
      </div>
    </div>

    <div v-if="lastPoint" class="last-line">
      Latest minute:
      <b>{{ fmtNumber(lastPoint.total) }}</b> requests ·
      <b>{{ fmtNumber(lastPoint.blocked) }}</b> blocked ·
      <b>{{ fmtNumber(lastPoint.challenged) }}</b> challenge
    </div>
  </div>
</template>

<style scoped>
.chart-wrap { position: relative; }

.legend { display: flex; gap: 18px; margin-bottom: 12px; font-size: 12px; color: var(--text-secondary); }
.legend-item { display: inline-flex; align-items: center; gap: 7px; }
.swatch { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }

.plot { position: relative; padding-bottom: 20px; }
/* Let the svg keep its viewBox ratio -> round markers stay round, never squashed */
svg { width: 100%; height: auto; display: block; overflow: visible; }

.y-axis { position: absolute; inset: 0; pointer-events: none; }
.y-axis span {
  position: absolute; left: 0; transform: translateY(-50%);
  font-size: 11px; color: var(--text-muted); font-variant-numeric: tabular-nums;
}

.x-axis { position: absolute; left: 0; right: 0; bottom: 0; height: 18px; pointer-events: none; }
.x-axis span {
  position: absolute; transform: translateX(-50%);
  font-size: 11px; color: var(--text-muted); font-variant-numeric: tabular-nums;
}

.tooltip {
  position: absolute; top: 8px;
  background: var(--surface-2); border: 1px solid var(--line-2);
  border-radius: 8px; padding: 9px 11px; min-width: 170px;
  box-shadow: var(--shadow); pointer-events: none; font-size: 12px;
}
.tip-time { color: var(--text-muted); font-size: 11px; margin-bottom: 6px; }
.tip-row { display: flex; align-items: center; gap: 7px; margin-top: 3px; }
.tip-label { color: var(--text-secondary); }
.tip-val { margin-left: auto; font-variant-numeric: tabular-nums; color: var(--text-primary); }

.last-line { margin-top: 10px; font-size: 12px; color: var(--text-muted); }
.last-line b { color: var(--text-secondary); font-weight: 600; }
</style>
