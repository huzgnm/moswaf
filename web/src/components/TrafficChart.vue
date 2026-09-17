<script setup>
import { ref, computed } from 'vue'
import { fmtNumber, fmtShortTime } from '../api'

const props = defineProps({
  points: { type: Array, default: () => [] },   // [{ minute, total, blocked, challenged }]
  loading: { type: Boolean, default: false },
})

// Ba chuoi cung don vi (so request) nen dung chung mot truc y.
// Mau lay theo thu tu co dinh cua bang mau, khong xoay vong.
const SERIES = [
  { key: 'total',      label: 'Tong request', color: 'var(--series-1)', area: true },
  { key: 'blocked',    label: 'Bi chan',      color: 'var(--series-2)' },
  { key: 'challenged', label: 'Challenge',    color: 'var(--series-3)' },
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
  // lam tron len cho truc y co so dep
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

// Vi tri tooltip theo % chieu rong de khong le ra ngoai khung
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

// Nhan truc tiep cho diem cuoi: doc duoc ma khong phai do mau voi chu giai
const lastPoint = computed(() => props.points[props.points.length - 1] || null)
</script>

<template>
  <div class="chart-wrap">
    <div class="legend">
      <span v-for="s in SERIES" :key="s.key" class="legend-item">
        <span class="swatch" :style="{ background: s.color }"></span>{{ s.label }}
      </span>
    </div>

    <div v-if="loading" class="empty">Dang tai du lieu...</div>
    <div v-else-if="!points.length" class="empty">Chua co luu luong nao di qua MosWAF</div>

    <div v-else class="plot">
      <svg
        ref="svgEl" :viewBox="`0 0 ${W} ${H}`"
        @mousemove="onMove" @mouseleave="hoverIdx = -1"
      >
        <!-- luoi lui ve sau -->
        <g>
          <line
            v-for="t in yTicks" :key="'g' + t.v"
            :x1="PAD.left" :x2="W - PAD.right" :y1="t.y" :y2="t.y"
            stroke="var(--line)" stroke-width="1"
          />
        </g>

        <!-- vung + duong -->
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

      <!-- nhan truc y -->
      <div class="y-axis">
        <span v-for="t in yTicks" :key="'y' + t.v" :style="{ top: `${(t.y / H) * 100}%` }">
          {{ fmtNumber(Math.round(t.v)) }}
        </span>
      </div>

      <!-- nhan truc x -->
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
      Phut gan nhat:
      <b>{{ fmtNumber(lastPoint.total) }}</b> request ·
      <b>{{ fmtNumber(lastPoint.blocked) }}</b> bi chan ·
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
/* De svg tu giu ty le cua viewBox -> marker tron van tron, khong bi keo det */
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
