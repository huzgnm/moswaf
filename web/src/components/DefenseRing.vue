<script setup>
import { computed } from 'vue'

// The hero's technical drawing. Every mark on it is a value: the outer ring is
// the window's traffic, the dark arc the share MosWAF blocked, the lighter arc
// the share it challenged, and the figure in the middle is the block rate. No
// glow, no sweep - it is a gauge, not an animation.
const props = defineProps({
  blockedRate: { type: Number, default: 0 },      // percent 0-100
  challengedRate: { type: Number, default: 0 },   // percent 0-100
  state: { type: String, default: 'ok' },         // ok | attack | warn | idle
  centerLabel: { type: String, default: '' },
})

const R = 74
const C = 2 * Math.PI * R

const blocked = computed(() => Math.max(0, Math.min(100, props.blockedRate)))
const challenged = computed(() => Math.max(0, Math.min(100 - blocked.value, props.challengedRate)))

// Each arc is a dash on a full circle; the second starts where the first ends.
// A 2-unit gap in the surface colour keeps the two readable where they meet.
const GAP = 2
const blockedDash = computed(() => {
  const len = (blocked.value / 100) * C
  return `${Math.max(0, len - (len > 0 ? GAP : 0))} ${C}`
})
const challengedDash = computed(() => {
  const len = (challenged.value / 100) * C
  return `${Math.max(0, len - (len > 0 ? GAP : 0))} ${C}`
})
const challengedOffset = computed(() => -((blocked.value / 100) * C))

const percent = computed(() => {
  const v = blocked.value
  return v >= 10 ? Math.round(v) : Math.round(v * 10) / 10
})

// Tick marks every 30 degrees, the quarter marks longer: a measured instrument
// rather than a decorative circle.
const ticks = computed(() => {
  const out = []
  for (let i = 0; i < 12; i++) {
    const a = (i / 12) * Math.PI * 2 - Math.PI / 2
    const long = i % 3 === 0
    const r1 = 92, r2 = long ? 84 : 88
    out.push({
      x1: 100 + Math.cos(a) * r1, y1: 100 + Math.sin(a) * r1,
      x2: 100 + Math.cos(a) * r2, y2: 100 + Math.sin(a) * r2,
      long,
    })
  }
  return out
})
</script>

<template>
  <svg class="ring" :class="state" viewBox="0 0 200 200" role="img" :aria-label="`${percent}% ${centerLabel}`">
    <g class="ticks">
      <line v-for="(tk, i) in ticks" :key="i" :x1="tk.x1" :y1="tk.y1" :x2="tk.x2" :y2="tk.y2"
            :stroke-width="tk.long ? 1.2 : 1" />
    </g>
    <circle cx="100" cy="100" r="46" class="inner-ring" />

    <g transform="rotate(-90 100 100)">
      <circle cx="100" cy="100" :r="R" fill="none" class="track" stroke-width="9" />
      <circle cx="100" cy="100" :r="R" fill="none" class="arc-blocked" stroke-width="9"
              stroke-linecap="butt" :stroke-dasharray="blockedDash" />
      <circle cx="100" cy="100" :r="R" fill="none" class="arc-challenged" stroke-width="9"
              stroke-linecap="butt" :stroke-dasharray="challengedDash" :stroke-dashoffset="challengedOffset" />
    </g>

    <text x="100" y="99" text-anchor="middle" class="pct">{{ percent }}<tspan class="pct-sign">%</tspan></text>
    <text x="100" y="117" text-anchor="middle" class="pct-label">{{ centerLabel }}</text>
  </svg>
</template>

<style scoped>
.ring { width: 100%; height: 100%; display: block; }
.ticks line { stroke: var(--line-2); }
.inner-ring { fill: none; stroke: var(--line); stroke-width: 1; }
.track { stroke: var(--surface-3); }
.arc-blocked { stroke: var(--series-2); }
.arc-challenged { stroke: var(--series-3); }
.ring.idle .arc-blocked, .ring.idle .arc-challenged { stroke: var(--line-3); }
.pct { font-family: var(--mono); font-size: 30px; font-weight: 500; fill: var(--ink); letter-spacing: -.04em; }
.pct-sign { font-size: 15px; fill: var(--ink-3); }
.pct-label { font-family: var(--mono); font-size: 9px; fill: var(--ink-3); letter-spacing: .22em; text-transform: uppercase; }
</style>
