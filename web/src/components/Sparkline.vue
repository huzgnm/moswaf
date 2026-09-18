<script setup>
import { computed } from 'vue'

// A trend line inside a stat cell. No axes, no labels: the number above it is
// the value, the line only says which way it has been going. One flat wash of
// the line's own colour under it - never a gradient.
const props = defineProps({
  values: { type: Array, default: () => [] },
  color: { type: String, default: 'var(--series-1)' },
  wash: { type: String, default: 'var(--series-1-wash)' },
  width: { type: Number, default: 160 },
  height: { type: Number, default: 32 },
})

const path = computed(() => {
  const v = props.values
  if (v.length < 2) return ''
  const max = Math.max(...v, 1)
  const stepX = props.width / (v.length - 1)
  const top = 3, bottom = props.height - 3
  return v.map((n, i) => {
    const x = (i * stepX).toFixed(1)
    const y = (bottom - (n / max) * (bottom - top)).toFixed(1)
    return `${i === 0 ? 'M' : 'L'}${x},${y}`
  }).join(' ')
})

const area = computed(() => (path.value ? `${path.value} L${props.width},${props.height} L0,${props.height} Z` : ''))

const last = computed(() => {
  const v = props.values
  if (v.length < 2) return null
  const max = Math.max(...v, 1)
  const bottom = props.height - 3
  return { x: props.width, y: bottom - (v[v.length - 1] / max) * (bottom - 3) }
})
</script>

<template>
  <svg class="spark" :viewBox="`0 0 ${width} ${height}`" preserveAspectRatio="none" aria-hidden="true">
    <path v-if="area" :d="area" :fill="wash" />
    <path v-if="path" :d="path" fill="none" :stroke="color" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" />
    <circle v-if="last" :cx="last.x" :cy="last.y" r="2" :fill="color" vector-effect="non-scaling-stroke" />
  </svg>
</template>

<style scoped>
.spark { width: 100%; height: 100%; display: block; overflow: visible; }
</style>
