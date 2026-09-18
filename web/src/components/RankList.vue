<script setup>
import { fmtNumber } from '../api'

// A ranked list with a magnitude bar under each row. One series, one colour:
// the bars compare within the list, they do not identify anything.
const props = defineProps({
  items: { type: Array, default: () => [] },   // [{ key, label, count }]
  tone: { type: String, default: '' },         // '' | 'serious' | 'violet'
  mono: { type: Boolean, default: false },
  clickable: { type: Boolean, default: false },   // rows become buttons that emit `pick`
  labelOf: { type: Function, default: null },
})
const emit = defineEmits(['pick'])

function width(item) {
  const max = Math.max(...props.items.map((x) => x.count), 1)
  return `${Math.max(2, (item.count / max) * 100)}%`
}
function label(item) {
  return props.labelOf ? props.labelOf(item) : (item.label || item.key)
}
</script>

<template>
  <div class="rank">
    <div v-for="(item, i) in items" :key="item.key" class="rank-row">
      <span class="rank-label">
        <span class="idx">{{ i + 1 }}</span>
        <button v-if="clickable" type="button" class="txt as-link" :class="{ mono }" :title="label(item)" @click="emit('pick', item)">{{ label(item) }}</button>
        <span v-else class="txt" :class="{ mono }" :title="label(item)">{{ label(item) }}</span>
      </span>
      <span class="rank-val">{{ fmtNumber(item.count) }}</span>
      <span class="rank-track"><span class="rank-fill" :class="tone" :style="{ width: width(item) }"></span></span>
    </div>
  </div>
</template>

<style scoped>
.as-link { background: none; border: none; padding: 0; color: inherit; font: inherit; text-align: left; cursor: pointer; }
.as-link:hover { color: var(--ink); }
</style>
