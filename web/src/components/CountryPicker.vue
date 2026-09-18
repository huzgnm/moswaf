<script setup>
import { ref, computed } from 'vue'
import { t, intlTag } from '../i18n'
import { fmtNumber } from '../api'
import Icon from './Icon.vue'

// Picks countries out of the list the data plane can actually decide against.
// The list comes from /api/geo/countries, never from a table compiled in here:
// a code the dataset does not contain would make an allow rule that matches
// nobody. Each row shows how many address ranges the country carries, so the
// weight of a rule is visible before it is chosen.
const props = defineProps({
  modelValue: { type: Array, default: () => [] },   // ISO-3166 alpha-2, upper case
  countries: { type: Array, default: () => [] },    // [{ code, ranges }]
  disabled: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue'])

const query = ref('')

const names = computed(() => {
  try { return new Intl.DisplayNames([intlTag()], { type: 'region' }) } catch { return null }
})
function nameOf(code) {
  try { return names.value?.of(code) || code } catch { return code }
}

const selected = computed(() => new Set(props.modelValue))

const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  const list = props.countries.map((c) => ({ ...c, name: nameOf(c.code) }))
  const hit = q ? list.filter((c) => c.code.toLowerCase().includes(q) || c.name.toLowerCase().includes(q)) : list
  // Selected first, then by name, so a long list still shows the rule at the top
  return hit.sort((a, b) => {
    const sa = selected.value.has(a.code), sb = selected.value.has(b.code)
    if (sa !== sb) return sa ? -1 : 1
    return a.name.localeCompare(b.name, intlTag())
  })
})

function toggle(code) {
  if (props.disabled) return
  const next = new Set(selected.value)
  if (next.has(code)) next.delete(code)
  else next.add(code)
  emit('update:modelValue', [...next].sort())
}
</script>

<template>
  <div class="picker" :class="{ disabled }">
    <div v-if="modelValue.length" class="chips">
      <button v-for="code in modelValue" :key="code" type="button" class="chip" :disabled="disabled" @click="toggle(code)" :title="t('geo.remove', { name: nameOf(code) })">
        <span class="mono">{{ code }}</span> {{ nameOf(code) }}<Icon name="x" />
      </button>
    </div>
    <div v-else class="hint" style="margin:0 0 8px">{{ t('geo.noneSelected') }}</div>

    <div class="search">
      <Icon name="search" />
      <input v-model="query" class="input" :placeholder="t('geo.search')" :disabled="disabled" />
    </div>

    <div class="list" role="listbox" aria-multiselectable="true">
      <div v-if="!shown.length" class="empty compact">{{ t('geo.noMatch') }}</div>
      <label v-for="c in shown" :key="c.code" class="opt" :class="{ on: selected.has(c.code) }">
        <input type="checkbox" :checked="selected.has(c.code)" :disabled="disabled" @change="toggle(c.code)" />
        <span class="code mono">{{ c.code }}</span>
        <span class="name">{{ c.name }}</span>
        <span class="ranges">{{ t('geo.ranges', { n: fmtNumber(c.ranges) }) }}</span>
      </label>
    </div>
  </div>
</template>

<style scoped>
.picker.disabled { opacity: .6; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.chip {
  display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px 3px 9px; border-radius: var(--radius);
  font-size: 12px; background: var(--surface-2); border: 1px solid var(--line-2); color: var(--ink);
}
.chip .ico { width: 12px; height: 12px; color: var(--ink-3); }
.chip:hover .ico { color: var(--ink); }
.search { position: relative; margin-bottom: 8px; }
.search .ico { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 15px; height: 15px; color: var(--ink-3); pointer-events: none; }
.search .input { padding-left: 32px; }
.list { max-height: 240px; overflow: auto; border: 1px solid var(--line-2); border-radius: var(--radius); background: var(--surface); padding: 4px; }
.opt { display: grid; grid-template-columns: 16px 36px 1fr auto; align-items: center; gap: 10px; padding: 6px 8px; border-radius: var(--radius); font-size: 13px; cursor: pointer; }
.opt:hover { background: var(--surface-2); }
.opt.on { color: var(--ink); }
.opt input { margin: 0; accent-color: var(--ink); }
.code { color: var(--ink-3); font-size: 11px; }
.name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ranges { font-family: var(--mono); font-size: 10.5px; color: var(--ink-3); font-variant-numeric: tabular-nums; white-space: nowrap; }
</style>
