<script setup>
// One choice out of a few: time ranges, list kinds. Real buttons with
// aria-pressed, so the keyboard and a screen reader both see which is selected.
defineProps({
  options: { type: Array, required: true },   // [{ value, label }]
  modelValue: { required: true },
  ariaLabel: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue'])
</script>

<template>
  <div class="seg" role="group" :aria-label="ariaLabel">
    <button
      v-for="o in options" :key="String(o.value)"
      type="button" class="seg-item"
      :aria-pressed="o.value === modelValue ? 'true' : 'false'"
      @click="emit('update:modelValue', o.value)"
    >{{ o.label }}</button>
  </div>
</template>
