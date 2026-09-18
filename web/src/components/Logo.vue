<script setup>
// The MosWAF mark: a shield with a signal line passing through it - traffic
// crossing a defence layer. Drawn in ink on the page, with the one warm accent
// reserved for the point on the line, so the mark still reads as a mark without
// bringing a second palette with it.
defineProps({ size: { type: Number, default: 28 } })
</script>

<template>
  <svg class="logo" :width="size" :height="size" viewBox="0 0 32 32" fill="none" aria-hidden="true">
    <path
      d="M16 3l10.5 3.8v7.9c0 6.3-4.4 11.1-10.5 12.8C9.9 25.8 5.5 21 5.5 14.7V6.8L16 3z"
      fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"
    />
    <path
      d="M9.4 17.6c2-2.2 3.7-1.1 4.9.4 1.3 1.7 2.6 1.8 3.9-.2 1.2-1.7 2.8-2 4.6-.5"
      fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"
      opacity=".55"
    />
    <circle cx="16" cy="11.4" r="1.7" fill="var(--sand)" />
  </svg>
</template>

<style scoped>
.logo { color: var(--ink); display: block; }
</style>
