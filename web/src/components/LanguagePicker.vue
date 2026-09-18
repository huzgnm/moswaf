<script setup>
import { LOCALES, i18n, setLocale, t } from '../i18n'
</script>

<template>
  <!--
    A plain <select>. It is reachable by keyboard, it is announced correctly by a
    screen reader, and it renders its options in the system font - which matters
    here, because the option labels are in four different scripts.
  -->
  <label class="lang" :title="t('common.language')">
    <span class="lang-icon" aria-hidden="true">A文</span>
    <select
      class="lang-select"
      :value="i18n.locale"
      :aria-label="t('common.language')"
      @change="setLocale($event.target.value)"
    >
      <option v-for="l in LOCALES" :key="l.code" :value="l.code">{{ l.label }}</option>
    </select>
  </label>
</template>

<style scoped>
.lang { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
.lang-icon {
  font-size: 11px; letter-spacing: .04em;
  color: var(--text-muted); user-select: none;
}
.lang-select {
  background: var(--surface-2); color: var(--text-secondary);
  border: 1px solid var(--line); border-radius: 7px;
  padding: 4px 8px; font-size: 12px; font-family: inherit; cursor: pointer;
}
.lang-select:hover { color: var(--text-primary); border-color: var(--series-1); }
.lang-select:focus-visible { outline: 2px solid var(--series-1); outline-offset: 1px; }
</style>
