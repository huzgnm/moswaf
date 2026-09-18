<script setup>
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { LOCALES, i18n, setLocale, t } from '../i18n'

const open = ref(false)
const root = ref(null)
const trigger = ref(null)
const options = ref([])          // the rendered <li> elements, for focus()
const cursor = ref(0)            // which option the keyboard is on

const current = computed(
  () => LOCALES.find((l) => l.code === i18n.locale) || LOCALES[0]
)

async function openMenu() {
  open.value = true
  cursor.value = Math.max(0, LOCALES.findIndex((l) => l.code === i18n.locale))
  await nextTick()
  options.value[cursor.value]?.focus()
}

// Focus goes back to the trigger on close, so keyboard users are not dropped at
// the top of the page - except when the menu closed because they clicked or
// tabbed somewhere else, which is what `refocus` is for.
function closeMenu(refocus = true) {
  if (!open.value) return
  open.value = false
  if (refocus) trigger.value?.focus()
}

function choose(code) {
  setLocale(code)
  closeMenu()
}

async function move(delta) {
  cursor.value = (cursor.value + delta + LOCALES.length) % LOCALES.length
  await nextTick()
  options.value[cursor.value]?.focus()
}

function onMenuKey(e) {
  switch (e.key) {
    case 'ArrowDown': e.preventDefault(); move(1); break
    case 'ArrowUp':   e.preventDefault(); move(-1); break
    case 'Home':      e.preventDefault(); cursor.value = -1; move(1); break
    case 'End':       e.preventDefault(); cursor.value = 0; move(-1); break
    case 'Escape':    e.preventDefault(); closeMenu(); break
    case 'Tab':       closeMenu(false); break
  }
}

function onTriggerKey(e) {
  if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
    e.preventDefault()
    openMenu()
  }
}

// pointerdown rather than click: closing on click would fire after the button's
// own handler had already toggled the menu back open.
function onOutside(e) {
  if (root.value && !root.value.contains(e.target)) closeMenu(false)
}

onMounted(() => document.addEventListener('pointerdown', onOutside))
onUnmounted(() => document.removeEventListener('pointerdown', onOutside))
</script>

<template>
  <div ref="root" class="lang" @keydown="open && onMenuKey($event)">
    <button
      ref="trigger"
      type="button"
      class="lang-trigger"
      :class="{ open }"
      :title="t('common.language')"
      :aria-label="t('common.language')"
      aria-haspopup="listbox"
      :aria-expanded="open ? 'true' : 'false'"
      @click="open ? closeMenu() : openMenu()"
      @keydown="onTriggerKey"
    >
      <svg class="globe" viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="8" cy="8" r="6.4" fill="none" stroke="currentColor" stroke-width="1.2" />
        <ellipse cx="8" cy="8" rx="2.7" ry="6.4" fill="none" stroke="currentColor" stroke-width="1.2" />
        <path d="M1.9 5.8h12.2M1.9 10.2h12.2" stroke="currentColor" stroke-width="1.2" />
      </svg>
      <span class="lang-name">{{ current.label }}</span>
      <svg class="chevron" viewBox="0 0 10 6" aria-hidden="true">
        <path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.4"
              stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    </button>

    <ul v-if="open" class="lang-menu" role="listbox" :aria-label="t('common.language')">
      <li
        v-for="(l, i) in LOCALES"
        :key="l.code"
        :ref="(el) => (options[i] = el)"
        class="lang-option"
        :class="{ selected: l.code === i18n.locale }"
        role="option"
        tabindex="-1"
        :aria-selected="l.code === i18n.locale ? 'true' : 'false'"
        @click="choose(l.code)"
        @keydown.enter.prevent="choose(l.code)"
        @keydown.space.prevent="choose(l.code)"
      >
        <span class="check" aria-hidden="true">
          <svg v-if="l.code === i18n.locale" viewBox="0 0 12 12">
            <path d="M2 6.3l2.8 2.8L10 3.4" fill="none" stroke="currentColor"
                  stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="native">{{ l.label }}</span>
        <span class="english">{{ l.english }}</span>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.lang { position: relative; display: inline-block; }

.lang-trigger {
  display: inline-flex; align-items: center; gap: 7px;
  background: var(--surface); color: var(--ink-2);
  border: 1px solid var(--line-2); border-radius: var(--radius);
  padding: 5px 9px; font: inherit; font-size: 12.5px; line-height: 1.2;
  cursor: pointer; transition: border-color .12s, color .12s;
}
.lang-trigger:hover,
.lang-trigger.open { color: var(--ink); border-color: var(--line-3); background: var(--surface-2); }
.lang-trigger:focus-visible { outline: none; box-shadow: var(--focus); }

.globe { width: 14px; height: 14px; flex: 0 0 14px; opacity: .8; }
.lang-name { white-space: nowrap; }
.chevron { width: 9px; height: 9px; opacity: .7; transition: transform .15s; }
.lang-trigger.open .chevron { transform: rotate(180deg); }

.lang-menu {
  position: absolute; z-index: 40; top: calc(100% + 6px); right: 0;
  min-width: 210px; margin: 0; padding: 5px;
  list-style: none;
  background: var(--surface); border: 1px solid var(--line-2);
  border-radius: var(--radius-card); box-shadow: var(--shadow-lg);
}

.lang-option {
  display: grid; grid-template-columns: 16px 1fr auto; align-items: center; gap: 9px;
  padding: 7px 9px; border-radius: var(--radius);
  font-size: 13px; color: var(--ink-2);
  cursor: pointer; white-space: nowrap;
}
.lang-option:hover,
.lang-option:focus { background: var(--surface-2); color: var(--ink); outline: none; }
.lang-option.selected { color: var(--ink); }

.check { width: 16px; height: 16px; color: var(--ink); }
.check svg { width: 100%; height: 100%; display: block; }
.native { font-weight: 500; }
.english { font-size: 11.5px; color: var(--ink-3); }
</style>
