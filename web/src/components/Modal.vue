<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { t } from '../i18n'
import Icon from './Icon.vue'

// okLabel has no default here on purpose: a default in defineProps is evaluated
// once, so it would freeze whichever language was active at first render.
// hideSubmit is for panels that act on each row as it is pressed rather than on
// one Save at the end. Showing a Save button there would suggest the changes are
// not real until it is pressed, when in fact they already are.
// danger paints the affirmative button red for actions that cannot be undone.
// disabled is separate from busy on purpose: busy means "working, wait", and
// says so on the button, while disabled means "this cannot be submitted yet" -
// a button that is lit but silently does nothing is worse than either.
const props = defineProps({
  title: String,
  busy: Boolean,
  disabled: Boolean,
  okLabel: String,
  hideSubmit: Boolean,
  danger: Boolean,
  narrow: Boolean,
})
const emit = defineEmits(['close', 'submit'])

const panel = ref(null)
let opener = null

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function focusables() {
  return Array.from(panel.value?.querySelectorAll(FOCUSABLE) || [])
}

// A real dialog: focus moves in when it opens, stays in while it is open, and
// goes back to whatever opened it when it closes. Escape closes it.
function onKey(e) {
  if (e.key === 'Escape') {
    e.preventDefault()
    emit('close')
    return
  }
  if (e.key !== 'Tab') return
  const list = focusables()
  if (!list.length) return
  const first = list[0], last = list[list.length - 1]
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
}

onMounted(() => {
  opener = document.activeElement
  document.addEventListener('keydown', onKey)
  // The first field, if there is one; otherwise the panel itself so Escape works
  const first = focusables().find((el) => !el.closest('.modal-head') && !el.closest('.modal-foot'))
  ;(first || panel.value)?.focus()
})
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKey)
  if (opener && typeof opener.focus === 'function') opener.focus()
})
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div ref="panel" class="modal" :class="{ narrow }" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabindex="-1">
      <div class="modal-head">
        <div id="modal-title" class="card-title">{{ title }}</div>
        <button type="button" class="icon-btn" :aria-label="t('common.close')" @click="emit('close')">
          <Icon name="x" />
        </button>
      </div>
      <div class="modal-body">
        <slot />
      </div>
      <div class="modal-foot">
        <button type="button" class="btn" @click="emit('close')">
          {{ hideSubmit ? t('common.close') : t('common.cancel') }}
        </button>
        <button
          v-if="!hideSubmit" type="button"
          class="btn" :class="danger ? 'btn-danger solid' : 'btn-primary'"
          :disabled="busy || disabled" @click="emit('submit')"
        >
          {{ busy ? t('common.saving') : (okLabel || t('common.save')) }}
        </button>
      </div>
    </div>
  </div>
</template>
