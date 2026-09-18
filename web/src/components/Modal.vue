<script setup>
import { t } from '../i18n'

// okLabel has no default here on purpose: a default in defineProps is evaluated
// once, so it would freeze whichever language was active at first render.
// hideSubmit is for panels that act on each row as it is pressed rather than on
// one Save at the end. Showing a Save button there would suggest the changes are
// not real until it is pressed, when in fact they already are.
defineProps({ title: String, busy: Boolean, okLabel: String, hideSubmit: Boolean })
const emit = defineEmits(['close', 'submit'])
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div class="modal">
      <div class="modal-head">
        <div class="card-title">{{ title }}</div>
        <button class="btn btn-sm" @click="emit('close')">{{ t('common.close') }}</button>
      </div>
      <div class="modal-body">
        <slot />
      </div>
      <div class="modal-foot">
        <button class="btn" @click="emit('close')">
          {{ hideSubmit ? t('common.close') : t('common.cancel') }}
        </button>
        <button v-if="!hideSubmit" class="btn btn-primary" :disabled="busy" @click="emit('submit')">
          {{ busy ? t('common.saving') : (okLabel || t('common.save')) }}
        </button>
      </div>
    </div>
  </div>
</template>
