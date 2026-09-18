<script setup>
import { t } from '../i18n'

// okLabel has no default here on purpose: a default in defineProps is evaluated
// once, so it would freeze whichever language was active at first render.
defineProps({ title: String, busy: Boolean, okLabel: String })
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
        <button class="btn" @click="emit('close')">{{ t('common.cancel') }}</button>
        <button class="btn btn-primary" :disabled="busy" @click="emit('submit')">
          {{ busy ? t('common.saving') : (okLabel || t('common.save')) }}
        </button>
      </div>
    </div>
  </div>
</template>
