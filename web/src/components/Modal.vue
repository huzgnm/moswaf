<script setup>
defineProps({ title: String, busy: Boolean, okLabel: { type: String, default: 'Save' } })
const emit = defineEmits(['close', 'submit'])
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div class="modal">
      <div class="modal-head">
        <div class="card-title">{{ title }}</div>
        <button class="btn btn-sm" @click="emit('close')">Close</button>
      </div>
      <div class="modal-body">
        <slot />
      </div>
      <div class="modal-foot">
        <button class="btn" @click="emit('close')">Cancel</button>
        <button class="btn btn-primary" :disabled="busy" @click="emit('submit')">
          {{ busy ? 'Saving...' : okLabel }}
        </button>
      </div>
    </div>
  </div>
</template>
