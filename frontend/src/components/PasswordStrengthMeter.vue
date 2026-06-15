<script setup lang="ts">
import { computed } from 'vue'
import { scorePassword } from '@/composables/usePasswordStrength'

const props = defineProps<{ password: string; userInputs?: string[] }>()
const s = computed(() => scorePassword(props.password, props.userInputs ?? []))

// red → amber → yellow → green → green, indexed by zxcvbn score 0..4.
const colors = ['#ef4444', '#f59e0b', '#eab308', '#22c55e', '#16a34a']
</script>

<template>
  <div v-if="password" class="strength">
    <div class="bar">
      <div class="fill" :style="{ width: ((s.score + 1) / 5) * 100 + '%', background: colors[s.score] }" />
    </div>
    <small :style="{ color: s.ok ? 'var(--p-text-muted-color)' : '#d97706' }">
      {{ s.label }}<template v-if="s.warning"> — {{ s.warning }}</template>
    </small>
  </div>
</template>

<style scoped>
.strength {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin-top: -0.5rem;
}
.bar {
  height: 4px;
  border-radius: 2px;
  background: var(--p-surface-border);
  overflow: hidden;
}
.fill {
  height: 100%;
  transition: width 0.2s ease, background 0.2s ease;
}
</style>
