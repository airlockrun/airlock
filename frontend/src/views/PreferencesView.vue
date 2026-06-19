<script setup lang="ts">
import { useTheme } from '@/composables/useTheme'

const { isDark } = useTheme()
</script>

<template>
  <div style="max-width: 40rem">
    <h1 style="margin: 0 0 1.5rem; font-size: 1.5rem">Preferences</h1>
    <Card>
      <template #title>Appearance</template>
      <template #content>
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem">
          <div style="display: flex; flex-direction: column">
            <span style="font-weight: 500">Dark mode</span>
            <span style="font-size: 0.85rem; color: var(--p-text-muted-color)">
              Switch between the light and dark theme.
            </span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem">
            <i :class="isDark ? 'pi pi-moon' : 'pi pi-sun'" style="font-size: 0.875rem" />
            <ToggleSwitch v-model="isDark" />
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
