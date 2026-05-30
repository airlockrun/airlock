<script setup lang="ts">
// SectionCard is the per-section wrapper used by AgentDetailView. There's
// no card/box around it — each section is just a heading followed by its
// content. The trailing #anchor stays as a permalink, and the agent page
// uses generous margin between sections so the heading itself is the cue
// that a new section has started.
defineProps<{
  id: string
  title: string
  badge?: string
  badgeSeverity?: 'info' | 'success' | 'warn' | 'danger' | 'secondary' | 'contrast'
}>()
</script>

<template>
  <section :id="id" class="section-card">
    <header class="section-header">
      <h2 class="section-title">{{ title }}</h2>
      <Tag v-if="badge" :value="badge" :severity="badgeSeverity ?? 'warn'" />
    </header>
    <slot />
  </section>
</template>

<style scoped>
.section-card {
  margin-bottom: 2.25rem;
  /* The sticky page nav sits at the top of the viewport (~2.5rem tall);
   * offset enough that a jump lands with the section title visible just
   * below the nav, not behind it. */
  scroll-margin-top: 3.25rem;
}
.section-header {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.section-title {
  margin: 0;
  font-size: 1.35rem;
  font-weight: 600;
  flex: 1;
  /* Theme primary so section titles stand out from any in-tab subheadings
   * (which use the default text color), establishing a clear hierarchy. */
  color: var(--p-primary-color);
}
</style>
