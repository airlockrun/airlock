<script setup lang="ts">
import { computed } from 'vue'
import Image from 'primevue/image'

interface DisplayPart {
  type: string
  text?: string
  url?: string
  alt?: string
}

const props = defineProps<{ images: DisplayPart[] }>()

const count = computed(() => props.images.length)

const layoutClass = computed(() => {
  if (count.value === 1) return 'album-1'
  if (count.value === 2) return 'album-2'
  if (count.value === 3) return 'album-3'
  if (count.value === 4) return 'album-4'
  return 'album-many'
})

// Only the first image carries the optional caption.
const caption = computed(() => props.images[0]?.text || '')
</script>

<template>
  <div class="album-wrap">
    <div class="album" :class="layoutClass">
      <div
        v-for="(img, i) in images"
        :key="i"
        class="album-cell"
        :class="{ 'cell-hero': count === 3 && i === 0 }"
      >
        <Image
          :src="img.url"
          :alt="img.alt || img.text || ''"
          :preview="true"
          image-class="album-img"
        />
      </div>
    </div>
    <div v-if="caption" class="album-caption">{{ caption }}</div>
  </div>
</template>

<style scoped>
.album-wrap {
  max-width: 32rem;
}

.album {
  display: grid;
  gap: 2px;
  border-radius: 0.75rem;
  overflow: hidden;
  background-color: var(--p-content-border-color);
}

.album-cell {
  position: relative;
  overflow: hidden;
  background-color: var(--p-content-background);
}

.album-cell :deep(.p-image) {
  width: 100%;
  height: 100%;
  display: block;
}

.album-cell :deep(.album-img) {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
  cursor: zoom-in;
}

/* 1 image — preserve aspect ratio. */
.album-1 .album-cell {
  max-height: 24rem;
}
.album-1 .album-cell :deep(.album-img) {
  height: auto;
  max-height: 24rem;
  object-fit: contain;
}

/* 2 images — side by side, square-ish. */
.album-2 {
  grid-template-columns: 1fr 1fr;
  aspect-ratio: 2 / 1;
}

/* 3 images — hero left full height, two stacked right. */
.album-3 {
  grid-template-columns: 2fr 1fr;
  grid-template-rows: 1fr 1fr;
  aspect-ratio: 3 / 2;
}
.album-3 .cell-hero {
  grid-row: 1 / 3;
}

/* 4 images — 2x2. */
.album-4 {
  grid-template-columns: 1fr 1fr;
  grid-template-rows: 1fr 1fr;
  aspect-ratio: 1 / 1;
}

/* 5+ — 3 col mosaic, rows auto; each cell square. */
.album-many {
  grid-template-columns: repeat(3, 1fr);
  grid-auto-rows: 8rem;
}

.album-caption {
  font-size: 0.85rem;
  margin-top: 0.375rem;
  opacity: 0.8;
}
</style>
