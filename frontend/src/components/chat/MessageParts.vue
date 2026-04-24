<script setup lang="ts">
import { computed } from 'vue'
import { marked } from 'marked'
import ImageAlbum from './ImageAlbum.vue'

export interface DisplayPart {
  type: 'text' | 'image' | 'file' | 'audio' | 'video'
  text?: string
  source?: string
  url?: string
  filename?: string
  mimeType?: string
  alt?: string
  duration?: number
}

type Block =
  | { kind: 'album'; images: DisplayPart[] }
  | { kind: 'text'; part: DisplayPart }
  | { kind: 'file'; part: DisplayPart }
  | { kind: 'audio'; part: DisplayPart }
  | { kind: 'video'; part: DisplayPart }

const props = defineProps<{ parts: DisplayPart[] }>()

const blocks = computed<Block[]>(() => {
  const out: Block[] = []
  let album: DisplayPart[] = []
  const flush = () => {
    if (album.length) {
      out.push({ kind: 'album', images: album })
      album = []
    }
  }
  for (const p of props.parts || []) {
    if (p.type === 'image') {
      album.push(p)
      continue
    }
    flush()
    if (p.type === 'text' || p.type === 'file' || p.type === 'audio' || p.type === 'video') {
      out.push({ kind: p.type, part: p } as Block)
    }
  }
  flush()
  return out
})

function renderMarkdown(src: string): string {
  return marked.parse(src || '') as string
}

function fileSizeLabel(p: DisplayPart): string {
  return p.filename || 'file'
}
</script>

<template>
  <div class="msg-parts">
    <template v-for="(block, i) in blocks" :key="i">
      <ImageAlbum v-if="block.kind === 'album'" :images="block.images" />

      <div v-else-if="block.kind === 'text'" class="part-text" v-html="renderMarkdown(block.part.text || '')" />

      <a
        v-else-if="block.kind === 'file'"
        class="part-file"
        :href="block.part.url || '#'"
        :download="block.part.filename || ''"
        target="_blank"
        rel="noopener noreferrer"
      >
        <i class="pi pi-file" style="font-size: 1.25rem" />
        <div style="display: flex; flex-direction: column; min-width: 0">
          <span style="font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ fileSizeLabel(block.part) }}</span>
          <span v-if="block.part.text" style="font-size: 0.8rem; opacity: 0.7">{{ block.part.text }}</span>
        </div>
      </a>

      <div v-else-if="block.kind === 'audio'" class="part-audio">
        <audio controls :src="block.part.url" style="width: 100%" />
        <div v-if="block.part.text" style="font-size: 0.85rem; margin-top: 0.25rem">{{ block.part.text }}</div>
      </div>

      <div v-else-if="block.kind === 'video'" class="part-video">
        <video controls :src="block.part.url" style="max-width: 100%; border-radius: 0.5rem" />
        <div v-if="block.part.text" style="font-size: 0.85rem; margin-top: 0.25rem">{{ block.part.text }}</div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.msg-parts {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.part-text :deep(p) {
  margin: 0.25rem 0;
}

.part-file {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.625rem 0.875rem;
  border-radius: 0.5rem;
  background-color: var(--p-content-hover-background);
  color: var(--p-text-color);
  text-decoration: none;
  max-width: 24rem;
}

.part-file:hover {
  background-color: var(--p-highlight-background);
}
</style>
