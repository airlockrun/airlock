<script setup lang="ts">
import { ref, computed } from 'vue'
import { promptAgentText } from '@/utils/messageGroup'
import { renderMarkdown } from '@/composables/useMarkdown'

// A tool run rendered as a compact, expandable badge instead of a chat
// bubble. Collapsed: a header (caret · label · live status), then the
// input flattened to a single line, then up to 5 formatted output lines.
// Click anywhere to expand to the full input / output / error.
const props = defineProps<{
  label: string
  toolName?: string
  input?: string
  output?: string
  error?: string
  status?: string // live only: running | confirmation | done | error
  // Force the full view open (and keep it open) regardless of the user's
  // toggle — used while this tool call is awaiting a confirmation so the
  // user sees exactly what they're approving before deciding.
  forceExpanded?: boolean
}>()

const MAX_OUTPUT_LINES = 5

const expanded = ref(false)
const isOpen = computed(() => expanded.value || !!props.forceExpanded)

// Input flattened to a minified-ish one-liner: collapse all whitespace,
// then drop it around structural punctuation so a multi-line script
// reads tight like minified code (e.g. "} else {" → "}else{",
// "f( a , b ) ;" → "f(a,b);"). Display-only heuristic — it doesn't
// respect string literals; the expanded view shows the real source.
const inputLine = computed(() =>
  (props.input || '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\s*([{}()[\];,:])\s*/g, '$1'),
)

// Human-facing output text: a promptAgent envelope is unwrapped to its
// text; everything else is the raw output. Error takes precedence.
const outputText = computed(() => {
  if (props.error) return props.error
  if (!props.output) return ''
  return promptAgentText(props.toolName || '', props.output) ?? props.output
})

// Output clamped to the first MAX_OUTPUT_LINES non-trailing-blank lines,
// keeping its own formatting (newlines preserved).
const clampedOutput = computed(() => {
  const txt = outputText.value.replace(/\s+$/, '')
  if (!txt) return { text: '', more: 0 }
  const lines = txt.split('\n')
  return {
    text: lines.slice(0, MAX_OUTPUT_LINES).join('\n'),
    more: Math.max(0, lines.length - MAX_OUTPUT_LINES),
  }
})

// Full markdown render of a promptAgent reply (expanded view only).
const mdOutput = computed(() => {
  if (!props.output) return null
  const t = promptAgentText(props.toolName || '', props.output)
  return t === null ? null : renderMarkdown(t)
})

const showStatus = computed(() => !!props.status && props.status !== 'done')
const statusSeverity = computed(() => (props.status === 'running' ? 'warn' : 'info'))

// Outcome dot. Persisted tool errors aren't structured — the runner
// prefixes the output with "Error: " — so sniff that too, not just the
// explicit error field / live status.
// Dot reflects the structured live tool status only — no text sniffing.
// When there's no status (a persisted row reloaded from the DB) the
// outcome genuinely isn't recorded per-tool yet, so stay neutral rather
// than guess. props.error is the live ToolErrorEvent error (also
// structured), so it's allowed here.
const dotColor = computed(() => {
  if (props.error || props.status === 'error') return 'var(--p-red-500)'
  if (props.status === 'confirmation') return 'var(--p-blue-500)'
  if (props.status === 'running') return 'var(--p-yellow-500)'
  if (props.status === 'done') return 'var(--p-green-500)'
  return 'var(--p-surface-400)' // unknown (persisted) — not recorded
})
</script>

<template>
  <div class="tool-badge" :class="{ expanded: isOpen }">
    <div class="tool-badge-head" @click="expanded = !isOpen">
      <i :class="isOpen ? 'pi pi-chevron-down' : 'pi pi-chevron-right'" class="tool-caret" />
      <span class="tool-dot" :style="{ backgroundColor: dotColor }" />
      <span class="tool-badge-name">{{ label }}</span>
      <Tag v-if="showStatus" :value="status" :severity="statusSeverity" class="tool-badge-tag" />
    </div>

    <!-- Collapsed summary: one-line input + ≤5 formatted output lines -->
    <div v-if="!isOpen && (inputLine || clampedOutput.text)" class="tool-badge-summary" @click="expanded = true">
      <div v-if="inputLine" class="tool-badge-inline">{{ inputLine }}</div>
      <pre
        v-if="clampedOutput.text"
        class="tool-pre tool-pre-clamped"
        :class="{ 'tool-pre-err': !!error }"
      >{{ clampedOutput.text }}</pre>
      <div v-if="clampedOutput.more" class="tool-badge-more">
        … {{ clampedOutput.more }} more line{{ clampedOutput.more === 1 ? '' : 's' }} — click to expand
      </div>
    </div>

    <!-- Expanded: full input / output / error -->
    <div v-else-if="isOpen" class="tool-badge-body">
      <pre v-if="input" class="tool-pre tool-pre-in">{{ input }}</pre>
      <div v-if="mdOutput" v-html="mdOutput" class="tool-badge-md" />
      <pre v-else-if="output" class="tool-pre">{{ output }}</pre>
      <pre v-if="error" class="tool-pre tool-pre-err">{{ error }}</pre>
    </div>
  </div>
</template>

<style scoped>
.tool-badge {
  border: 1px solid var(--p-surface-200);
  border-radius: 0.5rem;
  background: var(--p-surface-50);
  font-size: 0.78rem;
}

:root.dark .tool-badge {
  border-color: var(--p-surface-700);
  background: var(--p-surface-800);
}

.tool-badge-head {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.3rem 0.55rem;
  cursor: pointer;
  min-width: 0;
}

.tool-caret {
  font-size: 0.7rem;
  opacity: 0.45;
  width: 0.7rem;
  flex: none;
  text-align: center;
}

.tool-dot {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  flex: none;
}

.tool-badge-name {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.02em;
  opacity: 0.7;
  flex: none;
  font-weight: 600;
}

.tool-badge-tag {
  font-size: 0.62rem;
  flex: none;
}

.tool-badge-summary {
  padding: 0 0.55rem 0.45rem;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  cursor: pointer;
}

.tool-badge-inline {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  opacity: 0.55;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.tool-badge-more {
  font-size: 0.68rem;
  opacity: 0.45;
  font-style: italic;
}

.tool-badge-body {
  padding: 0 0.55rem 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.tool-pre {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 0.78rem;
  margin: 0;
}

.tool-pre-clamped {
  opacity: 0.75;
}

.tool-pre-in {
  opacity: 0.7;
}

.tool-pre-err {
  color: var(--p-red-500);
}
</style>

<!-- promptAgent output renders as markdown; keep a tiny self-contained
     rule set so it reads well without depending on a parent's scoped CSS. -->
<style>
.tool-badge-md p {
  margin: 0;
}
.tool-badge-md p + p {
  margin-top: 0.5em;
}
.tool-badge-md pre {
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0.25rem 0;
}
.tool-badge-md ul,
.tool-badge-md ol {
  margin: 0.25rem 0;
  padding-left: 1.25rem;
}
</style>
