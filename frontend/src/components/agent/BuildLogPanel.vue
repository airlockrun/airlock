<script setup lang="ts">
import { ref, nextTick, onMounted, onUnmounted, watch } from 'vue'
import Button from 'primevue/button'
import { ws } from '@/api/ws'
import { useBuildsStore } from '@/stores/builds'

const props = defineProps<{
  agentId: string
  buildId?: string
  active: boolean
}>()

const emit = defineEmits<{
  cancel: []
}>()

const buildsStore = useBuildsStore()

const solLines = ref<string[]>([])
const dockerLines = ref<string[]>([])
const snapshotSeq = ref(0)
const snapshotLoaded = ref(false)
const wsBuffer = ref<Array<{ seq: number; stream: string; line: string; buildId: string }>>([])

const solScroll = ref<HTMLElement | null>(null)
const dockerScroll = ref<HTMLElement | null>(null)

let unsub: (() => void) | null = null

function appendLine(stream: string, line: string) {
  const target = stream === 'docker' ? dockerLines : solLines
  target.value.push(line)
  // Soft cap to keep the panel responsive on very long builds.
  if (target.value.length > 2000) target.value = target.value.slice(-2000)
  nextTick(() => {
    const el = stream === 'docker' ? dockerScroll.value : solScroll.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

async function loadSnapshot(buildId: string) {
  try {
    const build = await buildsStore.fetchBuild(props.agentId, buildId)
    solLines.value = build.solLog ? build.solLog.split('\n').filter((l) => l.length > 0) : []
    dockerLines.value = build.dockerLog ? build.dockerLog.split('\n').filter((l) => l.length > 0) : []
    snapshotSeq.value = Number(build.logSeq || 0n)
  } catch {
    // Build may not yet exist (race between subscribe and creation) — tolerate.
  }
}

function handleMessage(payload: any) {
  if (payload?.agentId !== props.agentId) return
  // If we know the build id, drop messages for other builds.
  if (props.buildId && payload.buildId && payload.buildId !== props.buildId) return
  const msg = {
    seq: Number(payload.seq || 0),
    stream: String(payload.stream || 'sol'),
    line: String(payload.line || ''),
    buildId: String(payload.buildId || ''),
  }
  if (!snapshotLoaded.value) {
    wsBuffer.value.push(msg)
    return
  }
  if (msg.seq > 0 && msg.seq <= snapshotSeq.value) return
  appendLine(msg.stream, msg.line)
}

async function hydrate() {
  snapshotLoaded.value = false
  solLines.value = []
  dockerLines.value = []
  snapshotSeq.value = 0

  if (props.buildId) await loadSnapshot(props.buildId)

  snapshotLoaded.value = true
  // Drain anything that arrived while we were loading.
  for (const msg of wsBuffer.value) {
    if (props.buildId && msg.buildId && msg.buildId !== props.buildId) continue
    if (msg.seq > 0 && msg.seq <= snapshotSeq.value) continue
    appendLine(msg.stream, msg.line)
  }
  wsBuffer.value = []
}

onMounted(async () => {
  // Subscribe FIRST so incoming messages during snapshot fetch are buffered.
  unsub = ws.onMessage('agent.build.log', handleMessage)
  await hydrate()
})

watch(
  () => props.buildId,
  async (newId, oldId) => {
    if (newId !== oldId) await hydrate()
  },
)

onUnmounted(() => {
  unsub?.()
})
</script>

<template>
  <div v-if="active">
    <div style="display: flex; justify-content: flex-end; margin-bottom: 0.25rem">
      <Button label="Cancel Build" icon="pi pi-times" severity="danger" size="small" text @click="emit('cancel')" />
    </div>

    <div style="display: flex; flex-direction: column; gap: 0.5rem">
      <div>
        <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">
          Sol (codegen)
        </div>
        <div
          ref="solScroll"
          style="
            background: var(--p-surface-900);
            color: var(--p-green-400);
            font-family: monospace;
            font-size: 0.8rem;
            line-height: 1.4;
            padding: 0.75rem;
            border-radius: 0.5rem;
            max-height: 20rem;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
          "
        >
          <div v-for="(line, i) in solLines" :key="i">{{ line }}</div>
          <div v-if="solLines.length === 0" style="opacity: 0.5">Waiting for build output...</div>
        </div>
      </div>

      <div v-if="dockerLines.length > 0">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--p-text-muted-color); margin-bottom: 0.25rem">
          Docker (image build)
        </div>
        <div
          ref="dockerScroll"
          style="
            background: var(--p-surface-900);
            color: var(--p-blue-400);
            font-family: monospace;
            font-size: 0.8rem;
            line-height: 1.4;
            padding: 0.75rem;
            border-radius: 0.5rem;
            max-height: 20rem;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
          "
        >
          <div v-for="(line, i) in dockerLines" :key="i">{{ line }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
