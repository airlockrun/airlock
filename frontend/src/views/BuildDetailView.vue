<script setup lang="ts">
import { ref, onMounted, computed, watch, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { fromJson } from '@bufbuild/protobuf'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useBuildStream } from '@/composables/useBuildStream'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'

const route = useRoute()
const toast = useToast()
const agentId = route.params.id as string
const buildId = route.params.buildId as string
const agentName = ref(agentId.slice(0, 8))

const { build, solLines, dockerLines, todos, phase, loaded } = useBuildStream(agentId, buildId)

const isBuilding = computed(() => build.value?.status === 'building')
const canceling = ref(false)

async function cancelBuild() {
  canceling.value = true
  try {
    await api.post(`/api/v1/agents/${agentId}/builds/cancel`)
    toast.add({ severity: 'info', summary: 'Build cancelled', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Cancel failed', life: 5000 })
  } finally {
    canceling.value = false
  }
}
const phaseLabel = computed(() => {
  switch (phase.value) {
    case 'image': return 'Building image…'
    case 'migrations': return 'Running migrations…'
    case 'deploy': return 'Deploying…'
    case 'codegen': return 'Generating code…'
    default: return ''
  }
})

const solScroll = ref<HTMLElement | null>(null)
const dockerScroll = ref<HTMLElement | null>(null)

function scrollToBottom(el: HTMLElement | null) {
  if (el) el.scrollTop = el.scrollHeight
}
watch(() => solLines.value.length, () => nextTick(() => scrollToBottom(solScroll.value)))
watch(() => dockerLines.value.length, () => nextTick(() => scrollToBottom(dockerScroll.value)))

const statusSeverity = computed(() => {
  switch (build.value?.status) {
    case 'complete': return 'success'
    case 'building': return 'warn'
    case 'failed': return 'danger'
    case 'refused': return 'warn'
    default: return 'secondary'
  }
})

const costFormatted = computed(() => `$${(build.value?.llmCostEstimate ?? 0).toFixed(4)}`)
const cachedTokens = computed(() => build.value?.llmTokensCached ?? 0)
const nonCachedIn = computed(() => Math.max(0, (build.value?.llmTokensIn ?? 0) - cachedTokens.value))

const tasksDone = computed(() => todos.value.filter((t) => t.status === 'completed').length)

const todoIcon = (status: string) => {
  switch (status) {
    case 'completed': return 'pi pi-check-circle'
    case 'in_progress': return 'pi pi-spin pi-spinner'
    case 'cancelled': return 'pi pi-times-circle'
    default: return 'pi pi-circle'
  }
}
const todoClass = (status: string) => `todo-${status}`

onMounted(() => {
  api.get(`/api/v1/agents/${agentId}`).then(({ data }) => {
    const agent = fromJson(GetAgentDetailResponseSchema, data).agent
    if (agent) agentName.value = agent.name
  }).catch(() => {})
})
</script>

<template>
  <div v-if="!loaded">
    <Skeleton width="40%" height="2rem" style="margin-bottom: 1rem" />
    <Skeleton width="100%" height="24rem" />
  </div>

  <div v-else-if="build">
    <h1 style="margin: 0 0 1rem; font-size: 1.25rem">{{ agentName }} · Build {{ build.id.slice(0, 8) }}</h1>

    <!-- Metadata bar -->
    <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 1rem; margin-bottom: 1.5rem">
      <Tag :value="build.type" severity="secondary" />
      <Tag :value="build.status" :severity="statusSeverity" />
      <span v-if="isBuilding && phaseLabel" style="display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.875rem; color: var(--p-primary-color); font-weight: 500">
        <i class="pi pi-spin pi-spinner" style="font-size: 0.75rem" /> {{ phaseLabel }}
      </span>
      <Button
        v-if="isBuilding"
        label="Cancel build"
        icon="pi pi-times"
        severity="danger"
        outlined
        size="small"
        :loading="canceling"
        @click="cancelBuild"
      />
      <span v-if="todos.length" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ tasksDone }}/{{ todos.length }} tasks
      </span>
      <span v-if="build.startedAt" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ timestampDate(build.startedAt).toLocaleString() }}
      </span>
      <span v-if="build.sourceRef" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ build.sourceRef.slice(0, 12) }}
      </span>
      <span v-if="build.llmCalls" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ nonCachedIn.toLocaleString() }} in<template v-if="cachedTokens > 0"> + {{ cachedTokens.toLocaleString() }} cached</template> / {{ (build.llmTokensOut ?? 0).toLocaleString() }} out tokens
      </span>
      <span v-if="build.llmCalls" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ costFormatted }}
      </span>
    </div>

    <!-- Result: exit outcome + any infra error -->
    <Message v-if="build.status === 'failed' && build.failureKind === 'infra'" severity="warn" :closable="false" icon="pi pi-server" style="margin-bottom: 0.75rem">
      Platform error - a build infrastructure failure (toolserver / docker / deploy), not a problem in your app's code. Retry the build; if it persists, check the Airlock logs.
    </Message>
    <Message v-if="build.exitStatus === 'success' && build.exitMessage" severity="success" :closable="false" style="margin-bottom: 0.75rem">
      {{ build.exitMessage }}
    </Message>
    <Message v-else-if="build.exitMessage" severity="warn" :closable="false" style="margin-bottom: 0.75rem">
      {{ build.exitMessage }}
    </Message>
    <Message v-if="build.errorMessage && build.errorMessage !== build.exitMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      {{ build.errorMessage }}
    </Message>

    <!-- Instructions -->
    <div v-if="build.instructions" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Instructions</h3>
      <pre class="log-panel">{{ build.instructions }}</pre>
    </div>

    <!-- Tasks checklist -->
    <div v-if="todos.length" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Tasks ({{ tasksDone }}/{{ todos.length }})</h3>
      <ul class="todo-list">
        <li v-for="(t, i) in todos" :key="t.id || i" :class="todoClass(t.status)">
          <i :class="todoIcon(t.status)" /> <span>{{ t.content }}</span>
        </li>
      </ul>
    </div>

    <!-- Codegen log -->
    <div style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Codegen log</h3>
      <div ref="solScroll" class="stream-panel stream-sol">
        <div v-for="(line, i) in solLines" :key="i">{{ line }}</div>
        <div v-if="solLines.length === 0" style="opacity: 0.5">Waiting for build output…</div>
      </div>
    </div>

    <!-- Docker build log -->
    <div v-if="dockerLines.length > 0" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Docker build log</h3>
      <div ref="dockerScroll" class="stream-panel stream-docker">
        <div v-for="(line, i) in dockerLines" :key="i">{{ line }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.log-panel {
  white-space: pre-wrap;
  font-size: 0.8rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  padding: 0.75rem;
  border-radius: 0.5rem;
  background: var(--p-surface-100);
  border: 1px solid var(--p-surface-200);
  max-height: 24rem;
  overflow: auto;
}
:root.dark .log-panel {
  background: var(--p-surface-800);
  border-color: var(--p-surface-700);
}

.stream-panel {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8rem;
  line-height: 1.4;
  padding: 0.75rem;
  border-radius: 0.5rem;
  max-height: 24rem;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  background: var(--p-surface-900);
}
.stream-sol { color: var(--p-green-400); }
.stream-docker { color: var(--p-blue-400); }

.todo-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.todo-list li {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  font-size: 0.9rem;
}
.todo-list .pi {
  font-size: 0.8rem;
}
.todo-completed { color: var(--p-green-500); }
.todo-completed span { text-decoration: line-through; opacity: 0.7; }
.todo-in_progress { color: var(--p-primary-color); font-weight: 500; }
.todo-cancelled { color: var(--p-text-muted-color); }
.todo-cancelled span { text-decoration: line-through; opacity: 0.6; }
.todo-pending { color: var(--p-text-color); }
</style>
