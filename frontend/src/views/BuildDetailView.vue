<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { fromJson } from '@bufbuild/protobuf'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useBuildStream } from '@/composables/useBuildStream'
import { useBuildsStore } from '@/stores/builds'
import { AgentBuildDeploymentPhase, type JobInfo } from '@/gen/airlock/v1/types_pb'
import { JobLifecycleEventSchema, JobsSubscribedEventSchema } from '@/gen/airlock/v1/realtime_pb'
import { ws } from '@/api/ws'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'
import { jobStatusLabel } from '@/utils/jobs'

const route = useRoute()
const toast = useToast()
const confirm = useConfirm()
const buildsStore = useBuildsStore()
const { t, formatDate, formatNumber } = useAirlockI18n()
const agentId = route.params.id as string
const buildId = route.params.buildId as string
const agentName = ref(agentId.slice(0, 8))

const { build, solLines, dockerLines, todos, phase, loaded, refreshSnapshot } = useBuildStream(agentId, buildId)

const isBuilding = computed(() => build.value?.status === 'building')
const canceling = ref(false)
const blockerJobs = ref<JobInfo[]>([])
const blockerNextCursor = ref<string | null>(null)
const blockerLoading = ref(false)
const cancelingJobId = ref('')
const now = ref(Date.now())
const unsubscribers: Array<() => void> = []
let pollTimer: number | null = null
let clockTimer: number | null = null
let refreshInFlight = false
let refreshQueued = false

async function cancelBuild() {
  canceling.value = true
  try {
    await api.post(`/api/v1/agents/${agentId}/builds/cancel`)
    toast.add({ severity: 'info', summary: t('operations.build.cancelled'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('operations.build.cancelFailed'), life: 5000 })
  } finally {
    canceling.value = false
  }
}
const phaseLabel = computed(() => {
  switch (build.value?.deploymentPhase) {
    case AgentBuildDeploymentPhase.BLOCKED: return t('operations.build.phase.deploymentBlocked')
    case AgentBuildDeploymentPhase.PAUSED: return t('operations.build.phase.draining')
    case AgentBuildDeploymentPhase.STARTING: return t('operations.build.phase.starting')
    case AgentBuildDeploymentPhase.ROLLBACK: return t('operations.build.phase.rollback')
    case AgentBuildDeploymentPhase.MANIFEST: return t('operations.build.phase.manifest')
  }
  switch (phase.value) {
    case 'image': return t('operations.build.phase.image')
    case 'connectors': return t('operations.build.phase.connectors')
    case 'migrations': return t('operations.build.phase.migrations')
    case 'deploy': return t('operations.build.phase.deploy')
    case 'codegen': return t('operations.build.phase.codegen')
    default: return ''
  }
})

const showDeploymentState = computed(() => isBuilding.value && [
  AgentBuildDeploymentPhase.BLOCKED,
  AgentBuildDeploymentPhase.PAUSED,
  AgentBuildDeploymentPhase.STARTING,
  AgentBuildDeploymentPhase.ROLLBACK,
].includes(build.value?.deploymentPhase ?? AgentBuildDeploymentPhase.UNSPECIFIED))
const drainDeadline = computed(() => build.value?.deploymentDrainDeadline ? timestampDate(build.value.deploymentDrainDeadline) : null)
const drainSecondsRemaining = computed(() => drainDeadline.value ? Math.max(0, Math.ceil((drainDeadline.value.getTime() - now.value) / 1000)) : null)
const blockerCount = computed(() => (build.value?.jobBlockers ?? []).reduce((total, item) => total + item.queuedCount + item.runningCount, 0n))

function countdown(seconds: number): string {
  const minutes = Math.floor(seconds / 60)
  return `${formatNumber(minutes, { useGrouping: false })}:${formatNumber(seconds % 60, { minimumIntegerDigits: 2, useGrouping: false })}`
}

function buildTypeLabel(type: string): string {
  switch (type) {
    case 'build': return t('operations.build.type.build')
    case 'upgrade': return t('operations.build.type.upgrade')
    case 'rollback': return t('operations.build.type.rollback')
    default: return type
  }
}

function buildStatusLabel(status: string): string {
  switch (status) {
    case 'building': return t('operations.build.status.building')
    case 'complete': return t('operations.build.status.complete')
    case 'failed': return t('operations.build.status.failed')
    case 'refused': return t('operations.build.status.refused')
    case 'cancelled': return t('operations.build.status.cancelled')
    default: return status
  }
}

async function fetchBlockers(reset = true) {
  if (blockerLoading.value || (!reset && !blockerNextCursor.value)) return
  blockerLoading.value = true
  try {
    const page = await buildsStore.fetchJobBlockers(agentId, buildId, reset ? undefined : blockerNextCursor.value!)
    blockerJobs.value = reset ? page.jobs : [...blockerJobs.value, ...page.jobs]
    blockerNextCursor.value = page.nextCursor
  } finally {
    blockerLoading.value = false
  }
}

async function refreshAuthoritative() {
  if (refreshInFlight) {
    refreshQueued = true
    return
  }
  refreshInFlight = true
  try {
    await Promise.all([refreshSnapshot(), blockerJobs.value.length > 50 ? Promise.resolve() : fetchBlockers()])
  } finally {
    refreshInFlight = false
    if (refreshQueued) {
      refreshQueued = false
      void refreshAuthoritative().catch(() => {})
    }
  }
}

function confirmCancelJob(job: JobInfo) {
  confirm.require({
    header: t('operations.build.blockers.cancelTitle'),
    message: t('operations.build.blockers.cancelMessage', {
      handler: job.handlerName,
      version: job.handlerVersion,
      id: job.id.slice(0, 8),
    }),
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: t('operations.build.blockers.cancelJob'),
    rejectLabel: t('operations.build.blockers.keepJob'),
    acceptClass: 'p-button-danger',
    accept: async () => {
      cancelingJobId.value = job.id
      try {
        await buildsStore.cancelJobBlocker(job.id)
        await Promise.all([refreshSnapshot(), fetchBlockers()])
        toast.add({
          severity: 'info',
          summary: job.status === 'running'
            ? t('operations.build.blockers.cancellationRequested')
            : t('operations.build.blockers.jobCancelled'),
          life: 3000,
        })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('operations.build.cancelFailed'), life: 5000 })
      } finally {
        cancelingJobId.value = ''
      }
    },
  })
}

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

const costFormatted = computed(() => formatNumber(build.value?.llmCostEstimate ?? 0, {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 4,
  maximumFractionDigits: 4,
}))
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
  unsubscribers.push(
    ws.onMessage('job.lifecycle', (payload) => {
      try {
        const event = fromJson(JobLifecycleEventSchema, payload as any)
        if (event.summary?.agentId === agentId) void refreshAuthoritative().catch(() => {})
      } catch { /* malformed event */ }
    }),
    ws.onMessage('jobs.subscribed', (payload) => {
      try {
        const event = fromJson(JobsSubscribedEventSchema, payload as any)
        if (event.agentId === agentId) void refreshAuthoritative().catch(() => {})
      } catch { /* malformed event */ }
    }),
  )
  ws.subscribeJobs(agentId)
  void refreshAuthoritative().catch(() => {})
  pollTimer = window.setInterval(() => {
    if (isBuilding.value) void refreshAuthoritative().catch(() => {})
  }, 1500)
  clockTimer = window.setInterval(() => { now.value = Date.now() }, 1000)
})

onUnmounted(() => {
  ws.unsubscribeJobs(agentId)
  for (const unsubscribe of unsubscribers) unsubscribe()
  if (pollTimer !== null) window.clearInterval(pollTimer)
  if (clockTimer !== null) window.clearInterval(clockTimer)
})
</script>

<template>
  <div v-if="!loaded">
    <Skeleton width="40%" height="2rem" style="margin-bottom: 1rem" />
    <Skeleton width="100%" height="24rem" />
  </div>

  <div v-else-if="build">
    <h1 style="margin: 0 0 1rem; font-size: 1.25rem">{{ t('operations.build.title', { agent: agentName, id: build.id.slice(0, 8) }) }}</h1>

    <!-- Metadata bar -->
    <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 1rem; margin-bottom: 1.5rem">
      <Tag :value="buildTypeLabel(build.type)" severity="secondary" />
      <Tag :value="buildStatusLabel(build.status)" :severity="statusSeverity" />
      <span v-if="isBuilding && phaseLabel" style="display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.875rem; color: var(--p-primary-color); font-weight: 500">
        <i class="pi pi-spin pi-spinner" style="font-size: 0.75rem" /> {{ phaseLabel }}
      </span>
      <Button
        v-if="isBuilding"
        :label="t('operations.build.cancel')"
        icon="pi pi-times"
        severity="danger"
        outlined
        size="small"
        :loading="canceling"
        @click="cancelBuild"
      />
      <span v-if="todos.length" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ t('operations.build.tasksProgress', {
          doneFormatted: formatNumber(tasksDone),
          countFormatted: formatNumber(todos.length),
          count: todos.length,
        }) }}
      </span>
      <span v-if="build.startedAt" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ formatDate(timestampDate(build.startedAt), {
          year: 'numeric',
          month: 'numeric',
          day: 'numeric',
          hour: 'numeric',
          minute: '2-digit',
          second: '2-digit',
        }) }}
      </span>
      <span v-if="build.sourceRef" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ build.sourceRef.slice(0, 12) }}
      </span>
      <span v-if="build.llmCalls" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ cachedTokens > 0
          ? t('operations.build.tokensCached', {
              input: formatNumber(nonCachedIn),
              cached: formatNumber(cachedTokens),
              output: formatNumber(build.llmTokensOut ?? 0),
            })
          : t('operations.build.tokens', {
              input: formatNumber(nonCachedIn),
              output: formatNumber(build.llmTokensOut ?? 0),
            }) }}
      </span>
      <span v-if="build.llmCalls" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ costFormatted }}
      </span>
    </div>

    <section v-if="showDeploymentState" class="deployment-panel">
      <div class="deployment-heading">
        <div>
          <h3>{{ phaseLabel }}</h3>
          <p v-if="build.deploymentPhase === AgentBuildDeploymentPhase.BLOCKED">
            {{ t('operations.build.deployment.blocked', {
              formattedCount: formatNumber(blockerCount),
              count: Number(blockerCount),
            }) }}
          </p>
          <p v-else-if="build.deploymentPhase === AgentBuildDeploymentPhase.PAUSED">
            {{ t('operations.build.deployment.paused') }}
          </p>
          <p v-else-if="build.deploymentPhase === AgentBuildDeploymentPhase.STARTING">
            {{ t('operations.build.deployment.starting') }}
          </p>
          <p v-else-if="build.deploymentPhase === AgentBuildDeploymentPhase.ROLLBACK">
            {{ t('operations.build.deployment.rollback') }}
          </p>
        </div>
        <Tag
          :value="build.deploymentPhase === AgentBuildDeploymentPhase.PAUSED ? t('operations.build.deployment.drainingStatus') : phaseLabel"
          :severity="build.deploymentPhase === AgentBuildDeploymentPhase.ROLLBACK ? 'danger' : 'warn'"
        />
      </div>

      <div v-if="build.deploymentPausedAt && drainDeadline" class="drain-window">
        <span>{{ t('operations.build.deployment.pausedAt', { time: formatDate(timestampDate(build.deploymentPausedAt), { timeStyle: 'medium' }) }) }}</span>
        <span>{{ t('operations.build.deployment.deadline', { time: formatDate(drainDeadline, { timeStyle: 'medium' }) }) }}</span>
        <strong v-if="drainSecondsRemaining !== null">{{ t('operations.build.deployment.remaining', { time: countdown(drainSecondsRemaining) }) }}</strong>
      </div>

      <div v-if="build.jobBlockers.length" class="blocker-summaries">
        <div v-for="summary in build.jobBlockers" :key="`${summary.handlerName}:${summary.handlerVersion}:${summary.inputSchemaHash}:${summary.outputSchemaHash}`" class="blocker-contract">
          <div>
            <code>{{ summary.handlerName }}@v{{ summary.handlerVersion }}</code>
            <span>{{ t('operations.build.blockers.queued', { count: formatNumber(summary.queuedCount) }) }} · {{ t('operations.build.blockers.running', { count: formatNumber(summary.runningCount) }) }}</span>
          </div>
          <dl>
            <dt>{{ t('operations.build.blockers.inputSchema') }}</dt><dd><code>{{ summary.inputSchemaHash }}</code></dd>
            <dt>{{ t('operations.build.blockers.outputSchema') }}</dt><dd><code>{{ summary.outputSchemaHash }}</code></dd>
          </dl>
        </div>
      </div>

      <div v-if="blockerJobs.length" class="blocker-jobs">
        <h4>{{ t('operations.build.blockers.heading') }}</h4>
        <div v-for="job in blockerJobs" :key="job.id" class="blocker-job">
          <RouterLink :to="{ name: 'job-detail', params: { id: agentId, jobId: job.id } }">
            {{ job.handlerName }}@v{{ job.handlerVersion }} · {{ job.id.slice(0, 8) }}
          </RouterLink>
          <Tag :value="jobStatusLabel(job, t)" :severity="job.status === 'running' ? 'warn' : 'secondary'" />
          <Button
            v-if="!job.cancelRequestedAt && (job.status === 'queued' || job.status === 'running')"
            :label="t('operations.job.cancel.action')"
            icon="pi pi-times"
            severity="danger"
            text
            size="small"
            :loading="cancelingJobId === job.id"
            @click="confirmCancelJob(job)"
          />
        </div>
        <Button
          v-if="blockerNextCursor"
          :label="t('operations.build.blockers.loadMore')"
          icon="pi pi-angle-down"
          severity="secondary"
          outlined
          size="small"
          :loading="blockerLoading"
          @click="fetchBlockers(false)"
        />
      </div>
    </section>

    <!-- Result: exit outcome + any infra error -->
    <Message v-if="build.status === 'failed' && build.failureKind === 'infra'" severity="warn" :closable="false" icon="pi pi-server" style="margin-bottom: 0.75rem">
      {{ t('operations.build.platformErrorDetail') }}
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
      <h3 style="margin-bottom: 0.75rem">{{ t('operations.build.instructions') }}</h3>
      <pre class="log-panel">{{ build.instructions }}</pre>
    </div>

    <!-- Tasks checklist -->
    <div v-if="todos.length" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">{{ t('operations.build.tasks', {
        doneFormatted: formatNumber(tasksDone),
        countFormatted: formatNumber(todos.length),
      }) }}</h3>
      <ul class="todo-list">
        <li v-for="(t, i) in todos" :key="t.id || i" :class="todoClass(t.status)">
          <i :class="todoIcon(t.status)" /> <span>{{ t.content }}</span>
        </li>
      </ul>
    </div>

    <!-- Codegen log -->
    <div style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">{{ t('operations.build.codegenLog') }}</h3>
      <div ref="solScroll" class="stream-panel stream-sol">
        <div v-for="(line, i) in solLines" :key="i">{{ line }}</div>
        <div v-if="solLines.length === 0" style="opacity: 0.5">{{ t('operations.build.waitingForOutput') }}</div>
      </div>
    </div>

    <!-- Docker build log -->
    <div v-if="dockerLines.length > 0" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">{{ t('operations.build.dockerLog') }}</h3>
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

.deployment-panel {
  margin-bottom: 1.5rem;
  padding: 1rem;
  border: 1px solid var(--p-orange-300);
  border-radius: 0.65rem;
  background: color-mix(in srgb, var(--p-orange-100) 45%, transparent);
}
.deployment-heading {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
}
.deployment-heading h3, .deployment-heading p, .blocker-jobs h4 { margin: 0; }
.deployment-heading p { margin-top: 0.35rem; color: var(--p-text-muted-color); }
.drain-window {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 1.25rem;
  margin-top: 1rem;
  font-size: 0.875rem;
}
.blocker-summaries, .blocker-jobs { display: grid; gap: 0.65rem; margin-top: 1rem; }
.blocker-contract, .blocker-job {
  padding: 0.75rem;
  border: 1px solid var(--p-surface-300);
  border-radius: 0.5rem;
  background: var(--p-surface-0);
}
.blocker-contract > div, .blocker-job {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}
.blocker-contract dl { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 0.25rem 0.75rem; margin: 0.6rem 0 0; font-size: 0.75rem; }
.blocker-contract dt { color: var(--p-text-muted-color); }
.blocker-contract dd { margin: 0; min-width: 0; }
.blocker-contract dd code { overflow-wrap: anywhere; }
.blocker-job a { flex: 1; min-width: 0; }
@media (max-width: 640px) {
  .deployment-heading, .blocker-job { align-items: stretch; flex-direction: column; }
  .blocker-contract > div { align-items: flex-start; flex-direction: column; }
  .blocker-contract dl { grid-template-columns: 1fr; }
}
</style>
