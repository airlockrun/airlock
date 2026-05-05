<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { fromJson } from '@bufbuild/protobuf'
import { useRunsStore } from '@/stores/runs'
import type { RunInfo } from '@/gen/airlock/v1/types_pb'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useToast } from 'primevue/usetoast'
import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import { unwrapValue } from '@/api/proto'
import api from '@/api/client'
import { useMarkdown } from '@/composables/useMarkdown'
import { enrichMessages } from '@/utils/messageGroup'

// Per-tool-call collapse state. Defaults to expanded (RunDetailView is the
// audit view — show what happened by default; let the reader collapse if
// they want a summary).
const toolCollapseState = ref<Record<string, boolean>>({})
function toggleToolCollapse(id: string) {
  toolCollapseState.value[id] = !toolCollapseState.value[id]
}
function isToolCollapsed(id: string): boolean {
  return toolCollapseState.value[id] === true
}

const route = useRoute()
const router = useRouter()
const runsStore = useRunsStore()
const toast = useToast()

const agentId = route.params.id as string
const runId = route.params.runId as string
const run = ref<RunInfo | null>(null)
const runMessages = ref<AgentMessageInfo[]>([])
const agentName = ref(agentId.slice(0, 8))
const loading = ref(true)
const fixInstructions = ref('')
const fixDialogVisible = ref(false)
const fixLoading = ref(false)

async function submitFix() {
  fixLoading.value = true
  try {
    await api.post(`/api/v1/agents/${agentId}/upgrade`, {
      runId,
      description: fixInstructions.value || undefined,
    })
    toast.add({ severity: 'success', summary: 'Fix started', life: 3000 })
    fixDialogVisible.value = false
    router.push(`/agents/${agentId}`)
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Fix failed', life: 5000 })
  } finally {
    fixLoading.value = false
  }
}

const statusSeverity = computed(() => {
  switch (run.value?.status) {
    case 'success': case 'done': return 'success'
    case 'running': return 'warn'
    case 'tool_errors': return 'warn'
    case 'error': case 'failed': return 'danger'
    case 'suspended': return 'info'
    default: return 'secondary'
  }
})

const durationFormatted = computed(() => {
  if (!run.value?.durationMs) return '-'
  const ms = run.value.durationMs
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
})

const costFormatted = computed(() => {
  const cost = run.value?.llmCostEstimate ?? 0
  return `$${cost.toFixed(4)}`
})

const tokenTotal = computed(() => (run.value?.llmTokensIn ?? 0) + (run.value?.llmTokensOut ?? 0))
const meterValues = computed(() => {
  if (!tokenTotal.value) return []
  return [
    { label: 'Input', value: run.value?.llmTokensIn ?? 0, color: 'var(--p-blue-500)' },
    { label: 'Output', value: run.value?.llmTokensOut ?? 0, color: 'var(--p-green-500)' },
  ]
})

const actions = computed(() => {
  if (!run.value?.actions?.values) return []
  return run.value.actions.values.map(unwrapValue) as Record<string, any>[]
})

const hasErrors = computed(() => {
  const s = run.value?.status
  return s === 'tool_errors' || s === 'error' || s === 'failed'
})

// Hide the Fix-this-error workflow on platform-side errors (provider 4xx,
// network) — sending the run context to the build agent won't help when the
// agent's own code wasn't at fault. Empty error_kind keeps the button visible
// (legacy / unclassified errors).
const isPlatformError = computed(() => run.value?.errorKind === 'platform')

function formatActionInput(action: Record<string, any>): string {
  if (!action.request) return ''
  if (typeof action.request === 'string') return action.request
  const keys = Object.keys(action.request)
  if (keys.length === 1) return String(action.request[keys[0]])
  return JSON.stringify(action.request, null, 2)
}

function formatDurationMs(ms: number): string {
  if (!ms) return '<1ms'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

onMounted(async () => {
  try {
    const [result] = await Promise.all([
      runsStore.fetchRun(runId),
      api.get(`/api/v1/agents/${agentId}`).then(({ data }) => {
        const agent = fromJson(GetAgentDetailResponseSchema, data).agent
        if (agent) agentName.value = agent.name
      }).catch(() => {}),
    ])
    run.value = result.run
    runMessages.value = enrichMessages(result.messages)
  } catch {
    toast.add({ severity: 'error', summary: 'Run not found', life: 3000 })
    router.push(`/agents/${agentId}`)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div v-if="loading">
    <Skeleton width="40%" height="2rem" style="margin-bottom: 1rem" />
    <Skeleton width="100%" height="24rem" />
  </div>

  <div v-else-if="run">
    <!-- Breadcrumb -->
    <Breadcrumb
      :model="[
        { label: 'Agents', to: '/agents' },
        { label: agentName, to: `/agents/${agentId}` },
        { label: 'Runs' },
        { label: run.id.slice(0, 8) },
      ]"
      style="margin-bottom: 1rem"
    >
      <template #item="{ item }">
        <router-link v-if="item.to" :to="item.to" style="text-decoration: none; color: var(--p-primary-color)">
          {{ item.label }}
        </router-link>
        <span v-else>{{ item.label }}</span>
      </template>
    </Breadcrumb>

    <!-- Metadata bar -->
    <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 1rem; margin-bottom: 1.5rem">
      <Tag :value="run.status" :severity="statusSeverity" />
      <span v-if="run.startedAt" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ timestampDate(run.startedAt).toLocaleString() }}
      </span>
      <span style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ durationFormatted }}
      </span>
      <span v-if="tokenTotal" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ (run.llmTokensIn ?? 0).toLocaleString() }} in / {{ (run.llmTokensOut ?? 0).toLocaleString() }} out tokens
      </span>
      <span style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ costFormatted }}
      </span>
    </div>

    <!-- Conversation -->
    <div v-if="runMessages.length" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Conversation</h3>
      <div style="display: flex; flex-direction: column; gap: 0.5rem">
        <template v-for="msg in runMessages" :key="msg.id">
          <!-- Orphan tool result (no parent assistant we could fold into).
               Folded rows are marked _hidden by enrichMessages. -->
          <div v-if="msg.role === 'tool' && !(msg as any)._hidden && msg.content" style="display: flex; justify-content: flex-start">
            <div class="run-msg run-msg-tool">
              <pre style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0">{{ msg.content }}</pre>
            </div>
          </div>
          <!-- User / Assistant. Assistant turns may carry toolCalls[]
               folded from per-tool rows by enrichMessages — render them
               inside the same bubble first, then the text answer below.
               Mirrors AgentChatView so the audit view matches what the
               user saw live. -->
          <div v-else-if="msg.content || (msg as any).toolCalls?.length" :style="{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }">
            <div :class="['run-msg', msg.role === 'user' ? 'run-msg-user' : 'run-msg-assistant']">
              <div v-if="(msg as any).toolCalls?.length" :style="{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }">
                <div v-for="tc in (msg as any).toolCalls" :key="tc.toolCallId" style="padding: 0.25rem 0">
                  <div style="display: flex; align-items: center; justify-content: space-between; cursor: pointer" @click="toggleToolCollapse(tc.toolCallId)">
                    <div style="font-size: 0.7rem; text-transform: uppercase; opacity: 0.6">{{ tc.toolName }}</div>
                    <i :class="isToolCollapsed(tc.toolCallId) ? 'pi pi-plus' : 'pi pi-minus'" style="font-size: 0.7rem; opacity: 0.4" />
                  </div>
                  <template v-if="!isToolCollapsed(tc.toolCallId)">
                    <div v-if="tc.input" style="margin-top: 0.25rem; margin-bottom: 0.5rem">
                      <pre style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; opacity: 0.7">{{ tc.input }}</pre>
                    </div>
                    <pre v-if="tc.output" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0">{{ tc.output }}</pre>
                    <pre v-if="tc.error" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0; color: var(--p-red-500)">{{ tc.error }}</pre>
                  </template>
                </div>
              </div>
              <div
                v-if="msg.content"
                v-html="useMarkdown(computed(() => msg.content)).html.value"
                class="chat-bubble"
                :style="{ marginTop: (msg as any).toolCalls?.length ? '0.75rem' : '0' }"
              />
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- Error panel -->
    <Message v-if="run.errorMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      <div>{{ run.errorMessage }}</div>
      <div v-if="isPlatformError" style="font-size: 0.8rem; margin-top: 0.5rem; opacity: 0.85">
        Platform error — provider, network, or auth failure upstream of the agent. Retrying may help; fixing the agent code won't.
      </div>
      <pre v-if="run.panicTrace" style="white-space: pre-wrap; font-size: 0.8rem; margin-top: 0.5rem">{{ run.panicTrace }}</pre>
    </Message>

    <!-- Actions -->
    <div v-if="actions.length" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Actions</h3>
      <div style="display: flex; flex-direction: column; gap: 0.5rem">
        <div v-for="(action, i) in actions" :key="i" class="action-card">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem">
            <span style="font-weight: 600; font-size: 0.85rem; text-transform: uppercase">{{ action.type || 'action' }}</span>
            <span v-if="action.durationMs !== undefined" style="font-size: 0.75rem; color: var(--p-text-muted-color)">{{ formatDurationMs(action.durationMs) }}</span>
          </div>
          <pre v-if="formatActionInput(action)" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0.25rem 0; opacity: 0.7">{{ formatActionInput(action) }}</pre>
          <pre v-if="action.response" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; margin: 0.25rem 0">{{ typeof action.response === 'string' ? action.response : JSON.stringify(action.response, null, 2) }}</pre>
          <div v-if="action.error" style="color: var(--p-red-500); font-size: 0.8rem">{{ action.error }}</div>
        </div>
      </div>
    </div>

    <!-- Fix button — only for agent-code errors. Platform errors get the
         message panel above explaining why this workflow doesn't help. -->
    <div v-if="hasErrors && !isPlatformError" style="margin-bottom: 1.5rem">
      <Button label="Fix this error" icon="pi pi-wrench" severity="warn" @click="fixDialogVisible = true" />
    </div>

    <Dialog v-model:visible="fixDialogVisible" header="Fix Agent Error" modal style="width: 32rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; padding-top: 0.5rem">
        <p style="font-size: 0.85rem; color: var(--p-text-muted-color); margin: 0">
          The full run context (messages, actions, errors) will be passed to the build agent.
        </p>
        <Textarea
          v-model="fixInstructions"
          :auto-resize="true"
          rows="3"
          placeholder="Additional instructions (optional)"
          style="width: 100%"
        />
        <div style="display: flex; justify-content: flex-end">
          <Button label="Start Fix" icon="pi pi-wrench" :loading="fixLoading" @click="submitFix" />
        </div>
      </div>
    </Dialog>

    <!-- Logs -->
    <div v-if="run.stdoutLog">
      <h3 style="margin-bottom: 0.75rem">Logs</h3>
      <pre class="log-panel">{{ run.stdoutLog }}</pre>
    </div>
  </div>
</template>

<style scoped>
.run-msg {
  max-width: 70%;
  min-width: 0;
  overflow-wrap: break-word;
  padding: 0.5rem 0.75rem;
  border-radius: 0.75rem;
}

.run-msg-user {
  background-color: var(--p-primary-color);
  color: var(--p-primary-contrast-color);
}

.run-msg-assistant {
  background-color: var(--p-content-hover-background);
  color: var(--p-text-color);
}

.run-msg-tool {
  background-color: var(--p-surface-100);
  color: var(--p-text-color);
  font-size: 0.85rem;
  border: 1px solid var(--p-surface-200);
}

:root.dark .run-msg-tool {
  background-color: var(--p-surface-800);
  border-color: var(--p-surface-700);
}

.action-card {
  padding: 0.75rem;
  border-radius: 0.5rem;
  background: var(--p-surface-100);
  border: 1px solid var(--p-surface-200);
}

:root.dark .action-card {
  background: var(--p-surface-800);
  border-color: var(--p-surface-700);
}

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
</style>
