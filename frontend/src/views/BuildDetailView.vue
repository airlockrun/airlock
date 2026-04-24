<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import { fromJson } from '@bufbuild/protobuf'
import { useBuildsStore } from '@/stores/builds'
import type { AgentBuildInfo } from '@/gen/airlock/v1/types_pb'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import { useToast } from 'primevue/usetoast'
import api from '@/api/client'

const route = useRoute()
const router = useRouter()
const buildsStore = useBuildsStore()
const toast = useToast()

const agentId = route.params.id as string
const buildId = route.params.buildId as string
const build = ref<AgentBuildInfo | null>(null)
const agentName = ref(agentId.slice(0, 8))
const loading = ref(true)

const statusSeverity = computed(() => {
  switch (build.value?.status) {
    case 'complete': return 'success'
    case 'building': return 'warn'
    case 'failed': return 'danger'
    default: return 'secondary'
  }
})

onMounted(async () => {
  try {
    const [b] = await Promise.all([
      buildsStore.fetchBuild(agentId, buildId),
      api.get(`/api/v1/agents/${agentId}`).then(({ data }) => {
        const agent = fromJson(GetAgentDetailResponseSchema, data).agent
        if (agent) agentName.value = agent.name
      }).catch(() => {}),
    ])
    build.value = b
  } catch {
    toast.add({ severity: 'error', summary: 'Build not found', life: 3000 })
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

  <div v-else-if="build">
    <Breadcrumb
      :model="[
        { label: 'Agents', to: '/agents' },
        { label: agentName, to: `/agents/${agentId}` },
        { label: 'Builds' },
        { label: build.id.slice(0, 8) },
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
      <Tag :value="build.type" severity="secondary" />
      <Tag :value="build.status" :severity="statusSeverity" />
      <span v-if="build.startedAt" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ timestampDate(build.startedAt).toLocaleString() }}
      </span>
      <span v-if="build.sourceRef" style="font-size: 0.875rem; color: var(--p-text-muted-color)">
        {{ build.sourceRef.slice(0, 12) }}
      </span>
    </div>

    <!-- Error -->
    <Message v-if="build.errorMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      {{ build.errorMessage }}
    </Message>

    <!-- Instructions -->
    <div v-if="build.instructions" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Instructions</h3>
      <pre class="log-panel">{{ build.instructions }}</pre>
    </div>

    <!-- Sol Log -->
    <div v-if="build.solLog" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Sol Log</h3>
      <pre class="log-panel">{{ build.solLog }}</pre>
    </div>

    <!-- Docker Log -->
    <div v-if="build.dockerLog" style="margin-bottom: 1.5rem">
      <h3 style="margin-bottom: 0.75rem">Docker Log</h3>
      <pre class="log-panel">{{ build.dockerLog }}</pre>
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
</style>
