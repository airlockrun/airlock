<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAgentsStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { useAgentStatus } from '@/composables/useAgentStatus'

const router = useRouter()
const store = useAgentsStore()
const auth = useAuthStore()

// Admins can administer every agent in the workspace, not just the ones they're
// a member of. The grid above is the caller's working set; this points to the
// governance surface for the rest without listing other people's agents here.
const canGovern = computed(() => auth.can('tenant.agent.list_all'))

onMounted(() => {
  store.fetchAgents()
})

function goToAgent(id: string) {
  router.push(`/agents/${id}`)
}
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Agents</h1>
      <Button label="Create Agent" icon="pi pi-plus" @click="router.push('/agents/create')" />
    </div>

    <!-- Loading skeletons -->
    <div v-if="store.loading" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem">
      <Card v-for="i in 6" :key="i">
        <template #content>
          <Skeleton width="60%" height="1.25rem" style="margin-bottom: 0.5rem" />
          <Skeleton width="40%" height="1rem" style="margin-bottom: 1rem" />
          <Skeleton width="30%" height="1.5rem" />
        </template>
      </Card>
    </div>

    <!-- Empty state -->
    <Card v-else-if="store.agents.length === 0" style="text-align: center; padding: 2rem">
      <template #content>
        <i class="pi pi-box" style="font-size: 3rem; color: var(--p-surface-400); margin-bottom: 1rem" />
        <p style="color: var(--p-text-muted-color)">No agents yet. Create your first agent to get started.</p>
        <Button label="Create Agent" icon="pi pi-plus" @click="router.push('/agents/create')" style="margin-top: 1rem" />
      </template>
    </Card>

    <!-- Agent grid — system agent is pinned first as a special tile. -->
    <div v-else style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem">
      <Card
        style="cursor: pointer; border: 1px solid var(--p-primary-200)"
        @click="router.push('/system')"
      >
        <template #title>
          <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem">
            <span style="font-size: 1.3rem; line-height: 1">⚙️</span>
            System Agent
          </div>
        </template>
        <template #subtitle>operator</template>
        <template #content>
          <Tag value="Operator" severity="info" style="margin-bottom: 0.5rem" />
          <p style="font-size: 0.875rem; color: var(--p-text-muted-color); margin-top: 0.5rem">
            Manage agents, bridges, connections, members and runs through chat — with your own permissions.
          </p>
        </template>
      </Card>
      <Card
        v-for="agent in store.agents"
        :key="agent.id"
        style="cursor: pointer"
        @click="goToAgent(agent.id)"
      >
        <template #title>
          <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem">
            <span v-if="agent.emoji" style="font-size: 1.3rem; line-height: 1">{{ agent.emoji }}</span>
            <i v-else class="pi pi-box" />
            {{ agent.name }}
          </div>
        </template>
        <template #subtitle>
          <span>{{ agent.slug }}</span>
          <span
            v-if="!agent.isOwner && agent.ownerName"
            style="color: var(--p-text-muted-color)"
          >
            · <i class="pi pi-user" style="font-size: 0.7rem" /> {{ agent.ownerName }}
          </span>
        </template>
        <template #content>
          <Tag
            :value="useAgentStatus(agent.status, agent.running).label"
            :severity="useAgentStatus(agent.status, agent.running).severity"
            style="margin-bottom: 0.5rem"
          />
          <Message v-if="agent.errorMessage" severity="error" :closable="false" style="margin-top: 0.5rem; font-size: 0.8rem">
            <div style="max-height: 3.6em; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; word-break: break-word">
              {{ agent.errorMessage }}
            </div>
          </Message>
          <p v-if="agent.description" style="font-size: 0.875rem; color: var(--p-text-muted-color); margin-top: 0.5rem">
            {{ agent.description }}
          </p>
        </template>
      </Card>
    </div>

    <div
      v-if="canGovern"
      style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--p-content-border-color)"
    >
      <router-link
        to="/settings/agents"
        style="color: var(--p-text-muted-color); font-size: 0.875rem; text-decoration: none; display: inline-flex; align-items: center; gap: 0.4rem"
      >
        <i class="pi pi-th-large" style="font-size: 0.8rem" />
        Manage all agents in this workspace
        <i class="pi pi-arrow-right" style="font-size: 0.7rem" />
      </router-link>
    </div>
  </div>
</template>
