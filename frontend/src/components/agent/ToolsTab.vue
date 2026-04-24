<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ListToolsResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { ToolInfo } from '@/gen/airlock/v1/types_pb'

const props = defineProps<{ agentId: string }>()

const tools = ref<ToolInfo[]>([])
const loading = ref(true)

function accessSeverity(access: string): string {
  switch (access) {
    case 'admin': return 'warn'
    case 'public': return 'success'
    default: return 'info'
  }
}

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}/tools`)
    tools.value = fromJson(ListToolsResponseSchema, data).tools
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="tools" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No tools registered.
        </div>
      </template>
      <Column field="name" header="Name" />
      <Column field="description" header="Description" />
      <Column header="Access">
        <template #body="{ data: t }">
          <Tag :value="t.access" :severity="accessSeverity(t.access)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Name"><template #body><Skeleton width="40%" /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="Access"><template #body><Skeleton width="4rem" /></template></Column>
    </DataTable>
  </div>
</template>
