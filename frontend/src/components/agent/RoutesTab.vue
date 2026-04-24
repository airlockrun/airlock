<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'

interface Route {
  path: string
  method: string
  access: string
  description: string
}

const props = defineProps<{ agentId: string; agentSlug?: string; agentDomain?: string }>()

const routes = ref<Route[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}`)
    const response = fromJson(GetAgentDetailResponseSchema, data)
    routes.value = (response.routes || []).map(r => ({
      path: r.path,
      method: r.method,
      access: r.access,
      description: r.description,
    }))
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="routes" stripedRows>
      <Column field="method" header="Method" style="width: 5rem" />
      <Column field="path" header="Path" />
      <Column field="description" header="Description" />
      <Column field="access" header="Access" style="width: 6rem" />
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column header="Method"><template #body><Skeleton width="3rem" /></template></Column>
      <Column header="Path"><template #body><Skeleton /></template></Column>
      <Column header="Description"><template #body><Skeleton /></template></Column>
      <Column header="Access"><template #body><Skeleton width="4rem" /></template></Column>
    </DataTable>
  </div>
</template>
