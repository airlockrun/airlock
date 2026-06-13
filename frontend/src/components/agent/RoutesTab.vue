<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'

interface Route {
  path: string
  method: string
  access: string
  description: string
}

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()

const routes = ref<Route[]>([])
watch(routes, (v) => emit('populated', v.length), { immediate: true })
const routeBaseUrl = ref('')
const loading = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get(`/api/v1/agents/${props.agentId}`)
    const response = fromJson(GetAgentDetailResponseSchema, data)
    routeBaseUrl.value = response.routeBaseUrl || ''
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

// A GET route is reachable in the browser, so link it to its external
// URL ({routeBaseUrl}{/path}). Other methods (POST/PUT/...) aren't
// navigable, so they stay plain text. Empty base → no link (defensive).
function routeHref(r: Route): string | null {
  if (r.method.toUpperCase() !== 'GET' || !routeBaseUrl.value) return null
  const path = r.path.startsWith('/') ? r.path : '/' + r.path
  return routeBaseUrl.value + path
}
</script>

<template>
  <div>
    <DataTable v-if="!loading" :value="routes" stripedRows>
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: var(--p-text-muted-color)">
          No routes registered.
        </div>
      </template>
      <Column field="method" header="Method" style="width: 5rem" />
      <Column field="path" header="Path">
        <template #body="{ data }">
          <a
            v-if="routeHref(data)"
            :href="routeHref(data)!"
            target="_blank"
            rel="noopener noreferrer"
          >{{ data.path }}</a>
          <span v-else>{{ data.path }}</span>
        </template>
      </Column>
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
