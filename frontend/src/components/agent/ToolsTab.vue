<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ListToolsResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { ToolInfo } from '@/gen/airlock/v1/types_pb'
import { useAirlockI18n } from '@/i18n'

const props = defineProps<{ agentId: string }>()
const emit = defineEmits<{ populated: [count: number] }>()
const { t } = useAirlockI18n()

const tools = ref<ToolInfo[]>([])
watch(tools, (v) => emit('populated', v.length), { immediate: true })
const loading = ref(true)

function accessSeverity(access: string): string {
  switch (access) {
    case 'admin': return 'warn'
    case 'public': return 'success'
    default: return 'info'
  }
}

function accessLabel(access: string): string {
  if (access === 'public') return t('agentConfig.accessLevel.public')
  if (access === 'user') return t('agentConfig.accessLevel.user')
  if (access === 'admin') return t('agentConfig.accessLevel.admin')
  return access
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
          {{ t('agentConfig.tools.empty') }}
        </div>
      </template>
      <Column field="name" :header="t('agentConfig.common.name')" />
      <Column field="description" :header="t('agentConfig.common.description')" />
      <Column :header="t('agentConfig.common.access')">
        <template #body="{ data: t }">
          <Tag :value="accessLabel(t.access)" :severity="accessSeverity(t.access)" />
        </template>
      </Column>
    </DataTable>

    <DataTable v-else :value="[{}, {}, {}]">
      <Column :header="t('agentConfig.common.name')"><template #body><Skeleton width="40%" /></template></Column>
      <Column :header="t('agentConfig.common.description')"><template #body><Skeleton /></template></Column>
      <Column :header="t('agentConfig.common.access')"><template #body><Skeleton width="4rem" /></template></Column>
    </DataTable>
  </div>
</template>
