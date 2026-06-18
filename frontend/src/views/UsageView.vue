<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useUsageStore } from '@/stores/usage'

const usage = useUsageStore()
const days = ref(30)
const periods = [
  { label: '7 days', value: 7 },
  { label: '30 days', value: 30 },
  { label: '90 days', value: 90 },
  { label: 'All time', value: 0 },
]

onMounted(() => usage.fetchUsage(days.value))
watch(days, (d) => usage.fetchUsage(d))

function num(v: bigint | number): string {
  return Number(v).toLocaleString()
}
function cost(v: number): string {
  return '$' + (v < 1 ? v.toFixed(4) : v.toFixed(2))
}

const summary = computed(() => usage.report?.summary)
const byAgent = computed(() => usage.report?.byAgent ?? [])
const byModel = computed(() => usage.report?.byModel ?? [])
</script>

<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem">
      <h1 style="margin: 0; font-size: 1.5rem">Usage</h1>
      <SelectButton v-model="days" :options="periods" optionLabel="label" optionValue="value" :allowEmpty="false" />
    </div>
    <p style="margin: 0 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem">
      LLM token spend across every agent, from the durable ledger — usage from agents that have since
      been deleted is still counted (and marked).
    </p>

    <!-- Summary cards -->
    <div class="stat-row">
      <Card class="stat">
        <template #content>
          <div class="stat-label">Total cost</div>
          <div class="stat-value">{{ cost(summary?.costTotal ?? 0) }}</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">Calls</div>
          <div class="stat-value">{{ num(summary?.calls ?? 0) }}</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">Tokens in</div>
          <div class="stat-value">{{ num(summary?.tokensIn ?? 0) }}</div>
          <div class="stat-sub">{{ num(summary?.tokensCached ?? 0) }} cached</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">Tokens out</div>
          <div class="stat-value">{{ num(summary?.tokensOut ?? 0) }}</div>
        </template>
      </Card>
    </div>

    <!-- By agent -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>By agent</template>
      <template #content>
        <DataTable :value="byAgent" :loading="usage.loading" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">No usage in this window.</div>
          </template>
          <Column header="Agent">
            <template #body="{ data }">
              <div style="display: flex; align-items: center; gap: 0.4rem">
                <span style="font-weight: 500">{{ data.agentName }}</span>
                <Tag v-if="data.deleted" value="deleted" severity="secondary" style="font-size: 0.65rem" />
              </div>
              <span style="font-size: 0.72rem; color: var(--p-text-muted-color)">{{ data.agentSlug }}</span>
            </template>
          </Column>
          <Column header="Calls"><template #body="{ data }">{{ num(data.calls) }}</template></Column>
          <Column header="Tokens in"><template #body="{ data }">{{ num(data.tokensIn) }}</template></Column>
          <Column header="Cached"><template #body="{ data }">{{ num(data.tokensCached) }}</template></Column>
          <Column header="Tokens out"><template #body="{ data }">{{ num(data.tokensOut) }}</template></Column>
          <Column header="Cost"><template #body="{ data }">{{ cost(data.costTotal) }}</template></Column>
        </DataTable>
      </template>
    </Card>

    <!-- By model -->
    <Card>
      <template #title>By model</template>
      <template #content>
        <DataTable :value="byModel" :loading="usage.loading" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">No usage in this window.</div>
          </template>
          <Column header="Provider"><template #body="{ data }">{{ data.providerCatalogId }}</template></Column>
          <Column header="Model"><template #body="{ data }">{{ data.model }}</template></Column>
          <Column header="Calls"><template #body="{ data }">{{ num(data.calls) }}</template></Column>
          <Column header="Tokens in"><template #body="{ data }">{{ num(data.tokensIn) }}</template></Column>
          <Column header="Tokens out"><template #body="{ data }">{{ num(data.tokensOut) }}</template></Column>
          <Column header="Cost"><template #body="{ data }">{{ cost(data.costTotal) }}</template></Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>

<style scoped>
.stat-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.stat {
  flex: 1 1 10rem;
}
.stat-label {
  font-size: 0.8rem;
  color: var(--p-text-muted-color);
}
.stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  margin-top: 0.25rem;
}
.stat-sub {
  font-size: 0.72rem;
  color: var(--p-text-muted-color);
  margin-top: 0.1rem;
}
</style>
