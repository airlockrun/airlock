<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useUsageStore } from '@/stores/usage'
import { useAirlockI18n } from '@/i18n'

const usage = useUsageStore()
const { t, formatNumber } = useAirlockI18n()
const days = ref(30)
const periods = computed(() => [
  { label: t('administration.usage.days', { count: 7, formattedCount: formatNumber(7) }), value: 7 },
  { label: t('administration.usage.days', { count: 30, formattedCount: formatNumber(30) }), value: 30 },
  { label: t('administration.usage.days', { count: 90, formattedCount: formatNumber(90) }), value: 90 },
  { label: t('administration.usage.allTime'), value: 0 },
])

onMounted(() => usage.fetchUsage(days.value))
watch(days, (d) => usage.fetchUsage(d))

function num(v: bigint | number): string {
  return formatNumber(v)
}
function cost(v: number): string {
  const digits = v < 1 ? 4 : 2
  return formatNumber(v, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
}

const summary = computed(() => usage.report?.summary)
const byAgent = computed(() => usage.report?.byAgent ?? [])
const byModel = computed(() => usage.report?.byModel ?? [])
const byUser = computed(() => usage.report?.byUser ?? [])
</script>

<template>
  <div>
    <h1 style="margin: 0; font-size: 1.5rem">{{ t('administration.usage.title') }}</h1>
    <p style="margin: 0 0 1.5rem; color: var(--p-text-muted-color); max-width: 48rem">
      {{ t('administration.usage.description') }}
    </p>

    <!-- Period selector -->
    <div style="margin-bottom: 1rem">
      <SelectButton v-model="days" :options="periods" optionLabel="label" optionValue="value" :allowEmpty="false" />
    </div>

    <!-- Summary cards -->
    <div class="stat-row">
      <Card class="stat">
        <template #content>
          <div class="stat-label">{{ t('administration.usage.totalCost') }}</div>
          <div class="stat-value">{{ cost(summary?.costTotal ?? 0) }}</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">{{ t('administration.usage.calls') }}</div>
          <div class="stat-value">{{ num(summary?.calls ?? 0) }}</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">{{ t('administration.usage.tokensIn') }}</div>
          <div class="stat-value">{{ num(summary?.tokensIn ?? 0) }}</div>
          <div class="stat-sub">{{ t('administration.usage.cachedCount', { count: summary?.tokensCached ?? 0, formattedCount: num(summary?.tokensCached ?? 0) }) }}</div>
        </template>
      </Card>
      <Card class="stat">
        <template #content>
          <div class="stat-label">{{ t('administration.usage.tokensOut') }}</div>
          <div class="stat-value">{{ num(summary?.tokensOut ?? 0) }}</div>
        </template>
      </Card>
    </div>

    <!-- By agent -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>{{ t('administration.usage.byApp') }}</template>
      <template #content>
        <DataTable :value="byAgent" :loading="usage.loading" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">{{ t('administration.usage.empty') }}</div>
          </template>
          <Column :header="t('administration.usage.app')">
            <template #body="{ data }">
              <div style="display: flex; align-items: center; gap: 0.4rem">
                <span style="font-weight: 500">{{ data.agentName }}</span>
                <Tag v-if="data.deleted" :value="t('administration.usage.deleted')" severity="secondary" style="font-size: 0.65rem" />
              </div>
              <span style="font-size: 0.72rem; color: var(--p-text-muted-color)">{{ data.agentSlug }}</span>
            </template>
          </Column>
          <Column :header="t('administration.usage.owner')">
            <template #body="{ data }">
              <span v-if="data.ownerEmail">{{ data.ownerName || data.ownerEmail }}</span>
              <span v-else style="color: var(--p-text-muted-color)">-</span>
              <span v-if="data.ownerName && data.ownerEmail" style="display: block; font-size: 0.72rem; color: var(--p-text-muted-color)">{{ data.ownerEmail }}</span>
            </template>
          </Column>
          <Column :header="t('administration.usage.calls')"><template #body="{ data }">{{ num(data.calls) }}</template></Column>
          <Column :header="t('administration.usage.tokensIn')"><template #body="{ data }">{{ num(data.tokensIn) }}</template></Column>
          <Column :header="t('administration.usage.cached')"><template #body="{ data }">{{ num(data.tokensCached) }}</template></Column>
          <Column :header="t('administration.usage.tokensOut')"><template #body="{ data }">{{ num(data.tokensOut) }}</template></Column>
          <Column :header="t('administration.usage.cost')"><template #body="{ data }">{{ cost(data.costTotal) }}</template></Column>
        </DataTable>
      </template>
    </Card>

    <!-- By user -->
    <Card style="margin-bottom: 1.5rem">
      <template #title>{{ t('administration.usage.byUser') }}</template>
      <template #content>
        <DataTable :value="byUser" :loading="usage.loading" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">{{ t('administration.usage.empty') }}</div>
          </template>
          <Column :header="t('administration.usage.user')">
            <template #body="{ data }">
              <div style="display: flex; align-items: center; gap: 0.4rem">
                <span style="font-weight: 500">{{ data.userEmail }}</span>
                <Tag v-if="data.deleted" :value="t('administration.usage.deleted')" severity="secondary" style="font-size: 0.65rem" />
                <Tag v-else-if="!data.userEmail.includes('@')" :value="t('administration.usage.system')" severity="info" style="font-size: 0.65rem" />
              </div>
            </template>
          </Column>
          <Column :header="t('administration.usage.calls')"><template #body="{ data }">{{ num(data.calls) }}</template></Column>
          <Column :header="t('administration.usage.tokensIn')"><template #body="{ data }">{{ num(data.tokensIn) }}</template></Column>
          <Column :header="t('administration.usage.cached')"><template #body="{ data }">{{ num(data.tokensCached) }}</template></Column>
          <Column :header="t('administration.usage.tokensOut')"><template #body="{ data }">{{ num(data.tokensOut) }}</template></Column>
          <Column :header="t('administration.usage.cost')"><template #body="{ data }">{{ cost(data.costTotal) }}</template></Column>
        </DataTable>
      </template>
    </Card>

    <!-- By model -->
    <Card>
      <template #title>{{ t('administration.usage.byModel') }}</template>
      <template #content>
        <DataTable :value="byModel" :loading="usage.loading" stripedRows size="small">
          <template #empty>
            <div style="text-align: center; padding: 1.5rem; color: var(--p-text-muted-color)">{{ t('administration.usage.empty') }}</div>
          </template>
          <Column :header="t('administration.usage.provider')">
            <template #body="{ data }">
              <span style="font-weight: 500">{{ data.providerSlug || data.providerCatalogId }}</span>
              <span v-if="data.providerSlug" style="display: block; font-size: 0.72rem; color: var(--p-text-muted-color)">{{ data.providerCatalogId }}</span>
            </template>
          </Column>
          <Column :header="t('administration.usage.model')"><template #body="{ data }">{{ data.model }}</template></Column>
          <Column :header="t('administration.usage.calls')"><template #body="{ data }">{{ num(data.calls) }}</template></Column>
          <Column :header="t('administration.usage.tokensIn')"><template #body="{ data }">{{ num(data.tokensIn) }}</template></Column>
          <Column :header="t('administration.usage.tokensOut')"><template #body="{ data }">{{ num(data.tokensOut) }}</template></Column>
          <Column :header="t('administration.usage.cost')"><template #body="{ data }">{{ cost(data.costTotal) }}</template></Column>
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
