<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { useAirlockI18n } from '@/i18n'
import {
  LinkIdentityPreviewResponseSchema,
  type LinkIdentityPreviewResponse,
} from '@/gen/airlock/v1/api_pb'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const { t } = useAirlockI18n()

type Status = 'loading' | 'confirm' | 'linking' | 'success' | 'error'

const status = ref<Status>('loading')
const errorMsg = ref('')
const preview = ref<LinkIdentityPreviewResponse | null>(null)

const platformLabel = computed(() => {
  const p = preview.value?.platform
  if (!p) return t('auth.identity.external')
  return p.charAt(0).toUpperCase() + p.slice(1)
})

const query = computed(() => {
  const { platform, bridge, uid, ts, sig } = route.query
  if (!platform || !bridge || !uid || !ts || !sig) return null
  return { platform, bridge, uid, ts, sig } as Record<string, string>
})

function queryString(): string {
  const q = query.value
  if (!q) return ''
  return new URLSearchParams(q).toString()
}

onMounted(async () => {
  if (!query.value) {
    status.value = 'error'
    errorMsg.value = t('auth.identity.invalidLink')
    return
  }
  try {
    const { data } = await api.get(`/api/v1/link-identity/preview?${queryString()}`)
    preview.value = fromJson(LinkIdentityPreviewResponseSchema, data)
    status.value = 'confirm'
  } catch (err: any) {
    status.value = 'error'
    errorMsg.value = err.response?.data?.error || t('auth.identity.verifyFailed')
  }
})

async function confirmLink() {
  if (!query.value) return
  status.value = 'linking'
  try {
    await api.post(`/api/v1/link-identity?${queryString()}`)
    status.value = 'success'
    toast.add({
      severity: 'success',
      summary: t('auth.identity.linkedToast', { platform: platformLabel.value }),
      life: 5000,
    })
  } catch (err: any) {
    status.value = 'error'
    errorMsg.value = err.response?.data?.error || t('auth.identity.linkFailed')
  }
}

function cancel() {
  router.push('/agents')
}
</script>

<template>
  <div class="link-identity-wrap">
    <div class="link-identity-card">
      <template v-if="status === 'loading'">
        <i class="pi pi-spin pi-spinner" style="font-size: 2rem; margin-bottom: 1rem" />
        <p>{{ t('auth.identity.verifying') }}</p>
      </template>

      <template v-else-if="status === 'confirm' && preview">
        <i class="pi pi-link" style="font-size: 2rem; margin-bottom: 1rem; color: var(--p-primary-color)" />
        <h2 style="margin: 0 0 0.5rem 0">{{ t('auth.identity.confirmTitle', { platform: platformLabel }) }}</h2>
        <p style="color: var(--p-text-muted-color); margin: 0 0 1.5rem 0">
          {{ t('auth.identity.confirmInstructions') }}
        </p>

        <dl class="preview-list">
          <div class="preview-row">
            <dt>{{ t('auth.identity.platform') }}</dt>
            <dd>{{ platformLabel }}</dd>
          </div>
          <div class="preview-row">
            <dt>{{ t('auth.identity.bot') }}</dt>
            <dd>
              <span v-if="preview.botUsername">@{{ preview.botUsername }}</span>
              <span v-else>{{ preview.bridgeName || t('auth.identity.unknown') }}</span>
              <span v-if="preview.bridgeName && preview.botUsername" style="color: var(--p-text-muted-color)">
                · {{ preview.bridgeName }}
              </span>
            </dd>
          </div>
          <div class="preview-row">
            <dt>{{ t('auth.identity.platformUser', { platform: platformLabel }) }}</dt>
            <dd class="platform-user">
              <img
                v-if="preview.platformAvatarUrl"
                :src="preview.platformAvatarUrl"
                alt=""
                class="platform-avatar"
              />
              <div>
                <div v-if="preview.platformDisplayName">{{ preview.platformDisplayName }}</div>
                <div v-if="preview.platformUsername" style="color: var(--p-text-muted-color)">
                  @{{ preview.platformUsername }}
                </div>
                <div style="color: var(--p-text-muted-color); font-size: 0.85em">
                  {{ t('auth.identity.userId', { id: preview.platformUserId }) }}
                </div>
              </div>
            </dd>
          </div>
          <div class="preview-row">
            <dt>{{ t('auth.identity.linkingTo') }}</dt>
            <dd>{{ preview.currentUserEmail }}</dd>
          </div>
        </dl>

        <div class="actions">
          <Button :label="t('auth.action.cancel')" severity="secondary" @click="cancel" />
          <Button :label="t('auth.identity.confirmAndLink')" icon="pi pi-check" @click="confirmLink" />
        </div>
      </template>

      <template v-else-if="status === 'linking'">
        <i class="pi pi-spin pi-spinner" style="font-size: 2rem; margin-bottom: 1rem" />
        <p>{{ t('auth.identity.linking') }}</p>
      </template>

      <template v-else-if="status === 'success'">
        <i class="pi pi-check-circle" style="font-size: 2rem; color: var(--p-green-500); margin-bottom: 1rem" />
        <p>{{ t('auth.identity.success', { platform: platformLabel }) }}</p>
        <Button :label="t('auth.identity.goToApps')" style="margin-top: 1rem" @click="router.push('/agents')" />
      </template>

      <template v-else>
        <i class="pi pi-times-circle" style="font-size: 2rem; color: var(--p-red-500); margin-bottom: 1rem" />
        <p>{{ errorMsg }}</p>
        <Button :label="t('auth.identity.goToApps')" severity="secondary" style="margin-top: 1rem" @click="router.push('/agents')" />
      </template>
    </div>
  </div>
</template>

<style scoped>
.link-identity-wrap {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 60vh;
  padding: 1rem;
}
.link-identity-card {
  text-align: center;
  max-width: 28rem;
  width: 100%;
}
.preview-list {
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 0 0 1.5rem 0;
  padding: 1rem;
  border: 1px solid var(--p-surface-300);
  border-radius: 0.5rem;
  background: var(--p-surface-50);
}
:root.dark .preview-list {
  border-color: var(--p-surface-700);
  background: var(--p-surface-900);
}
.preview-row {
  display: grid;
  grid-template-columns: 8rem 1fr;
  gap: 0.75rem;
}
.preview-row dt {
  font-weight: 600;
  color: var(--p-text-muted-color);
}
.platform-user {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.platform-avatar {
  width: 3rem;
  height: 3rem;
  border-radius: 50%;
  flex-shrink: 0;
}
.preview-row dd {
  margin: 0;
  word-break: break-word;
}
.actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
</style>
