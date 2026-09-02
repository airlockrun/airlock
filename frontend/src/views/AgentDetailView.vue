<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { ws } from '@/api/ws'
import { useCatalogStore } from '@/stores/catalog'
import { useAgentsStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { useUsersStore } from '@/stores/users'
import { useAgentStatus } from '@/composables/useAgentStatus'
import type { AgentInfo, SetupCountsInfo } from '@/gen/airlock/v1/types_pb'
import { ConnectionSetupStatusResponseSchema, GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import ConnectionsTab from '@/components/agent/ConnectionsTab.vue'
import WebhooksTab from '@/components/agent/WebhooksTab.vue'
import SchedulesTab from '@/components/agent/SchedulesTab.vue'
import RoutesTab from '@/components/agent/RoutesTab.vue'
import MCPServersTab from '@/components/agent/MCPServersTab.vue'
import ConnectorsTab from '@/components/agent/ConnectorsTab.vue'
import EnvVarsTab from '@/components/agent/EnvVarsTab.vue'
import ToolsTab from '@/components/agent/ToolsTab.vue'
import MembersTab from '@/components/agent/MembersTab.vue'
import SiblingsTab from '@/components/agent/SiblingsTab.vue'
import AccessTab from '@/components/agent/AccessTab.vue'
import ModelsTab from '@/components/agent/ModelsTab.vue'
import RunsTab from '@/components/agent/RunsTab.vue'
import BuildsTab from '@/components/agent/BuildsTab.vue'
import JobsTab from '@/components/agent/JobsTab.vue'
import SourceTab from '@/components/agent/SourceTab.vue'
import SectionCard from '@/components/agent/SectionCard.vue'
import { useBuildsStore } from '@/stores/builds'
import { buildBadgeText } from '@/utils/buildBadge'
import { applyAgentBuildEvent } from '@/utils/agentBuildLifecycle'
import { markRaw } from 'vue'
import { oauthCallbackNotice, setupSummary } from '@/utils/resources'
import { useAirlockI18n } from '@/i18n'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()
const i18n = useAirlockI18n()
const { t, formatNumber } = i18n
const agentStatus = useAgentStatus()

const catalog = useCatalogStore()
const buildsStore = useBuildsStore()
const agentsStore = useAgentsStore()
const auth = useAuthStore()
const usersStore = useUsersStore()

// --- Rename (name + slug) ---
const renameOpen = ref(false)
const renameName = ref('')
const renameSlug = ref('')
const renaming = ref(false)
const slugChanged = computed(
  () => !!agent.value && renameSlug.value.trim() !== agent.value.slug,
)

function openRename() {
  if (!agent.value) return
  renameName.value = agent.value.name
  renameSlug.value = agent.value.slug
  renameOpen.value = true
}

async function saveRename() {
  if (!agent.value) return
  const name = renameName.value.trim()
  const slug = renameSlug.value.trim()
  if (!name) {
    toast.add({ severity: 'warn', summary: t('agents.detail.nameRequired'), life: 3000 })
    return
  }
  if (slug.length < 2 || slug.length > 63 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    toast.add({
      severity: 'warn',
      summary: t('agents.detail.invalidSlug'),
      detail: t('agents.detail.invalidSlugDetailRename'),
      life: 4000,
    })
    return
  }
  renaming.value = true
  try {
    const updated = await agentsStore.renameAgent(agent.value.id, name, slug)
    agent.value = updated
    renameOpen.value = false
    toast.add({ severity: 'success', summary: t('agents.detail.renamed'), life: 2500 })
    // Repaint the address bar to the new slug (same cosmetic mechanism
    // as the router's vanity-URL afterEach; route.params.id stays UUID).
    const parts = window.location.pathname.split('/')
    if (parts[1] === 'agents' && parts[2]) {
      parts[2] = updated.slug
      history.replaceState(
        history.state,
        '',
        parts.join('/') + window.location.search + window.location.hash,
      )
    }
  } catch (e: any) {
    const status = e?.response?.status
    toast.add({
      severity: 'error',
      summary: status === 409 ? t('agents.detail.slugTaken') : t('agents.detail.renameFailed'),
      detail: e?.response?.data?.error,
      life: 5000,
    })
  } finally {
    renaming.value = false
  }
}

// --- Clone (fork this agent's code into a new agent I own) ---
// Visible to managers who are members of this agent; the server also enforces
// it. Copies code + authored config only — no data, secrets, or bindings.
const canClone = computed(() => auth.can('tenant.agent.clone'))
const cloneOpen = ref(false)
const cloneName = ref('')
const cloneSlug = ref('')
const cloning = ref(false)

function openClone() {
  if (!agent.value) return
  cloneName.value = t('agents.detail.copyName', { name: agent.value.name })
  cloneSlug.value = `${agent.value.slug}-copy`
  cloneOpen.value = true
}

async function saveClone() {
  if (!agent.value) return
  const name = cloneName.value.trim()
  const slug = cloneSlug.value.trim()
  if (!name) {
    toast.add({ severity: 'warn', summary: t('agents.detail.nameRequired'), life: 3000 })
    return
  }
  if (slug.length < 2 || slug.length > 63 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    toast.add({ severity: 'warn', summary: t('agents.detail.invalidSlug'), detail: t('agents.detail.invalidSlugDetailClone'), life: 4000 })
    return
  }
  cloning.value = true
  try {
    const clone = await agentsStore.cloneAgent(agent.value.id, name, slug)
    cloneOpen.value = false
    toast.add({ severity: 'success', summary: t('agents.detail.cloned'), detail: t('agents.detail.buildingCopy'), life: 3000 })
    router.push(`/agents/${clone.slug}`)
  } catch (e: any) {
    const status = e?.response?.status
    toast.add({ severity: 'error', summary: status === 409 ? t('agents.detail.slugTaken') : t('agents.detail.cloneFailed'), detail: e?.response?.data?.error, life: 5000 })
  } finally {
    cloning.value = false
  }
}

// --- Transfer ownership ---
// Owner (or tenant admin) only. Hands the agent to another tenant user; the
// current owner loses access and all owner-scoped bindings are unbound.
const canTransfer = computed(() => !!agent.value?.isOwner || auth.can('tenant.agent.transfer_any'))
const transferOpen = ref(false)
const transferTarget = ref('')
const transferring = ref(false)
const transferUsers = computed(() =>
  usersStore.selectable.filter((u) => u.kind !== 'group').map((u) => ({
    id: u.id,
    label: u.displayName ? `${u.displayName} (${u.email})` : u.email,
  })),
)

function openTransfer() {
  transferTarget.value = ''
  usersStore.fetchSelectable()
  transferOpen.value = true
}

function saveTransfer() {
  if (!agent.value || !transferTarget.value) {
    toast.add({ severity: 'warn', summary: t('agents.detail.pickTransferUser'), life: 3000 })
    return
  }
  const target = transferUsers.value.find((u) => u.id === transferTarget.value)
  confirm.require({
    message: t('agents.detail.transferConfirm', {
      name: agent.value.name,
      user: target?.label ?? t('agents.detail.thisUser'),
    }),
    header: t('agents.detail.transferOwnership'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      if (!agent.value) return
      transferring.value = true
      try {
        await agentsStore.transferOwnership(agent.value.id, transferTarget.value)
        transferOpen.value = false
        toast.add({ severity: 'success', summary: t('agents.detail.ownershipTransferred'), life: 3000 })
        router.push('/agents')
      } catch (e: any) {
        toast.add({ severity: 'error', summary: t('agents.detail.transferFailed'), detail: e?.response?.data?.error, life: 5000 })
      } finally {
        transferring.value = false
      }
    },
  })
}

const agentId = route.params.id as string
const agent = ref<AgentInfo | null>(null)
const isReadOnlyGit = computed(() => agent.value?.gitMode === 'read_only')
const loading = ref(true)
const activeBuildId = ref<string | undefined>(undefined)
// External URL of the agent's web homepage (GET "/"), or null when it has none.
const webUrl = ref<string | null>(null)
const buildTasksDone = ref(0)
const buildTasksTotal = ref(0)
const buildPhase = ref('')
const buildBadgeLabel = computed(() => buildBadgeText(buildPhase.value, buildTasksDone.value, buildTasksTotal.value, t))

// Per-section item counts emitted by each *Tab component via @populated.
// Sections (and their right-rail entries) only render when count > 0, so the
// page shows just what's actually relevant to this agent. Activity below is
// driven by the runs + builds + jobs counts together.
const counts = ref<Record<string, number>>({})
function onPopulated(id: string, n: number) {
  counts.value[id] = n
}

// Inner tab inside the Activity section: 0 = Runs, 1 = Builds, 2 = Jobs.
const activityTab = ref(0)

// Active section in the scroll viewport — drives the highlight in the
// right-rail jump nav. Set by an IntersectionObserver in onMounted.
const activeSectionId = ref<string>('')

// The sticky section nav; horizontally scrollable on narrow viewports.
const navRef = ref<HTMLElement | null>(null)
const mainRef = ref<HTMLElement | null>(null)

// Keep the highlighted tab visible as scrollspy moves it: on mobile the nav
// is horizontally truncated and the active tab can sit off-screen, so center
// it in the nav. Only adjusts the nav's own horizontal scroll — never the
// page's vertical position.
watch(activeSectionId, (id) => {
  if (!id) return
  if (hashTargetID() && !hashScrollInProgress) history.replaceState(null, '', `#${encodeURIComponent(id)}`)
  nextTick(() => {
    const nav = navRef.value
    if (!nav) return
    const link = nav.querySelector(`a[href="#${id}"]`) as HTMLElement | null
    if (!link) return
    const navRect = nav.getBoundingClientRect()
    const linkRect = link.getBoundingClientRect()
    const delta = linkRect.left + linkRect.width / 2 - (navRect.left + navRect.width / 2)
    nav.scrollTo({ left: nav.scrollLeft + delta, behavior: 'smooth' })
  })
})

// Configuration sections rendered inline inside the Configure tab, in the
// order users typically walk through them: integrations → triggers →
// sharing → source → registered surfaces. needsSetupKey ties a section to the
// field on setupStatus that flags an unconfigured slot (see badgeFor below).
// markRaw skips deep reactivity on the component refs — they're constants.
const configSections = computed(() => [
  { id: 'members',        label: t('agents.detail.section.members'),        component: markRaw(MembersTab) },
  { id: 'connections',    label: t('agents.detail.section.connections'),    component: markRaw(ConnectionsTab),   needsSetupKey: 'connections' as const },
  { id: 'mcp-servers',    label: t('agents.detail.section.mcpServers'),    component: markRaw(MCPServersTab),    needsSetupKey: 'mcpServers' as const },
  { id: 'connectors',     label: t('agents.detail.section.connectors'),     component: markRaw(ConnectorsTab),     needsSetupKey: 'connectors' as const },
  { id: 'env-vars',       label: t('agents.detail.section.environment'),    component: markRaw(EnvVarsTab),       needsSetupKey: 'envVars' as const },
  { id: 'webhooks',       label: t('agents.detail.section.webhooks'),       component: markRaw(WebhooksTab) },
  { id: 'schedules',      label: t('agents.detail.section.schedules'),      component: markRaw(SchedulesTab) },
  { id: 'siblings',       label: t('agents.detail.section.siblings'),       component: markRaw(SiblingsTab), alwaysShow: true },
  { id: 'access',         label: t('agents.detail.section.access'),         component: markRaw(AccessTab), alwaysShow: true },
  { id: 'source',         label: t('agents.detail.section.source'),         component: markRaw(SourceTab), alwaysShow: true, adminOnly: true },
  { id: 'routes',         label: t('agents.detail.section.routes'),         component: markRaw(RoutesTab) },
  { id: 'tools',          label: t('agents.detail.section.tools'),          component: markRaw(ToolsTab) },
  { id: 'models',         label: t('agents.detail.section.models'),         component: markRaw(ModelsTab) },
] as const)
type ConfigSection = (typeof configSections.value)[number]

// Activity (Runs + Builds + Jobs) renders as the final section, but uses the same
// counts machinery — visible when at least one of its inner lists has items.
// Activity is admin-only: the lists span every user's runs, the agent's build
// history, and operator job payloads, which non-admin members shouldn't see.
const activityVisible = computed(() => isAgentAdmin.value && (
  (counts.value.runs ?? 0) > 0 ||
  (counts.value.builds ?? 0) > 0 ||
  (counts.value.jobs ?? 0) > 0
))

// Right-rail entries — only sections with content. Hides empty-but-mounted
// sections from the rail (which itself still mounts so it can emit a count).
// Sections marked alwaysShow stay visible even at count 0 (e.g. Siblings,
// where the "add your first sibling" affordance is a meaningful entry point).
// adminOnly sections (Source: its only action, connect, is agent-admin) are
// hidden entirely from non-admins rather than showing an action that 403s.
const isAgentAdmin = computed(() => agent.value?.yourAccess === 'admin')
const visibleSections = computed(() =>
  configSections.value.filter((s) => {
    if ((s as any).adminOnly && !isAgentAdmin.value) return false
    return (s as any).alwaysShow || (counts.value[s.id] ?? 0) > 0
  }),
)

// badgeFor surfaces the existing setup-status counts on the three sections
// the backend tracks. Returns undefined when the section is not tracked or
// has zero unconfigured items. Visible both on the section header (warn tag)
// and in the jump rail (right-aligned mini-tag).
function badgeFor(section: ConfigSection): string | undefined {
  const s = setupStatus.value
  if (!s || !('needsSetupKey' in section)) return undefined
  const key = (section as { needsSetupKey?: keyof SetupCountsInfo }).needsSetupKey
  if (!key) return undefined
  const n = s[key]
  if (typeof n !== 'number' || n <= 0) return undefined
  return t('agents.detail.needsSetupCount', { count: n, formattedCount: formatNumber(n) })
}

// Bumped on every event that should refresh the data tabs (build
// terminal, agent sync). Used as a `:key` on the TabPanels container
// so each tab unmounts/remounts and re-runs its onMounted fetch —
// avoids wiring a WS subscription into every tab component.
const tabsKey = ref(0)

const actionItems = computed(() => {
  const items = []
  // Three-state lifecycle:
  //   Running   = status=active + running → offer Suspend + Stop
  //   Suspended = status=active + !running → offer Start (kicks container)
  //                                          + Stop (parks it)
  //   Stopped   = status=stopped → offer Start (resumes)
  // 'failed' agents still offer Start in case the operator wants to
  // try the existing image; status flips to active on success.
  if (isAgentAdmin.value) {
    const status = agent.value?.status ?? ''
    const running = !!agent.value?.running
    if (status === 'active') {
      if (running) {
        items.push({ label: t('agents.action.suspend'), icon: 'pi pi-pause', command: () => doSuspend() })
        items.push({ label: t('agents.action.stop'), icon: 'pi pi-stop', command: () => confirmStop() })
      } else {
        items.push({ label: t('agents.action.start'), icon: 'pi pi-play', command: () => doStart() })
        items.push({ label: t('agents.action.stop'), icon: 'pi pi-stop', command: () => confirmStop() })
      }
    } else if (status === 'stopped' || status === 'failed') {
      items.push({ label: t('agents.action.start'), icon: 'pi pi-play', command: () => doStart() })
    }
    items.push({
      label: isReadOnlyGit.value ? t('agents.action.rebuild') : t('agents.action.upgrade'),
      icon: isReadOnlyGit.value ? 'pi pi-refresh' : 'pi pi-arrow-up',
      command: () => doUpgrade(),
    })
  }
  if (canClone.value) {
    items.push({ label: t('agents.action.clone'), icon: 'pi pi-copy', command: () => openClone() })
  }
  if (canTransfer.value) {
    items.push({ label: t('agents.detail.transferOwnership'), icon: 'pi pi-user-edit', command: () => openTransfer() })
  }
  if (isAgentAdmin.value) {
    items.push({ label: t('agents.action.delete'), icon: 'pi pi-trash', command: () => confirmDelete() })
  }
  return items
})

const statusTooltip = computed(() => {
  const status = agent.value?.status ?? ''
  const running = !!agent.value?.running
  if (status === 'active' && running) return t('agents.detail.statusTooltip.running')
  if (status === 'active' && !running) return t('agents.detail.statusTooltip.suspended')
  if (status === 'stopped') return t('agents.detail.statusTooltip.stopped')
  return ''
})

const setupStatus = ref<SetupCountsInfo | null>(null)

async function loadSetupStatus() {
  try {
    const { data } = await api.get(`/api/v1/agents/${agentId}/setup-status`)
    setupStatus.value = fromJson(ConnectionSetupStatusResponseSchema, data).counts ?? null
  } catch {
    // Non-fatal — header just won't show the badge.
    setupStatus.value = null
  }
}

function handleOAuthCallback() {
  const status = typeof route.query.oauth_status === 'string' ? route.query.oauth_status : ''
  if (!status) return
  const message = typeof route.query.message === 'string' ? route.query.message : ''
  const resourceID = typeof route.query.resource_id === 'string' ? route.query.resource_id : ''
  const notice = oauthCallbackNotice(status, message, resourceID, i18n)
  toast.add({
    severity: notice.severity,
    summary: notice.summary,
    detail: notice.detail,
    life: notice.severity === 'success' ? 4500 : 8000,
  })

  const url = new URL(window.location.href)
  url.searchParams.delete('oauth_status')
  url.searchParams.delete('message')
  url.searchParams.delete('resource_id')
  history.replaceState(history.state, '', url.pathname + url.search + url.hash)
  tabsKey.value++
  void loadSetupStatus()
}

function onResourceMutation(gitMode?: string) {
  if (gitMode !== undefined && agent.value) agent.value.gitMode = gitMode
  tabsKey.value++
  void loadSetupStatus()
}

// Refresh setup status when the page regains visibility because resource setup
// may change while this tab is hidden.
function onVisibilityChange() {
  if (document.visibilityState === 'visible') loadSetupStatus()
}

// Scrollspy: highlight the section currently dominant in the viewport. The
// rootMargin tilts the "active" band toward the top quarter of the viewport,
// so the highlight tracks the section the user is reading rather than the
// one that's just scrolled into view at the bottom.
let scrollObserver: IntersectionObserver | null = null
let hashLayoutObserver: ResizeObserver | null = null
let hashScrollTimer: number | null = null
let hashScrollSettleTimer: number | null = null
let hashScrollAttempts = 0
let hashScrollInProgress = false

function setupScrollSpy() {
  scrollObserver?.disconnect()
  scrollObserver = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .map((e) => e.target as HTMLElement)
        .sort((a, b) => a.offsetTop - b.offsetTop)
      if (visible.length > 0) activeSectionId.value = visible[0].id
    },
    { rootMargin: '-15% 0px -70% 0px', threshold: 0 },
  )
  const ids = [...configSections.value.map((s) => s.id), 'activity']
  for (const id of ids) {
    const el = document.getElementById(id)
    if (el) scrollObserver.observe(el)
  }
}

function hashTargetID(): string {
  const hash = window.location.hash || route.hash
  if (!hash.startsWith('#')) return ''
  try {
    return decodeURIComponent(hash.slice(1))
  } catch {
    return hash.slice(1)
  }
}

function clearHashScrollTimer() {
  if (hashScrollTimer !== null) {
    window.clearTimeout(hashScrollTimer)
    hashScrollTimer = null
  }
}

function clearHashScrollSettleTimer() {
  if (hashScrollSettleTimer !== null) {
    window.clearTimeout(hashScrollSettleTimer)
    hashScrollSettleTimer = null
  }
}

function settleHashScroll() {
  clearHashScrollSettleTimer()
  hashScrollSettleTimer = window.setTimeout(() => {
    hashScrollSettleTimer = null
    hashScrollInProgress = false
  }, 300)
}

function setupHashLayoutObserver() {
  hashLayoutObserver?.disconnect()
  hashLayoutObserver = new ResizeObserver(() => {
    if (hashTargetID()) scheduleHashScroll()
  })
  if (mainRef.value) hashLayoutObserver.observe(mainRef.value)
}

function targetIsVisible(el: HTMLElement): boolean {
  return el.getClientRects().length > 0
}

function tryScrollToHash() {
  const id = hashTargetID()
  if (!id) {
    clearHashScrollSettleTimer()
    hashScrollInProgress = false
    return
  }
  const el = document.getElementById(id)
  if (el && targetIsVisible(el)) {
    clearHashScrollTimer()
    el.scrollIntoView({ behavior: 'auto', block: 'start' })
    activeSectionId.value = id
    settleHashScroll()
    return
  }
  if (hashScrollAttempts >= 40) {
    hashScrollInProgress = false
    return
  }
  hashScrollAttempts++
  clearHashScrollTimer()
  hashScrollTimer = window.setTimeout(() => {
    void nextTick(() => window.requestAnimationFrame(tryScrollToHash))
  }, 100)
}

function scheduleHashScroll(resetAttempts = false) {
  if (!hashTargetID()) return
  if (resetAttempts) hashScrollAttempts = 0
  clearHashScrollSettleTimer()
  hashScrollInProgress = true
  void nextTick(() => window.requestAnimationFrame(tryScrollToHash))
}

// Smooth-scroll on rail click; the URL still gets the hash (so middle-click
// / copy-link still produces a permalink), but we suppress the default
// hash-jump so the scroll is animated.
function scrollToSection(id: string, e: Event) {
  e.preventDefault()
  const el = document.getElementById(id)
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    activeSectionId.value = id
    history.replaceState(null, '', `#${id}`)
  }
}

const setupTotal = computed(() => {
  return setupSummary(setupStatus.value, i18n).total
})

const setupTooltip = computed(() => {
  return setupSummary(setupStatus.value, i18n).tooltip
})

let unsubBuild: (() => void) | null = null
let unsubSynced: (() => void) | null = null

onMounted(async () => {
  document.addEventListener('visibilitychange', onVisibilityChange)
  // Scrollspy needs the section <section> elements in the DOM; wait one
  // microtask after agent load so v-for has emitted them.
  setTimeout(setupScrollSpy, 0)
  try {
    const { data } = await api.get(`/api/v1/agents/${agentId}`)
    const resp = fromJson(GetAgentDetailResponseSchema, data)
    agent.value = resp.agent ?? null
    // Surface a "Web" button only when the agent serves a browser-reachable
    // homepage — a GET route at "/". External URL is routeBaseUrl + "/".
    const base = resp.routeBaseUrl || ''
    const hasHome = (resp.routes || []).some(
      (r) => r.method.toUpperCase() === 'GET' && (r.path === '/' || r.path === ''),
    )
    webUrl.value = base && hasHome ? base + '/' : null
  } catch {
    toast.add({ severity: 'error', summary: t('agents.detail.notFound'), life: 3000 })
    router.push('/agents')
    return
  } finally {
    loading.value = false
  }
  await nextTick()
  setupHashLayoutObserver()
  scheduleHashScroll(true)
  catalog.fetchConfiguredModels()
  loadSetupStatus()
  handleOAuthCallback()

  // If a build is currently in progress, grab its id so the build badge can
  // link to the dedicated Build page.
  if (agent.value?.status === 'building' || agent.value?.upgradeStatus === 'building') {
    try {
      await buildsStore.fetchBuilds(agentId)
      const inProgress = buildsStore.builds.find((b) => b.status === 'building')
      if (inProgress) activeBuildId.value = inProgress.id
    } catch { /* ignore */ }
  }

  // WS subscriptions are server-driven (agent_members) — no client subscribe call.
  unsubBuild = ws.onMessage('agent.build', (payload: any) => {
    if (payload?.agentId !== agentId) return
    if (payload.buildId) activeBuildId.value = payload.buildId
    buildTasksDone.value = payload.tasksDone ?? 0
    buildTasksTotal.value = payload.tasksTotal ?? 0
    buildPhase.value = payload.phase ?? ''
    if (agent.value) applyAgentBuildEvent(agent.value, payload)
    if (payload.status === 'started') {
      // New build kicked off while we were watching; buildId already captured
      // above. The reconciled state makes the badge appear immediately.
      return
    }
    if (payload.status === 'complete') {
      toast.add({ severity: 'success', summary: t('agents.detail.buildComplete'), life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'failed') {
      toast.add({ severity: 'error', summary: payload.error || t('agents.detail.buildFailed'), life: 10000 })
      tabsKey.value++
    } else if (payload.status === 'cancelled') {
      toast.add({ severity: 'warn', summary: t('agents.detail.buildCancelled'), life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'refused') {
      toast.add({
        severity: 'warn',
        summary: t('agents.detail.requestDeclined'),
        detail: payload.error || t('agents.detail.outsideBuilderScope'),
        life: 8000,
      })
      tabsKey.value++
    }
  })

  // Agent finished a sync (initial boot after build, restart, upgrade) —
  // its declared surface (tools, webhooks, schedules, routes, MCP, connections,
  // model slots) just changed. Bump tabsKey so each tab remounts and
  // refetches; saves wiring a WS listener into every tab component.
  unsubSynced = ws.onMessage('agent.synced', (payload: any) => {
    if (payload?.agentId !== agentId) return
    tabsKey.value++
    loadSetupStatus()
    toast.add({
      severity: 'success',
      summary: t('agents.detail.synced'),
      detail: t('agents.detail.appSynced', { name: agent.value?.slug ?? t('agents.detail.appFallback') }),
      life: 2500,
    })
  })
})

onUnmounted(() => {
  unsubBuild?.()
  unsubSynced?.()
  scrollObserver?.disconnect()
  hashLayoutObserver?.disconnect()
  clearHashScrollTimer()
  clearHashScrollSettleTimer()
  document.removeEventListener('visibilitychange', onVisibilityChange)
})

// Re-observe sections when their v-show flips (counts change can reveal a
// previously hidden section). Watching visibleSections in a nextTick-safe
// way keeps the rail's active-section highlight working as the page fills in.
watch([visibleSections, activityVisible, tabsKey], () => {
  setTimeout(() => {
    setupScrollSpy()
    setupHashLayoutObserver()
  }, 0)
  scheduleHashScroll()
})

watch(() => route.hash, () => scheduleHashScroll(true))

function confirmStop() {
  confirm.require({
    message: t('agents.detail.stopConfirm', { name: agent.value?.name ?? '' }),
    header: t('agents.detail.stopTitle'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${agentId}/stop`, {})
        if (agent.value) {
          agent.value.status = 'stopped'
          agent.value.running = false
        }
        toast.add({ severity: 'success', summary: t('agents.detail.stopped'), life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.detail.stopFailed'), life: 5000 })
      }
    },
  })
}

async function doSuspend() {
  try {
    await api.post(`/api/v1/agents/${agentId}/suspend`, {})
    if (agent.value) agent.value.running = false
    toast.add({
      severity: 'info',
      summary: t('agents.detail.suspended'),
      detail: t('agents.detail.suspendedDetail'),
      life: 3000,
    })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.detail.suspendFailed'), life: 5000 })
  }
}

async function doStart() {
  try {
    await api.post(`/api/v1/agents/${agentId}/start`, {})
    if (agent.value) agent.value.status = 'active'
    toast.add({ severity: 'success', summary: t('agents.detail.started'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.detail.startFailed'), life: 5000 })
  }
}

function confirmDelete() {
  confirm.require({
    message: t('agents.detail.deleteConfirm', { name: agent.value?.name ?? '' }),
    header: t('agents.detail.deleteTitle'),
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${agentId}`)
        toast.add({ severity: 'success', summary: t('agents.detail.deleted'), life: 3000 })
        router.push('/agents')
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.detail.deleteFailed'), life: 5000 })
      }
    },
  })
}

const showUpgradeDialog = ref(false)
const upgradeDescription = ref('')
// Empty description = bare rebuild (re-image current source against the
// latest agentsdk, no code changes). Any text = a codegen upgrade.
const rebuildMode = computed(() => isReadOnlyGit.value || upgradeDescription.value.trim() === '')

function doUpgrade() {
  upgradeDescription.value = ''
  showUpgradeDialog.value = true
}

async function submitUpgrade() {
  showUpgradeDialog.value = false
  try {
    const wasRebuild = rebuildMode.value
    await api.post(`/api/v1/agents/${agentId}/upgrade`, {
      description: isReadOnlyGit.value ? '' : upgradeDescription.value,
    })
    if (agent.value) agent.value.upgradeStatus = 'queued'
    toast.add({ severity: 'info', summary: wasRebuild ? t('agents.detail.rebuildQueued') : t('agents.detail.upgradeQueued'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || (isReadOnlyGit.value ? t('agents.detail.rebuildFailed') : t('agents.detail.upgradeFailed')), life: 5000 })
  }
}

async function cancelBuild() {
  try {
    await api.post(`/api/v1/agents/${agentId}/builds/cancel`)
    toast.add({ severity: 'info', summary: t('agents.detail.buildCancelled'), life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || t('agents.detail.cancelFailed'), life: 5000 })
  }
}

function goToChat() {
  router.push(`/agents/${agentId}/chat`)
}

function openWeb() {
  if (webUrl.value) window.open(webUrl.value, '_blank', 'noopener')
}

</script>

<template>
  <div v-if="loading" style="display: flex; flex-direction: column; gap: 1rem; margin-top: 1.5rem">
    <Skeleton width="40%" height="2rem" />
    <Skeleton width="20%" height="1.5rem" />
    <Skeleton width="100%" height="20rem" />
  </div>

  <div v-else-if="agent">
    <!-- Header — restore the top gap the layout's flush-top removed (that
         flush-top is for the sticky section nav below, not this header). -->
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-top: 1.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.75rem">
      <div>
        <!-- Line 1: emoji + name -->
        <h1 style="margin: 0; font-size: 1.875rem; font-weight: 700; line-height: 1.2">
          <span v-if="agent.emoji" style="margin-right: 0.4rem">{{ agent.emoji }}</span>{{ agent.name }}
        </h1>
        <!-- Line 2: slug, rename, status -->
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-top: 0.4rem; flex-wrap: wrap">
          <span style="color: var(--p-text-muted-color)">{{ agent.slug }}</span>
          <Button
            icon="pi pi-pencil"
            text
            rounded
            size="small"
            severity="secondary"
            :aria-label="t('agents.detail.renameAria')"
            v-tooltip.bottom="t('agents.action.rename')"
            @click="openRename"
          />
          <!-- Single badge that folds container state into the lifecycle:
               Running/Suspended/Stopped/Building/Error/Draft. See
               useAgentStatus for the (status, running) → label map. -->
          <Tag
            :value="agentStatus(agent.status, agent.running).label"
            :severity="agentStatus(agent.status, agent.running).severity"
            v-tooltip.bottom="statusTooltip"
          />
          <Tag
            v-if="setupTotal > 0"
            :value="t('agents.detail.needsSetupBadge', { count: setupTotal, formattedCount: formatNumber(setupTotal) })"
            severity="warn"
            v-tooltip.bottom="setupTooltip"
          />
        </div>
        <p v-if="agent.description" style="margin: 0.5rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">{{ agent.description }}</p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button :label="t('agents.detail.chat')" icon="pi pi-comments" @click="goToChat" />
        <Button v-if="webUrl" :label="t('agents.detail.web')" icon="pi pi-external-link" severity="secondary" outlined @click="openWeb" />
        <SplitButton v-if="actionItems.length" :label="t('agents.detail.actions')" :model="actionItems" severity="secondary" />
      </div>
    </div>

    <!-- Build in progress: link to the dedicated Build page (the codegen +
         docker logs, and task checklist stream there). -->
    <div
      v-if="agent.status === 'building' || agent.upgradeStatus === 'building'"
      style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem"
    >
      <RouterLink
        v-if="activeBuildId"
        :to="{ name: 'build-detail', params: { id: agentId, buildId: activeBuildId } }"
        class="build-badge"
      >
        <i class="pi pi-spin pi-spinner" />
        <span>{{ buildBadgeLabel }}</span>
        <i class="pi pi-arrow-right" style="font-size: 0.75rem" />
      </RouterLink>
      <Button :label="t('agents.detail.cancelBuild')" icon="pi pi-times" severity="danger" size="small" text @click="cancelBuild" />
    </div>

    <!-- Error message -->
    <Message v-if="agent.errorMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 20rem; overflow-y: auto">{{ agent.errorMessage }}</pre>
    </Message>

    <!-- Sticky horizontal jump nav, placed after the action buttons so it
         sits above the sections and stays visible as the user scrolls
         through them. Only populated sections appear; the section currently
         in view (per scrollspy) gets the underline. -->
    <nav ref="navRef" class="agent-page-nav" :aria-label="t('agents.detail.sectionNavigation')">
      <ul>
        <li
          v-for="s in visibleSections"
          :key="s.id"
          :class="{ active: activeSectionId === s.id }"
        >
          <a :href="`#${s.id}`" @click="scrollToSection(s.id, $event)">
            <span class="nav-label">{{ s.label }}</span>
            <Tag
              v-if="badgeFor(s)"
              :value="formatNumber(setupStatus?.[(s as any).needsSetupKey] ?? 0)"
              severity="warn"
            />
          </a>
        </li>
        <li v-if="activityVisible" :class="{ active: activeSectionId === 'activity' }">
          <a href="#activity" @click="scrollToSection('activity', $event)">
            <span class="nav-label">{{ t('agents.detail.activity') }}</span>
          </a>
        </li>
      </ul>
    </nav>

    <!-- Single inline scroll: each configuration domain is a SectionCard;
          Activity (Runs + Builds + Jobs) is the final section. Sections hide
         themselves when their tab reports zero items via @populated. -->
    <div ref="mainRef" class="agent-page-main" :key="tabsKey">
      <SectionCard
        v-for="s in configSections"
        v-show="(!(s as any).adminOnly || isAgentAdmin) && ((s as any).alwaysShow || (counts[s.id] ?? 0) > 0)"
        :key="s.id"
        :id="s.id"
        :title="s.label"
        :badge="badgeFor(s)"
      >
        <component
          :is="s.component"
          :agent-id="agentId"
          :your-access="['members', 'connections', 'mcp-servers', 'connectors', 'models'].includes(s.id) ? (agent?.yourAccess ?? '') : undefined"
          v-bind="s.id === 'source' ? { agentSlug: agent?.slug ?? '' } : {}"
          @populated="onPopulated(s.id, $event)"
          @mutated="onResourceMutation"
        />
      </SectionCard>

      <SectionCard
        v-if="isAgentAdmin"
        v-show="activityVisible"
        id="activity"
        :title="t('agents.detail.activity')"
      >
        <Tabs v-model:value="activityTab">
          <TabList>
            <Tab :value="0">{{ t('agents.detail.runs') }}</Tab>
            <Tab :value="1">{{ t('agents.detail.builds') }}</Tab>
            <Tab :value="2">{{ t('agents.detail.jobs') }}</Tab>
          </TabList>
          <TabPanels>
            <TabPanel :value="0">
              <RunsTab :agent-id="agentId" @populated="onPopulated('runs', $event)" />
            </TabPanel>
            <TabPanel :value="1">
              <BuildsTab
                :agent-id="agentId"
                :current-source-ref="agent?.sourceRef ?? ''"
                :read-only-git="isReadOnlyGit"
                @populated="onPopulated('builds', $event)"
              />
            </TabPanel>
            <TabPanel :value="2">
              <JobsTab :agent-id="agentId" @populated="onPopulated('jobs', $event)" />
            </TabPanel>
          </TabPanels>
        </Tabs>
      </SectionCard>
    </div>

    <!-- Upgrade dialog -->
    <Dialog v-model:visible="showUpgradeDialog" :header="rebuildMode ? t('agents.detail.rebuildApp') : t('agents.detail.upgradeApp')" modal style="width: 30rem">
      <template v-if="isReadOnlyGit">
        <p style="margin-top: 0">
          {{ t('agents.detail.rebuildDescription') }}
        </p>
        <small style="display: block; color: var(--p-text-muted-color)">
          {{ t('agents.detail.gitAuthoritative') }}
        </small>
      </template>
      <template v-else>
        <p style="margin-top: 0">{{ t('agents.detail.upgradePrompt') }}</p>
        <Textarea v-model="upgradeDescription" rows="4" style="width: 100%" :placeholder="t('agents.detail.upgradePlaceholder')" autofocus />
        <small style="display: block; margin-top: 0.5rem; color: var(--p-text-muted-color)">
          {{ t('agents.detail.emptyUpgradeBeforeRebuild') }} <strong>{{ t('agents.action.rebuildLowercase') }}</strong> {{ t('agents.detail.emptyUpgradeAfterRebuild') }}
        </small>
      </template>
      <template #footer>
        <Button :label="t('agents.action.cancel')" severity="secondary" text @click="showUpgradeDialog = false" />
        <Button :label="rebuildMode ? t('agents.action.rebuild') : t('agents.action.upgrade')" :icon="rebuildMode ? 'pi pi-refresh' : 'pi pi-arrow-up'" @click="submitUpgrade" />
      </template>
    </Dialog>

    <Dialog v-model:visible="renameOpen" :header="t('agents.detail.renameTitle')" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.detail.name') }}</label>
          <InputText v-model="renameName" style="width: 100%" autofocus />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.create.slug') }}</label>
          <InputText v-model="renameSlug" style="width: 100%" />
          <small style="display: block; margin-top: 0.35rem; color: var(--p-text-muted-color)">
            {{ t('agents.detail.slugHelp') }}
          </small>
        </div>
        <Message v-if="slugChanged" severity="warn" :closable="false">
          {{ t('agents.detail.slugWarningBeforeBinding') }} <code>agent_&lt;slug&gt;</code> {{ t('agents.detail.slugWarningAfterBinding') }}
        </Message>
      </div>
      <template #footer>
        <Button :label="t('agents.action.cancel')" severity="secondary" text :disabled="renaming" @click="renameOpen = false" />
        <Button :label="t('agents.action.save')" icon="pi pi-check" :loading="renaming" @click="saveRename" />
      </template>
    </Dialog>

    <Dialog v-model:visible="cloneOpen" :header="t('agents.detail.cloneTitle')" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <Message severity="info" :closable="false">
          {{ t('agents.detail.cloneDescriptionBeforeNot') }} <strong>{{ t('agents.detail.not') }}</strong> {{ t('agents.detail.cloneDescriptionAfterNot') }}
        </Message>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.detail.name') }}</label>
          <InputText v-model="cloneName" style="width: 100%" autofocus />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.create.slug') }}</label>
          <InputText v-model="cloneSlug" style="width: 100%" />
          <small style="display: block; margin-top: 0.35rem; color: var(--p-text-muted-color)">
            {{ t('agents.detail.slugHelp') }}
          </small>
        </div>
      </div>
      <template #footer>
        <Button :label="t('agents.action.cancel')" severity="secondary" text :disabled="cloning" @click="cloneOpen = false" />
        <Button :label="t('agents.action.clone')" icon="pi pi-copy" :loading="cloning" @click="saveClone" />
      </template>
    </Dialog>

    <Dialog v-model:visible="transferOpen" :header="t('agents.detail.transferOwnership')" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <Message severity="warn" :closable="false">
          {{ t('agents.detail.transferDescription') }}
        </Message>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">{{ t('agents.detail.transferTo') }}</label>
          <Select
            v-model="transferTarget"
            :options="transferUsers"
            option-label="label"
            option-value="id"
            :placeholder="t('agents.detail.selectUser')"
            filter
            style="width: 100%"
          />
        </div>
      </div>
      <template #footer>
        <Button :label="t('agents.action.cancel')" severity="secondary" text :disabled="transferring" @click="transferOpen = false" />
        <Button :label="t('agents.action.transfer')" icon="pi pi-user-edit" severity="danger" :loading="transferring" :disabled="!transferTarget" @click="saveTransfer" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
/* Clickable "Building N/M tasks" badge linking to the dedicated Build page. */
.build-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35rem 0.75rem;
  border-radius: 0.5rem;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--p-primary-contrast-color);
  background: var(--p-primary-color);
  text-decoration: none;
}
.build-badge:hover {
  filter: brightness(1.05);
}

/* Sticky horizontal section nav. Sits above the sections and stays at the
 * top of the scroll viewport as the user scrolls through them. The
 * negative horizontal margins let it span the full inner width of the
 * agent page (offsetting the page's own 1.5rem padding) so the bottom
 * border reads as a true page divider. */
.agent-page-nav {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--p-content-background);
  /* Break out of .app-content's 1.5rem side padding so the bar spans the
     full content area (reads as a top bar, not a section), then pad the
     items back in to keep them aligned with the page content. A baseline
     border separates it from the sections below. */
  margin: 0 -1.5rem 1.25rem;
  padding: 0 1.5rem;
  border-bottom: 1px solid var(--p-content-border-color);
  overflow-x: auto;
  /* Setting overflow-x alone implicitly auto-s overflow-y in most engines —
   * pin overflow-y so a phantom vertical scrollbar can't appear. */
  overflow-y: hidden;
  /* Keep the bar scrollable (narrow viewports + scrollspy centering) but hide
   * the scrollbar track, which otherwise shows as a thin strip under the tabs. */
  scrollbar-width: none; /* Firefox */
  -ms-overflow-style: none; /* legacy Edge */
}
.agent-page-nav::-webkit-scrollbar {
  display: none; /* Chromium, Safari */
}
.agent-page-nav ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  gap: 0;
  white-space: nowrap;
  align-items: stretch;
}
.agent-page-nav li {
  display: flex;
}
.agent-page-nav li a {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0 0.85rem;
  height: 2.5rem; /* fixed so badged items don't push the underline lower */
  box-sizing: border-box;
  color: var(--p-text-muted-color);
  text-decoration: none;
  font-size: 0.875rem;
  border-bottom: 2px solid transparent;
  transition: color 0.15s ease, border-color 0.15s ease;
}
.agent-page-nav li a:hover {
  color: var(--p-text-color);
}
.agent-page-nav li.active a {
  color: var(--p-text-color);
  border-bottom-color: var(--p-primary-color);
  font-weight: 500;
}
.agent-page-nav .nav-label {
  white-space: nowrap;
}

.agent-page-main {
  min-width: 0;
}

/* Tabs use their own <h3> for inner subheadings (e.g. SiblingsTab's
 * "Who can call this agent"). Browser/PrimeVue h3 defaults can rival or
 * exceed the section title — normalize so subheadings stay clearly
 * smaller and the colored section title remains the dominant heading. */
.agent-page-main :deep(h3) {
  font-size: 1rem;
  font-weight: 500;
  margin-top: 0;
}

/* PrimeVue's TabPanels apply default padding around inner content, which
 * makes the DataTables inside Activity (Runs / Builds) look inset relative
 * to the other section tables. Zero it so they share the full section
 * width; the TabList keeps its own styling. */
.agent-page-main :deep(.p-tabpanels) {
  padding: 0;
  background: transparent;
}
.agent-page-main :deep(.p-tabpanel) {
  padding: 0;
}

</style>
