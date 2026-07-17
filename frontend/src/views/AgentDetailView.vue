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
import type { AgentInfo } from '@/gen/airlock/v1/types_pb'
import { GetAgentDetailResponseSchema } from '@/gen/airlock/v1/api_pb'
import ConnectionsTab from '@/components/agent/ConnectionsTab.vue'
import ExecEndpointsTab from '@/components/agent/ExecEndpointsTab.vue'
import WebhooksTab from '@/components/agent/WebhooksTab.vue'
import SchedulesTab from '@/components/agent/SchedulesTab.vue'
import RoutesTab from '@/components/agent/RoutesTab.vue'
import MCPServersTab from '@/components/agent/MCPServersTab.vue'
import EnvVarsTab from '@/components/agent/EnvVarsTab.vue'
import ToolsTab from '@/components/agent/ToolsTab.vue'
import MembersTab from '@/components/agent/MembersTab.vue'
import SiblingsTab from '@/components/agent/SiblingsTab.vue'
import AccessTab from '@/components/agent/AccessTab.vue'
import ModelsTab from '@/components/agent/ModelsTab.vue'
import RunsTab from '@/components/agent/RunsTab.vue'
import BuildsTab from '@/components/agent/BuildsTab.vue'
import SourceTab from '@/components/agent/SourceTab.vue'
import SectionCard from '@/components/agent/SectionCard.vue'
import { useBuildsStore } from '@/stores/builds'
import { buildBadgeText } from '@/utils/buildBadge'
import { markRaw } from 'vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()

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
    toast.add({ severity: 'warn', summary: 'Name is required', life: 3000 })
    return
  }
  if (slug.length < 2 || slug.length > 63 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    toast.add({
      severity: 'warn',
      summary: 'Invalid slug',
      detail: '2–63 chars: lowercase letters/digits, single dashes between.',
      life: 4000,
    })
    return
  }
  renaming.value = true
  try {
    const updated = await agentsStore.renameAgent(agent.value.id, name, slug)
    agent.value = updated
    renameOpen.value = false
    toast.add({ severity: 'success', summary: 'App renamed', life: 2500 })
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
      summary: status === 409 ? 'Slug already taken' : 'Rename failed',
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
  cloneName.value = `${agent.value.name} copy`
  cloneSlug.value = `${agent.value.slug}-copy`
  cloneOpen.value = true
}

async function saveClone() {
  if (!agent.value) return
  const name = cloneName.value.trim()
  const slug = cloneSlug.value.trim()
  if (!name) {
    toast.add({ severity: 'warn', summary: 'Name is required', life: 3000 })
    return
  }
  if (slug.length < 2 || slug.length > 63 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    toast.add({ severity: 'warn', summary: 'Invalid slug', detail: '2–63 chars: lowercase letters/digits, single dashes.', life: 4000 })
    return
  }
  cloning.value = true
  try {
    const clone = await agentsStore.cloneAgent(agent.value.id, name, slug)
    cloneOpen.value = false
    toast.add({ severity: 'success', summary: 'App cloned', detail: 'Building your copy…', life: 3000 })
    router.push(`/agents/${clone.slug}`)
  } catch (e: any) {
    const status = e?.response?.status
    toast.add({ severity: 'error', summary: status === 409 ? 'Slug already taken' : 'Clone failed', detail: e?.response?.data?.error, life: 5000 })
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
  usersStore.selectable.map((u) => ({
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
    toast.add({ severity: 'warn', summary: 'Pick a user to transfer to', life: 3000 })
    return
  }
  const target = transferUsers.value.find((u) => u.id === transferTarget.value)
  confirm.require({
    message: `Transfer "${agent.value.name}" to ${target?.label ?? 'this user'}? You will lose access, and its connections, git credential, and bridges will be unbound.`,
    header: 'Transfer ownership',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      if (!agent.value) return
      transferring.value = true
      try {
        await agentsStore.transferOwnership(agent.value.id, transferTarget.value)
        transferOpen.value = false
        toast.add({ severity: 'success', summary: 'Ownership transferred', life: 3000 })
        router.push('/agents')
      } catch (e: any) {
        toast.add({ severity: 'error', summary: 'Transfer failed', detail: e?.response?.data?.error, life: 5000 })
      } finally {
        transferring.value = false
      }
    },
  })
}

const agentId = route.params.id as string
const agent = ref<AgentInfo | null>(null)
const loading = ref(true)
const activeBuildId = ref<string | undefined>(undefined)
// External URL of the agent's web homepage (GET "/"), or null when it has none.
const webUrl = ref<string | null>(null)
const buildTasksDone = ref(0)
const buildTasksTotal = ref(0)
const buildPhase = ref('')
const buildBadgeLabel = computed(() => buildBadgeText(buildPhase.value, buildTasksDone.value, buildTasksTotal.value))

// Per-section item counts emitted by each *Tab component via @populated.
// Sections (and their right-rail entries) only render when count > 0, so the
// page shows just what's actually relevant to this agent. Activity below is
// driven by the runs + builds counts together.
const counts = ref<Record<string, number>>({})
function onPopulated(id: string, n: number) {
  counts.value[id] = n
}

// Inner tab inside the Activity section: 0 = Runs, 1 = Builds.
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
// sharing → source → registered surfaces. Exec Endpoints defaults collapsed
// because its content (host/keys/pinning) is vertically heavy and most
// agents have at most one. needsSetupKey ties a section to the field on
// setupStatus that flags an unconfigured slot (see badgeFor below).
// markRaw skips deep reactivity on the component refs — they're constants.
const configSections = [
  { id: 'members',        label: 'Members',        component: markRaw(MembersTab) },
  { id: 'connections',    label: 'Connections',    component: markRaw(ConnectionsTab),   needsSetupKey: 'connections' as const },
  { id: 'mcp-servers',    label: 'MCP Servers',    component: markRaw(MCPServersTab),    needsSetupKey: 'mcpServers' as const },
  { id: 'env-vars',       label: 'Environment',    component: markRaw(EnvVarsTab),       needsSetupKey: 'envVars' as const },
  { id: 'exec-endpoints', label: 'Exec Endpoints', component: markRaw(ExecEndpointsTab) },
  { id: 'webhooks',       label: 'Webhooks',       component: markRaw(WebhooksTab) },
  { id: 'schedules',      label: 'Schedules',      component: markRaw(SchedulesTab) },
  { id: 'siblings',       label: 'Siblings',       component: markRaw(SiblingsTab), alwaysShow: true },
  { id: 'access',         label: 'Access',         component: markRaw(AccessTab), alwaysShow: true },
  { id: 'source',         label: 'Source',         component: markRaw(SourceTab), alwaysShow: true, adminOnly: true },
  { id: 'routes',         label: 'Routes',         component: markRaw(RoutesTab) },
  { id: 'tools',          label: 'Tools',          component: markRaw(ToolsTab) },
  { id: 'models',         label: 'Models',         component: markRaw(ModelsTab) },
] as const
type ConfigSection = (typeof configSections)[number]

// Activity (Runs + Builds) renders as the final section, but uses the same
// counts machinery — visible when at least one of its inner lists has items.
// Activity (runs + builds) is admin-only: both lists span every user's runs
// and the agent's build history, which non-admin members shouldn't see (the
// API gates the same via AgentRunView / AgentBuildsView).
const activityVisible = computed(() => isAgentAdmin.value && ((counts.value.runs ?? 0) > 0 || (counts.value.builds ?? 0) > 0))

// Right-rail entries — only sections with content. Hides empty-but-mounted
// sections from the rail (which itself still mounts so it can emit a count).
// Sections marked alwaysShow stay visible even at count 0 (e.g. Siblings,
// where the "add your first sibling" affordance is a meaningful entry point).
// adminOnly sections (Source: its only action, connect, is agent-admin) are
// hidden entirely from non-admins rather than showing an action that 403s.
const isAgentAdmin = computed(() => agent.value?.yourAccess === 'admin')
const visibleSections = computed(() =>
  configSections.filter((s) => {
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
  const key = (section as { needsSetupKey?: keyof SetupStatus }).needsSetupKey
  if (!key) return undefined
  const n = s[key]
  if (typeof n !== 'number' || n <= 0) return undefined
  return `${n} need${n === 1 ? 's' : ''} setup`
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
  const status = agent.value?.status ?? ''
  const running = !!agent.value?.running
  if (status === 'active') {
    if (running) {
      items.push({ label: 'Suspend', icon: 'pi pi-pause', command: () => doSuspend() })
      items.push({ label: 'Stop', icon: 'pi pi-stop', command: () => confirmStop() })
    } else {
      items.push({ label: 'Start', icon: 'pi pi-play', command: () => doStart() })
      items.push({ label: 'Stop', icon: 'pi pi-stop', command: () => confirmStop() })
    }
  } else if (status === 'stopped' || status === 'failed') {
    items.push({ label: 'Start', icon: 'pi pi-play', command: () => doStart() })
  }
  items.push({ label: 'Upgrade', icon: 'pi pi-arrow-up', command: () => doUpgrade() })
  if (canClone.value) {
    items.push({ label: 'Clone', icon: 'pi pi-copy', command: () => openClone() })
  }
  if (canTransfer.value) {
    items.push({ label: 'Transfer ownership', icon: 'pi pi-user-edit', command: () => openTransfer() })
  }
  items.push({ label: 'Delete', icon: 'pi pi-trash', command: () => confirmDelete() })
  return items
})

const statusTooltip = computed(() => {
  const status = agent.value?.status ?? ''
  const running = !!agent.value?.running
  if (status === 'active' && running) return 'A container is live'
  if (status === 'active' && !running) return 'No container running - starts automatically on next use'
  if (status === 'stopped') return 'Stopped - will not auto-resume; click Start'
  return ''
})

interface SetupStatus {
  connections: number
  mcpServers: number
  envVars: number
}
const setupStatus = ref<SetupStatus | null>(null)

async function loadSetupStatus() {
  try {
    const { data } = await api.get(`/api/v1/agents/${agentId}/setup-status`)
    setupStatus.value = (data?.counts ?? null) as SetupStatus | null
  } catch {
    // Non-fatal — header just won't show the badge.
    setupStatus.value = null
  }
}

// Refresh setup-status when the page regains visibility — operator switched
// to another tab/window and may have changed something. The single-scroll
// layout removed the tab-switch refresh point this watch used to hook into.
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
  const ids = [...configSections.map((s) => s.id), 'activity']
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
  const s = setupStatus.value
  if (!s) return 0
  return (s.connections ?? 0) + (s.mcpServers ?? 0) + (s.envVars ?? 0)
})

const setupTooltip = computed(() => {
  const s = setupStatus.value
  const total = setupTotal.value
  if (!s || total === 0) return ''
  const parts: string[] = []
  if (s.connections) parts.push(`${s.connections} connection${s.connections === 1 ? '' : 's'}`)
  if (s.mcpServers) parts.push(`${s.mcpServers} MCP server${s.mcpServers === 1 ? '' : 's'}`)
  if (s.envVars) parts.push(`${s.envVars} env var${s.envVars === 1 ? '' : 's'}`)
  return `${parts.join(', ')} need${total === 1 ? 's' : ''} setup`
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
    toast.add({ severity: 'error', summary: 'App not found', life: 3000 })
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
    if (payload.status === 'started') {
      // New build kicked off while we were watching; buildId already captured
      // above. Mirror the server-side state transition so the build badge
      // appears immediately instead of waiting for a page refresh.
      if (agent.value) {
        if (agent.value.status === 'draft' || agent.value.status === 'failed') {
          agent.value.status = 'building'
        } else {
          agent.value.upgradeStatus = 'building'
        }
      }
      return
    }
    if (payload.status === 'complete') {
      if (agent.value) {
        agent.value.status = 'active'
        agent.value.upgradeStatus = 'idle'
      }
      toast.add({ severity: 'success', summary: 'Build complete', life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'failed') {
      if (agent.value) {
        agent.value.upgradeStatus = 'failed'
        // Initial build that failed never reached active — drop it out of
        // 'building' so the badge clears (mirrors the cancelled branch).
        if (agent.value.status === 'building') agent.value.status = 'failed'
      }
      toast.add({ severity: 'error', summary: payload.error || 'Build failed', life: 10000 })
      tabsKey.value++
    } else if (payload.status === 'cancelled') {
      if (agent.value) {
        agent.value.upgradeStatus = 'failed'
        if (agent.value.status === 'building') agent.value.status = 'failed'
      }
      toast.add({ severity: 'warn', summary: 'Build cancelled', life: 3000 })
      tabsKey.value++
    } else if (payload.status === 'refused') {
      // The request was out of scope — the agent itself is untouched.
      // An initial build still has no image, so it lands on 'failed';
      // an upgrade just returns to idle.
      if (agent.value) {
        agent.value.upgradeStatus = 'idle'
        if (agent.value.status === 'building') agent.value.status = 'failed'
      }
      toast.add({
        severity: 'warn',
        summary: 'Request declined',
        detail: payload.error || "Outside the app builder's scope",
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
      summary: 'Synced',
      detail: `${agent.value?.slug ?? 'App'} synced`,
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
    message:
      `Stop app "${agent.value?.name}"? It will not auto-resume on the ` +
      'next trigger - you\'ll have to click Start to bring it back.',
    header: 'Confirm Stop',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await api.post(`/api/v1/agents/${agentId}/stop`, {})
        if (agent.value) {
          agent.value.status = 'stopped'
          agent.value.running = false
        }
        toast.add({ severity: 'success', summary: 'App stopped', life: 3000 })
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Stop failed', life: 5000 })
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
      summary: 'App suspended',
      detail: 'Auto-resumes on the next trigger.',
      life: 3000,
    })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Suspend failed', life: 5000 })
  }
}

async function doStart() {
  try {
    await api.post(`/api/v1/agents/${agentId}/start`, {})
    if (agent.value) agent.value.status = 'active'
    toast.add({ severity: 'success', summary: 'App started', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Start failed', life: 5000 })
  }
}

function confirmDelete() {
  confirm.require({
    message: `Delete app "${agent.value?.name}"? This cannot be undone.`,
    header: 'Confirm Delete',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await api.delete(`/api/v1/agents/${agentId}`)
        toast.add({ severity: 'success', summary: 'App deleted', life: 3000 })
        router.push('/agents')
      } catch (err: any) {
        toast.add({ severity: 'error', summary: err.response?.data?.error || 'Delete failed', life: 5000 })
      }
    },
  })
}

const showUpgradeDialog = ref(false)
const upgradeDescription = ref('')
// Empty description = bare rebuild (re-image current source against the
// latest agentsdk, no code changes). Any text = a codegen upgrade.
const rebuildMode = computed(() => upgradeDescription.value.trim() === '')

function doUpgrade() {
  upgradeDescription.value = ''
  showUpgradeDialog.value = true
}

async function submitUpgrade() {
  showUpgradeDialog.value = false
  try {
    const wasRebuild = rebuildMode.value
    await api.post(`/api/v1/agents/${agentId}/upgrade`, { description: upgradeDescription.value })
    if (agent.value) agent.value.upgradeStatus = 'queued'
    toast.add({ severity: 'info', summary: wasRebuild ? 'Rebuild queued' : 'Upgrade queued', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Upgrade failed', life: 5000 })
  }
}

async function cancelBuild() {
  try {
    await api.post(`/api/v1/agents/${agentId}/builds/cancel`)
    toast.add({ severity: 'info', summary: 'Build cancelled', life: 3000 })
  } catch (err: any) {
    toast.add({ severity: 'error', summary: err.response?.data?.error || 'Cancel failed', life: 5000 })
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
            aria-label="Rename app"
            v-tooltip.bottom="'Rename'"
            @click="openRename"
          />
          <!-- Single badge that folds container state into the lifecycle:
               Running/Suspended/Stopped/Building/Error/Draft. See
               useAgentStatus for the (status, running) → label map. -->
          <Tag
            :value="useAgentStatus(agent.status, agent.running).label"
            :severity="useAgentStatus(agent.status, agent.running).severity"
            v-tooltip.bottom="statusTooltip"
          />
          <Tag
            v-if="setupTotal > 0"
            :value="`Needs setup (${setupTotal})`"
            severity="warn"
            v-tooltip.bottom="setupTooltip"
          />
        </div>
        <p v-if="agent.description" style="margin: 0.5rem 0 0; color: var(--p-text-muted-color); font-size: 0.9rem">{{ agent.description }}</p>
      </div>
      <div style="display: flex; gap: 0.5rem">
        <Button label="Chat" icon="pi pi-comments" @click="goToChat" />
        <Button v-if="webUrl" label="Web" icon="pi pi-external-link" severity="secondary" outlined @click="openWeb" />
        <SplitButton label="Actions" :model="actionItems" severity="secondary" />
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
      <Button label="Cancel Build" icon="pi pi-times" severity="danger" size="small" text @click="cancelBuild" />
    </div>

    <!-- Error message -->
    <Message v-if="agent.errorMessage" severity="error" :closable="false" style="margin-bottom: 1rem">
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 0.8rem; max-height: 20rem; overflow-y: auto">{{ agent.errorMessage }}</pre>
    </Message>

    <!-- Sticky horizontal jump nav, placed after the action buttons so it
         sits above the sections and stays visible as the user scrolls
         through them. Only populated sections appear; the section currently
         in view (per scrollspy) gets the underline. -->
    <nav ref="navRef" class="agent-page-nav" aria-label="Section navigation">
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
              :value="String(setupStatus?.[(s as any).needsSetupKey] ?? '')"
              severity="warn"
            />
          </a>
        </li>
        <li v-if="activityVisible" :class="{ active: activeSectionId === 'activity' }">
          <a href="#activity" @click="scrollToSection('activity', $event)">
            <span class="nav-label">Activity</span>
          </a>
        </li>
      </ul>
    </nav>

    <!-- Single inline scroll: each configuration domain is a SectionCard;
         Activity (Runs + Builds) is the final section. Sections hide
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
          :your-access="s.id === 'models' ? (agent?.yourAccess ?? '') : undefined"
          v-bind="s.id === 'source' ? { agentSlug: agent?.slug ?? '' } : {}"
          @populated="onPopulated(s.id, $event)"
        />
      </SectionCard>

      <SectionCard
        v-if="isAgentAdmin"
        v-show="activityVisible"
        id="activity"
        title="Activity"
      >
        <Tabs v-model:value="activityTab">
          <TabList>
            <Tab :value="0">Runs</Tab>
            <Tab :value="1">Builds</Tab>
          </TabList>
          <TabPanels>
            <TabPanel :value="0">
              <RunsTab :agent-id="agentId" @populated="onPopulated('runs', $event)" />
            </TabPanel>
            <TabPanel :value="1">
              <BuildsTab :agent-id="agentId" :current-source-ref="agent?.sourceRef ?? ''" @populated="onPopulated('builds', $event)" />
            </TabPanel>
          </TabPanels>
        </Tabs>
      </SectionCard>
    </div>

    <!-- Upgrade dialog -->
    <Dialog v-model:visible="showUpgradeDialog" :header="rebuildMode ? 'Rebuild App' : 'Upgrade App'" modal style="width: 30rem">
      <p style="margin-top: 0">Describe what to change or fix:</p>
      <Textarea v-model="upgradeDescription" rows="4" style="width: 100%" placeholder="e.g. Add a /history page that shows past voting rounds" autofocus />
      <small style="display: block; margin-top: 0.5rem; color: var(--p-text-muted-color)">
        Leave empty to <strong>rebuild</strong> against the latest agentsdk - no code changes. If the SDK API changed and the code no longer compiles, the rebuild fails; add a description so the builder can adapt it.
      </small>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showUpgradeDialog = false" />
        <Button :label="rebuildMode ? 'Rebuild' : 'Upgrade'" :icon="rebuildMode ? 'pi pi-refresh' : 'pi pi-arrow-up'" @click="submitUpgrade" />
      </template>
    </Dialog>

    <Dialog v-model:visible="renameOpen" header="Rename app" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Name</label>
          <InputText v-model="renameName" style="width: 100%" autofocus />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Slug</label>
          <InputText v-model="renameSlug" style="width: 100%" />
          <small style="display: block; margin-top: 0.35rem; color: var(--p-text-muted-color)">
            Lowercase letters, digits and single dashes (2–63 chars).
          </small>
        </div>
        <Message v-if="slugChanged" severity="warn" :closable="false">
          Changing the slug re-points sibling <code>agent_&lt;slug&gt;</code> bindings and
          breaks any externally-configured MCP URL using the old slug. In-app
          links keep working.
        </Message>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text :disabled="renaming" @click="renameOpen = false" />
        <Button label="Save" icon="pi pi-check" :loading="renaming" @click="saveRename" />
      </template>
    </Dialog>

    <Dialog v-model:visible="cloneOpen" header="Clone app" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <Message severity="info" :closable="false">
          Copies this app's code and settings into a new app you own. Its data,
          secrets, connections and bridges are <strong>not</strong> copied - the clone
          starts clean and builds fresh.
        </Message>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Name</label>
          <InputText v-model="cloneName" style="width: 100%" autofocus />
        </div>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Slug</label>
          <InputText v-model="cloneSlug" style="width: 100%" />
          <small style="display: block; margin-top: 0.35rem; color: var(--p-text-muted-color)">
            Lowercase letters, digits and single dashes (2–63 chars).
          </small>
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text :disabled="cloning" @click="cloneOpen = false" />
        <Button label="Clone" icon="pi pi-copy" :loading="cloning" @click="saveClone" />
      </template>
    </Dialog>

    <Dialog v-model:visible="transferOpen" header="Transfer ownership" modal style="width: 28rem">
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 0.25rem">
        <Message severity="warn" :closable="false">
          The new owner becomes admin and you lose access. Owner-scoped bindings
          (connections, MCP/exec credentials, git credential, bridges) are unbound -
          the new owner reconnects their own.
        </Message>
        <div>
          <label style="display: block; margin-bottom: 0.35rem; font-size: 0.85rem">Transfer to</label>
          <Select
            v-model="transferTarget"
            :options="transferUsers"
            option-label="label"
            option-value="id"
            placeholder="Select a user"
            filter
            style="width: 100%"
          />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text :disabled="transferring" @click="transferOpen = false" />
        <Button label="Transfer" icon="pi pi-user-edit" severity="danger" :loading="transferring" :disabled="!transferTarget" @click="saveTransfer" />
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
