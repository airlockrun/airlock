import { ref, nextTick, onMounted, onUnmounted } from 'vue'
import { ws } from '@/api/ws'
import { useBuildsStore } from '@/stores/builds'
import type { AgentBuildInfo, TodoItem } from '@/gen/airlock/v1/types_pb'

// useBuildStream owns the per-build snapshot + live stream for the Build page.
// It loads the REST snapshot (sol/docker log, todos), subscribes to the
// per-build WS topic (codegen log, todos), and dedupes live events against the
// snapshot by seq.
export function useBuildStream(agentId: string, buildId: string) {
  const buildsStore = useBuildsStore()

  const build = ref<AgentBuildInfo | null>(null)
  const solLines = ref<string[]>([])
  const dockerLines = ref<string[]>([])
  const todos = ref<TodoItem[]>([])
  const phase = ref('')
  const loaded = ref(false)

  const snapshotSeq = ref(0)
  const logBuffer: Array<{ seq: number; stream: string; line: string }> = []
  let pendingTodos: { seq: number; todos: TodoItem[] } | null = null

  const unsubs: Array<() => void> = []

  function appendLog(stream: string, line: string) {
    const target = stream === 'docker' ? dockerLines : solLines
    target.value.push(line)
    if (target.value.length > 4000) target.value = target.value.slice(-4000)
  }

  function onLog(payload: any) {
    if (String(payload?.buildId || '') !== buildId) return
    const seq = Number(payload.seq || 0)
    const stream = String(payload.stream || 'sol')
    const line = String(payload.line || '')
    if (!loaded.value) {
      logBuffer.push({ seq, stream, line })
      return
    }
    if (seq > 0 && seq <= snapshotSeq.value) return
    appendLog(stream, line)
  }

  function onTodos(payload: any) {
    if (String(payload?.buildId || '') !== buildId) return
    const seq = Number(payload.seq || 0)
    const list = (payload.todos || []) as TodoItem[]
    if (!loaded.value) {
      pendingTodos = { seq, todos: list }
      return
    }
    todos.value = list
  }

  // Lifecycle status on the agent topic: keep the metadata fresh (terminal
  // transitions carry the final result via a snapshot refetch).
  function onBuildEvent(payload: any) {
    if (String(payload?.buildId || '') !== buildId) return
    if (payload.phase) phase.value = String(payload.phase)
    const status = String(payload.status || '')
    if (build.value && status && status !== 'progress' && status !== 'started') {
      build.value.status = status === 'complete' ? 'complete' : status
      // Terminal: refetch to pick up exit_status / exit_message / error /
      // finished_at, which ride the REST row, not the verbose stream.
      void refreshSnapshot()
    }
  }

  async function refreshSnapshot() {
    try {
      build.value = await buildsStore.fetchBuild(agentId, buildId)
      if (build.value.todos?.length) todos.value = build.value.todos
    } catch {
      // tolerate (build may be mid-write)
    }
  }

  async function hydrate() {
    try {
      const b = await buildsStore.fetchBuild(agentId, buildId)
      build.value = b
      solLines.value = b.solLog ? b.solLog.split('\n').filter((l) => l.length > 0) : []
      dockerLines.value = b.dockerLog ? b.dockerLog.split('\n').filter((l) => l.length > 0) : []
      snapshotSeq.value = Number(b.logSeq || 0n)
      todos.value = b.todos ?? []
    } catch {
      // Build may not exist yet — tolerate; live stream fills it in.
    }

    loaded.value = true

    // Drain buffers captured during the snapshot fetch.
    for (const m of logBuffer) {
      if (m.seq > 0 && m.seq <= snapshotSeq.value) continue
      appendLog(m.stream, m.line)
    }
    logBuffer.length = 0
    if (pendingTodos && pendingTodos.seq > snapshotSeq.value) {
      todos.value = pendingTodos.todos
    }
    pendingTodos = null
  }

  onMounted(async () => {
    // Subscribe to the per-build topic FIRST so events during the snapshot
    // fetch are buffered, then register handlers, then hydrate.
    ws.subscribeBuild(buildId)
    unsubs.push(ws.onMessage('agent.build.log', onLog))
    unsubs.push(ws.onMessage('agent.build.todos', onTodos))
    unsubs.push(ws.onMessage('agent.build', onBuildEvent))
    await hydrate()
    await nextTick()
  })

  onUnmounted(() => {
    ws.unsubscribeBuild(buildId)
    for (const u of unsubs) u()
  })

  return { build, solLines, dockerLines, todos, phase, loaded }
}
