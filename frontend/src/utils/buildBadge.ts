// buildBadgeText renders the "build in progress" badge label. During codegen
// it shows the agent's task progress (N/M); once the pipeline moves past
// codegen the phase drives a stage label so the badge doesn't freeze on the
// final task count while the image builds / migrations run / the container
// swaps. Phases come from AgentBuildEvent.phase.
export function buildBadgeText(phase: string, done: number, total: number): string {
  switch (phase) {
    case 'image': return 'Building image…'
    case 'migrations': return 'Running migrations…'
    case 'deploy': return 'Deploying…'
    default: return total > 0 ? `Building ${done}/${total} tasks` : 'Building…'
  }
}
