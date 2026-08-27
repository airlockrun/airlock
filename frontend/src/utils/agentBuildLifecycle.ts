import type { AgentBuildEvent, AgentInfo } from '@/gen/airlock/v1/types_pb'

type AgentBuildState = Pick<AgentInfo, 'status' | 'upgradeStatus' | 'errorMessage'>
type BuildLifecycleEvent = Pick<AgentBuildEvent, 'status' | 'error'>

export function applyAgentBuildEvent(agent: AgentBuildState, event: BuildLifecycleEvent) {
  switch (event.status) {
    case 'started':
      agent.errorMessage = ''
      if (agent.status === 'draft' || agent.status === 'failed') {
        agent.status = 'building'
      } else {
        agent.upgradeStatus = 'building'
      }
      break
    case 'complete':
      if (agent.status !== 'stopped') agent.status = 'active'
      agent.upgradeStatus = 'idle'
      agent.errorMessage = ''
      break
    case 'failed':
    case 'cancelled':
      agent.upgradeStatus = 'failed'
      if (agent.status === 'building') agent.status = 'failed'
      agent.errorMessage = event.error
      break
    case 'refused':
      agent.upgradeStatus = 'idle'
      if (agent.status === 'building') {
        agent.status = 'failed'
        agent.errorMessage = event.error
      } else {
        agent.errorMessage = ''
      }
      break
  }
}
