/**
 * Maps the (agents.status, container running) tuple to a display badge.
 *
 * Three runtime states the user sees:
 *   - Running   = status=active AND container running
 *   - Suspended = status=active AND container NOT running
 *                 (either reaped after idle or explicitly suspended;
 *                 next trigger auto-resumes via EnsureRunning)
 *   - Stopped   = status=stopped (no auto-resume; manual Start needed)
 *
 * Pre-runtime states (Draft, Building) and terminal failure
 * (Error) bypass the running flag — they describe the agent's
 * lifecycle, not its container.
 */
export function useAgentStatus() {
  const { t } = useAirlockI18n()

  return (status: string, running?: boolean) => {
    switch (status) {
      case 'active':
        if (running) return { severity: 'success' as const, label: t('agents.status.running') }
        return { severity: 'secondary' as const, label: t('agents.status.suspended') }
      case 'building':
        return { severity: 'warn' as const, label: t('agents.status.building') }
      case 'error':
      case 'failed':
        return { severity: 'danger' as const, label: t('agents.status.error') }
      case 'stopped':
        return { severity: 'secondary' as const, label: t('agents.status.stopped') }
      case 'draft':
        return { severity: 'secondary' as const, label: t('agents.status.draft') }
      case 'inactive':
        return { severity: 'secondary' as const, label: t('agents.status.inactive') }
      default:
        return { severity: 'info' as const, label: status }
    }
  }
}
import { useAirlockI18n } from '@/i18n'
