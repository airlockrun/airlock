/** Maps agent status to PrimeVue Tag severity and display label. */
export function useAgentStatus(status: string) {
  switch (status) {
    case 'active':
      return { severity: 'success' as const, label: 'Active' }
    case 'building':
      return { severity: 'warn' as const, label: 'Building' }
    case 'error':
    case 'failed':
      return { severity: 'danger' as const, label: 'Error' }
    case 'stopped':
      return { severity: 'secondary' as const, label: 'Stopped' }
    case 'draft':
      return { severity: 'secondary' as const, label: 'Draft' }
    case 'inactive':
      return { severity: 'secondary' as const, label: 'Inactive' }
    default:
      return { severity: 'info' as const, label: status }
  }
}
