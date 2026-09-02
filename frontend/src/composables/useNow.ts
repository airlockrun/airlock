import { onScopeDispose, ref } from 'vue'

export function useNow(refreshMilliseconds = 1000) {
  const now = ref(Date.now())
  const timer = window.setInterval(() => {
    now.value = Date.now()
  }, refreshMilliseconds)
  onScopeDispose(() => window.clearInterval(timer))
  return now
}
