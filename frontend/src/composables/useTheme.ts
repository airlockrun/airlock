import { ref, watchEffect } from 'vue'

const savedTheme = localStorage.getItem('theme')
const isDark = ref(
  savedTheme ? savedTheme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches,
)

watchEffect(() => {
  document.documentElement.classList.toggle('dark', isDark.value)
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
})

export function useTheme() {
  function toggle() {
    isDark.value = !isDark.value
  }

  return { isDark, toggle }
}
