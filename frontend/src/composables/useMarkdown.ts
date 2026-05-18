import { computed, type Ref } from 'vue'
import { marked } from 'marked'

marked.setOptions({ gfm: true, breaks: true })

const renderer = new marked.Renderer()
renderer.link = ({ href, text }) => {
  return `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`
}
marked.use({ renderer })

// renderMarkdown is the non-composable form — for call sites that need
// to render markdown imperatively (e.g. inside a v-for where a
// per-iteration composable isn't viable). Same renderer config.
export function renderMarkdown(source: string): string {
  if (!source) return ''
  return marked.parse(source) as string
}

export function useMarkdown(source: Ref<string>) {
  const html = computed(() => {
    if (!source.value) return ''
    return marked.parse(source.value) as string
  })

  return { html }
}
