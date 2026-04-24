import { computed, type Ref } from 'vue'
import { marked } from 'marked'

marked.setOptions({ gfm: true, breaks: true })

const renderer = new marked.Renderer()
renderer.link = ({ href, text }) => {
  return `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`
}
marked.use({ renderer })

export function useMarkdown(source: Ref<string>) {
  const html = computed(() => {
    if (!source.value) return ''
    return marked.parse(source.value) as string
  })

  return { html }
}
