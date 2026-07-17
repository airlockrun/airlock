import { computed, type Ref } from 'vue'
import DOMPurify from 'dompurify'
import { marked } from 'marked'

marked.setOptions({ gfm: true, breaks: true })

const renderer = new marked.Renderer()
renderer.link = ({ href, text }) => {
  if (!isSafeLink(href)) return text
  return `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`
}
marked.use({ renderer })

const allowedTags = [
  'a', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4',
  'h5', 'h6', 'hr', 'img', 'li', 'ol', 'p', 'pre', 'strong', 'table',
  'tbody', 'td', 'th', 'thead', 'tr', 'ul',
]

// Relative URLs and these explicit protocols cover dashboard links while
// excluding executable and browser-local schemes such as javascript: and data:.
const allowedUri = /^(?:(?:https?|mailto|tel):|(?:[^a-z]|[a-z+.-]+(?:[^a-z+.-:]|$)))/i

function isSafeLink(href: string): boolean {
  try {
    const url = new URL(href, 'https://airlock.invalid')
    return ['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol)
  } catch {
    return false
  }
}

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.nodeName === 'A' && node.hasAttribute('href')) {
    node.setAttribute('target', '_blank')
    node.setAttribute('rel', 'noopener noreferrer')
  }
})

// This is the only function that turns Markdown into HTML. Every v-html call
// uses it directly or through useMarkdown below.
export function renderMarkdown(source: string): string {
  if (!source) return ''
  return DOMPurify.sanitize(marked.parse(source) as string, {
    ALLOWED_TAGS: allowedTags,
    ALLOWED_ATTR: ['alt', 'href', 'rel', 'src', 'target', 'title'],
    ALLOWED_URI_REGEXP: allowedUri,
  })
}

export function useMarkdown(source: Ref<string>) {
  const html = computed(() => renderMarkdown(source.value))

  return { html }
}
