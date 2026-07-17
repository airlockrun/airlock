// @vitest-environment jsdom

import { describe, expect, it } from 'vitest'
import { renderMarkdown } from './useMarkdown'

describe('renderMarkdown', () => {
  it('removes script elements', () => {
    const html = renderMarkdown('<script>window.pwned = true</script><p>safe</p>')

    expect(html).not.toContain('<script')
    expect(html).not.toContain('window.pwned')
    expect(html).toContain('<p>safe</p>')
  })

  it('removes event handler attributes', () => {
    const html = renderMarkdown('<img src="/safe.png" onerror="alert(1)"><p onclick="alert(1)">safe</p>')

    expect(html).not.toMatch(/onerror|onclick/i)
    expect(html).toContain('src="/safe.png"')
  })

  it('removes SVG content', () => {
    const html = renderMarkdown('<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>')

    expect(html).not.toMatch(/svg|xlink|javascript:/i)
  })

  it('does not create links for javascript URLs', () => {
    const html = renderMarkdown('[click me](javascript:alert(1))')

    expect(html).not.toMatch(/href|javascript:/i)
    expect(html).toContain('click me')
  })

  it('keeps safe links isolated from the opener', () => {
    const html = renderMarkdown('[docs](https://example.com/docs)')

    expect(html).toContain('href="https://example.com/docs"')
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
  })
})
