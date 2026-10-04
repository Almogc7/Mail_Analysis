import { describe, expect, it } from 'vitest'

/**
 * Rendering rules for untrusted content (docs/DESIGN_V2.md, section 9): the UI shows text, never markup. This test reads the source of every
 * non-test file and fails if any of them could render HTML from the message, load a remote image, open a frame, or make a message link clickable.
 */
const sources = import.meta.glob('../**/*.{ts,tsx,css}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
const files = Object.entries(sources).filter(([path]) => !/\.test\.tsx?$/.test(path) && !path.includes('/test/'))

const FORBIDDEN: [string, RegExp][] = [
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['innerHTML / outerHTML', /\b(inner|outer)HTML\b/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['document.write', /document\.write/],
  ['an <img> element (a remote image is a tracking beacon)', /<img[\s>/]/i],
  ['an <iframe>', /<iframe[\s>/]/i],
  ['an <object> or <embed>', /<(object|embed)[\s>/]/i],
  ['a <script> element', /<script[\s>/]/i],
  ['srcDoc', /srcDoc/],
  ['eval()', /\beval\s*\(/],
  ['new Function()', /new\s+Function\s*\(/],
  ['window.open', /window\.open/],
  ['a javascript: URL', /javascript:/i],
  ['a CSS url() loading a remote resource', /url\(\s*['"]?https?:/i],
  ['an @import of a remote stylesheet', /@import\s+url\(\s*['"]?https?:/i],
]

describe('untrusted content is rendered as plain text only', () => {
  it('finds the source files (the test is not vacuous)', () => {
    const names = files.map(([path]) => path)
    expect(files.length).toBeGreaterThan(10)
    expect(names.some((n) => n.endsWith('/ResultsView.tsx'))).toBe(true)
  })

  it.each(FORBIDDEN)('no source file contains %s', (_label, pattern) => {
    const offenders = files.filter(([, text]) => pattern.test(text)).map(([path]) => path)
    expect(offenders).toEqual([])
  })

  it('the only links the UI creates are the third-party lookup links of the indicator list, opened with noopener and noreferrer', () => {
    const withLinks = files.filter(([, text]) => /<a[\s>]/.test(text) || /href=/.test(text)).map(([path]) => path.split('/').pop())
    expect(withLinks).toEqual(['IndicatorsPanel.tsx'])
    const panel = files.find(([path]) => path.endsWith('/IndicatorsPanel.tsx'))![1]
    expect(panel).toContain('rel="noopener noreferrer"')
    expect(panel).toContain('target="_blank"')
    expect(panel.match(/href=/g)).toHaveLength(1)
    expect(panel).toContain('href={p.url}')
  })

  it('no source file builds a link from message content (an href from a URL, host or display text)', () => {
    for (const [path, text] of files) {
      if (path.endsWith('/IndicatorsPanel.tsx')) continue
      expect(text, path).not.toMatch(/href\s*=/)
      expect(text, path).not.toMatch(/\.href\s*=/)
    }
  })
})
