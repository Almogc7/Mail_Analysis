import { describe, expect, it } from 'vitest'
import { listSrc, readSrc } from './readSource'

/**
 * Rendering rules for untrusted content (docs/DESIGN_V2.md, section 9): the UI shows text, never markup. This test reads the source of every
 * non-test file and fails if any of them could render HTML from the message, load a remote image, open a frame, or make a message link clickable.
 * Stylesheets are read from disk (vitest returns an empty string for an imported .css), and the test asserts it really found their text.
 */
const isTest = (path: string) => /\.test\.tsx?$/.test(path) || path.startsWith('test/')
const code = listSrc('.ts').concat(listSrc('.tsx')).filter((p) => !isTest(p)).map((p) => [p, readSrc(p)] as const)
const styles = listSrc('.css').map((p) => [p, readSrc(p)] as const)
const everything = [...code, ...styles]

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
  ['a CSS url() loading a remote resource', /url\(\s*['"]?(https?:)?\/\//i],
  ['an @import of a remote stylesheet', /@import\s+(url\(\s*)?['"]?(https?:)?\/\//i],
]

describe('untrusted content is rendered as plain text only', () => {
  it('finds the source files and the stylesheets with real text (the test is not vacuous)', () => {
    const names = code.map(([path]) => path)
    expect(code.length).toBeGreaterThan(10)
    expect(names).toContain('components/ResultsView.tsx')
    expect(styles.length).toBeGreaterThanOrEqual(3)
    for (const [path, text] of styles) expect(text.length, path).toBeGreaterThan(100)
    expect(styles.find(([p]) => p === 'app.css')![1]).toContain('.verdict-benign')
  })

  it.each(FORBIDDEN)('no source file or stylesheet contains %s', (_label, pattern) => {
    expect(everything.filter(([, text]) => pattern.test(text)).map(([path]) => path)).toEqual([])
  })

  it('the only links the UI creates are the third-party lookup links of the indicator list, opened with noopener and noreferrer', () => {
    const withLinks = code.filter(([, text]) => /<a[\s>]/.test(text) || /href=/.test(text)).map(([path]) => path.split('/').pop())
    expect(withLinks).toEqual(['IndicatorsPanel.tsx'])
    const panel = code.find(([path]) => path.endsWith('IndicatorsPanel.tsx'))![1]
    expect(panel).toContain('rel="noopener noreferrer"')
    expect(panel).toContain('target="_blank"')
    expect(panel.match(/href=/g)).toHaveLength(1)
    expect(panel).toContain('href={p.url}')
  })

  it('no source file builds a link from message content (an href from a URL, host or display text)', () => {
    for (const [path, text] of code) {
      if (path.endsWith('IndicatorsPanel.tsx')) continue
      expect(text, path).not.toMatch(/href\s*=/)
      expect(text, path).not.toMatch(/\.href\s*=/)
    }
  })
})
