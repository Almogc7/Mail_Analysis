import { describe, expect, it } from 'vitest'
import { readSrc } from './readSource'

/**
 * workbench.css is migrated to the design tokens (docs/UI_DESIGN.md): colours come from theme.css only. This test reads the stylesheet text from disk
 * (vitest returns an empty string for an imported .css), drops comments, and fails if a raw colour, a color-mix(), a remote url() or an @import
 * appears, if it uses a custom property that theme.css does not define or that was retired in step 13, or if the motion and hover rules drift.
 */
const strip = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, '')
const raw = readSrc('workbench.css')
const css = strip(raw)
const theme = readSrc('theme.css')

const defined = new Set([...strip(theme).matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]))
// the legacy tokens deleted from theme.css in step 13; they must not come back
const RETIRED = [
  '--border-muted', '--accent-green', '--accent-cyan', '--accent-red', '--accent-amber', '--verdict-needs-review', '--verdict-legit',
  '--severity-critical', '--severity-high', '--severity-medium', '--severity-low', '--severity-info', '--llm-bg', '--llm-border',
]

const RAW_COLOUR: [string, RegExp][] = [
  ['a hex colour', /#[0-9a-fA-F]{3,8}\b/],
  ['an rgb()/rgba() colour', /\brgba?\s*\(/i],
  ['an hsl()/hsla()/hwb() colour', /\b(hsla?|hwb)\s*\(/i],
  ['an lab()/lch()/oklab()/oklch()/color() colour', /\b(ok)?(lab|lch)\s*\(|\bcolor\s*\(/i],
  ['a named colour', /:[^;{}]*\b(red|green|blue|white|black|gray|grey|orange|yellow|cyan|magenta|purple|pink|brown|navy|teal|silver|gold|lime|maroon)\b/i],
  ['color-mix()', /color-mix\s*\(/i],
  ['a url()', /url\s*\(/i],
  ['an @import', /@import/i],
]

describe('workbench.css uses design tokens only', () => {
  it('is read from disk with real content (the test is not vacuous)', () => {
    expect(css.length).toBeGreaterThan(2000)
    expect(css).toContain('.wb-panel')
    expect(css).toContain('var(--bg-panel')
    expect(defined.has('--bg-panel')).toBe(true)
    expect(RETIRED.filter((name) => defined.has(name))).toEqual([])
  })

  it.each(RAW_COLOUR)('contains no %s', (_label, pattern) => {
    expect(css.match(pattern)).toBeNull()
  })

  it('uses only custom properties that theme.css defines, and none of the legacy ones', () => {
    const used = [...new Set([...css.matchAll(/var\(\s*(--[\w-]+)/g)].map((m) => m[1]))]
    expect(used.length).toBeGreaterThan(20)
    expect(used.filter((name) => !defined.has(name))).toEqual([])
    expect(used.filter((name) => RETIRED.includes(name))).toEqual([])
  })

  it('has no animation: no keyframes, and the only transition is the 100ms hover colour change', () => {
    expect(css).not.toMatch(/@keyframes|animation\s*:|animation-name/)
    const transitions = [...css.matchAll(/transition\s*:\s*([^;]+);/g)].map((m) => m[1].trim())
    expect(transitions).toEqual(['border-color 100ms, background-color 100ms', 'none'])
    expect(css).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*transition: none/)
  })

  it('has a forced-colors block that uses system colours only', () => {
    const start = css.indexOf('@media (forced-colors: active)')
    expect(start).toBeGreaterThan(-1)
    const block = css.slice(start)
    expect(block).toMatch(/CanvasText/)
    expect(block).toMatch(/Highlight/)
    expect(block).not.toMatch(/var\(--(?!space)/)
  })

  it('hover never uses the focus colour, and the focus ring does', () => {
    const hoverRules = [...css.matchAll(/[^{}]*:hover[^{}]*\{[^}]*\}/g)].map((m) => m[0])
    expect(hoverRules.length).toBeGreaterThan(0)
    for (const rule of hoverRules) expect(rule).not.toContain('--focus')
    expect(css).toMatch(/:focus-visible\s*\{[^}]*var\(--focus\)/)
  })

  it('uses logical properties next to content, not left or right', () => {
    expect(css).not.toMatch(/\b(margin|padding|border)-(left|right)\b/)
    expect(css).not.toMatch(/(^|[;{\s])(left|right)\s*:/)
    expect(css).not.toMatch(/text-align\s*:\s*(left|right)/)
  })
})
