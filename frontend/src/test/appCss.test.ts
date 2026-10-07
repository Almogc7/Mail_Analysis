import { describe, expect, it } from 'vitest'
import { readSrc } from './readSource'

/**
 * app.css uses the design tokens (docs/UI_DESIGN.md) in the WHOLE file; there is no exempt section any more (step 13 migrated the verdict card). This test
 * reads the stylesheet from disk (vitest returns an empty string for an imported .css), drops comments, and fails if the file has a raw colour (hex, rgb,
 * hsl, lab, a named colour), a color-mix(), a remote url() or @import, a retired or undefined token, a physical left/right property, a drifting motion or
 * hover rule, or a removed focus ring.
 */
const raw = readSrc('app.css')
const theme = readSrc('theme.css')
const strip = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, '')
const css = strip(raw)

const defined = new Set([...strip(theme).matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]))
// The legacy tokens deleted from theme.css in step 13. They must not come back, in the theme or in any stylesheet.
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

describe('app.css: read from disk, whole file, no exempt section', () => {
  it('has real content, the verdict-card rules and the tier rules, and no exemption markers', () => {
    expect(raw.length).toBeGreaterThan(5000)
    expect(css).toContain('.verdict-benign {')
    expect(css).toContain('.tier--none-found {')
    expect(raw).not.toMatch(/not migrated|Phase B: verdict card/i)
  })
})

describe('app.css uses design tokens only, in the whole file', () => {
  it.each(RAW_COLOUR)('contains no %s', (_label, pattern) => {
    expect(css.match(pattern)).toBeNull()
  })

  it('uses only custom properties that theme.css defines, and none of the retired ones', () => {
    const used = [...new Set([...css.matchAll(/var\(\s*(--[\w-]+)/g)].map((m) => m[1]))]
    expect(used.length).toBeGreaterThan(25)
    expect(used.filter((name) => !defined.has(name))).toEqual([])
    expect(used.filter((name) => RETIRED.includes(name))).toEqual([])
  })

  it('theme.css defines none of the retired tokens and carries no "legacy" marker', () => {
    expect(RETIRED.filter((name) => defined.has(name))).toEqual([])
    expect(theme).not.toMatch(/legacy: retire during migration/)
  })

  it('has no green anywhere', () => {
    expect(css).not.toMatch(/green/i)
  })

  it('uses logical properties, not left or right', () => {
    expect(css).not.toMatch(/\b(margin|padding|border)-(left|right)\b/)
    expect(css).not.toMatch(/(^|[;{\s])(left|right)\s*:/)
    expect(css).not.toMatch(/text-align\s*:\s*(left|right)/)
  })

  it('has no animation: no keyframes, and the only transition is the 100ms hover colour change, off under reduced motion', () => {
    expect(css).not.toMatch(/@keyframes|animation\s*:|animation-name/)
    expect([...css.matchAll(/transition\s*:\s*([^;]+);/g)].map((m) => m[1].trim())).toEqual(['border-color 100ms, background-color 100ms', 'none'])
    expect(css).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*transition: none/)
  })

  it('keeps hover neutral and the focus ring on the focus colour, and never removes the outline', () => {
    const hoverRules = [...css.matchAll(/[^{}]*:hover[^{}]*\{[^}]*\}/g)].map((m) => m[0])
    expect(hoverRules.length).toBeGreaterThan(1)
    for (const rule of hoverRules) expect(rule).not.toContain('--focus')
    expect(css).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px solid var\(--focus\)/)
    expect(css).not.toMatch(/outline\s*:\s*(none|0)\b/)
  })

  it('sets buttons at 28px with a neutral control border, and gives the primary action a 2px text-colour border', () => {
    expect(css).toMatch(/\nbutton\s*\{[^}]*min-height:\s*28px[^}]*border:\s*1px solid var\(--border-control\)/)
    expect(css).toMatch(/\.reset-button\s*\{[^}]*border:\s*2px solid var\(--text-primary\)/)
  })

  it('has a forced-colors block that uses system colours only, and covers the tier card', () => {
    const start = css.indexOf('@media (forced-colors: active)')
    expect(start).toBeGreaterThan(-1)
    const block = css.slice(start)
    expect(block).toMatch(/CanvasText/)
    expect(block).toMatch(/Highlight/)
    expect(block).toMatch(/\.tier \{/)
    expect(block).not.toMatch(/var\(--(?!space)/)
  })

  it('keeps the page at 1200px with logical side padding', () => {
    expect(css).toMatch(/\.app-shell\s*\{[^}]*max-width:\s*1200px[^}]*padding-inline:\s*var\(--space-4\)/)
  })
})
