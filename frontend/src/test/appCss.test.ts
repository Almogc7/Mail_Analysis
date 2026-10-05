import { describe, expect, it } from 'vitest'
import { readSrc } from './readSource'

/**
 * app.css is migrated to the design tokens (docs/UI_DESIGN.md) everywhere except ONE marked section: the verdict card, which Phase B rewrites. This test
 * reads the stylesheet from disk (vitest returns an empty string for an imported .css), cuts out the marked section, drops comments, and fails if the rest
 * has a raw colour (hex, rgb, hsl, lab, a named colour), a color-mix(), a remote url() or @import, a legacy or undefined token, a physical left/right
 * property, a drifting motion or hover rule, or a removed focus ring. It also pins what the exempt section may contain, so the exemption cannot grow
 * to hide a violation.
 */
const raw = readSrc('app.css')
const theme = readSrc('theme.css')
const strip = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, '')

const START = 'Phase B: verdict card, not migrated (start)'
const END = 'Phase B: verdict card, not migrated (end)'
const startAt = raw.indexOf(START)
const endAt = raw.indexOf(END)
const marked = startAt >= 0 && endAt > startAt
// the section runs from the opening of the start comment to the close of the end comment
const sectionFrom = marked ? raw.lastIndexOf('/*', startAt) : -1
const sectionTo = marked ? raw.indexOf('*/', endAt) + 2 : -1
const section = marked ? raw.slice(sectionFrom, sectionTo) : ''
const outside = strip(marked ? raw.slice(0, sectionFrom) + raw.slice(sectionTo) : raw)

const defined = new Set([...strip(theme).matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]))
const legacy = new Set([...theme.matchAll(/legacy: retire during migration[^\n]*\n\s*(--[\w-]+)\s*:/g)].map((m) => m[1]))

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

describe('app.css: the marked verdict-card section', () => {
  it('is marked exactly once, with both markers, and the file is read from disk with real content', () => {
    expect(raw.length).toBeGreaterThan(5000)
    expect(raw.split(START)).toHaveLength(2)
    expect(raw.split(END)).toHaveLength(2)
    expect(endAt).toBeGreaterThan(startAt)
    expect(section).toContain('.verdict-benign {')
    expect(outside.length).toBeGreaterThan(5000)
  })

  it('holds only the verdict card, the Why list, top drivers, overrides and the neutral-tier note', () => {
    const selectors = [...strip(section).matchAll(/([^{}]+)\{/g)].map((m) => m[1].replace(/\s+/g, ' ').trim())
    expect(selectors).toEqual([
      '.verdict-banner',
      '.verdict-malicious',
      '.verdict-suspicious',
      '.verdict-inconclusive',
      '.verdict-benign',
      '.why-list ul',
      '.confidence-line',
      '.top-drivers-heading, .overrides-heading, .raw-data-heading',
      '.top-drivers ul, .applied-overrides ul',
      '.benign-note',
    ])
  })
})

describe('app.css outside the verdict-card section uses design tokens only', () => {
  it.each(RAW_COLOUR)('contains no %s', (_label, pattern) => {
    expect(outside.match(pattern)).toBeNull()
  })

  it('uses only custom properties that theme.css defines, and none of the legacy ones', () => {
    const used = [...new Set([...outside.matchAll(/var\(\s*(--[\w-]+)/g)].map((m) => m[1]))]
    expect(used.length).toBeGreaterThan(25)
    expect(used.filter((name) => !defined.has(name))).toEqual([])
    expect(used.filter((name) => legacy.has(name))).toEqual([])
    expect(legacy.has('--accent-green')).toBe(true)  // the legacy list was really read
  })

  it('has no green anywhere outside the verdict card', () => {
    expect(outside).not.toMatch(/green/i)
  })

  it('uses logical properties, not left or right', () => {
    expect(outside).not.toMatch(/\b(margin|padding|border)-(left|right)\b/)
    expect(outside).not.toMatch(/(^|[;{\s])(left|right)\s*:/)
    expect(outside).not.toMatch(/text-align\s*:\s*(left|right)/)
  })

  it('has no animation: no keyframes, and the only transition is the 100ms hover colour change, off under reduced motion', () => {
    expect(outside).not.toMatch(/@keyframes|animation\s*:|animation-name/)
    expect([...outside.matchAll(/transition\s*:\s*([^;]+);/g)].map((m) => m[1].trim())).toEqual(['border-color 100ms, background-color 100ms', 'none'])
    expect(outside).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*transition: none/)
  })

  it('keeps hover neutral and the focus ring on the focus colour, and never removes the outline', () => {
    const hoverRules = [...outside.matchAll(/[^{}]*:hover[^{}]*\{[^}]*\}/g)].map((m) => m[0])
    expect(hoverRules.length).toBeGreaterThan(1)
    for (const rule of hoverRules) expect(rule).not.toContain('--focus')
    expect(outside).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px solid var\(--focus\)/)
    expect(outside).not.toMatch(/outline\s*:\s*(none|0)\b/)
  })

  it('sets buttons at 28px with a neutral control border, and gives the primary action a 2px text-colour border', () => {
    expect(outside).toMatch(/\nbutton\s*\{[^}]*min-height:\s*28px[^}]*border:\s*1px solid var\(--border-control\)/)
    expect(outside).toMatch(/\.reset-button\s*\{[^}]*border:\s*2px solid var\(--text-primary\)/)
  })

  it('has a forced-colors block that uses system colours only', () => {
    const start = outside.indexOf('@media (forced-colors: active)')
    expect(start).toBeGreaterThan(-1)
    const block = outside.slice(start)
    expect(block).toMatch(/CanvasText/)
    expect(block).toMatch(/Highlight/)
    expect(block).not.toMatch(/var\(--(?!space)/)
  })

  it('keeps the page at 1200px with logical side padding', () => {
    expect(outside).toMatch(/\.app-shell\s*\{[^}]*max-width:\s*1200px[^}]*padding-inline:\s*var\(--space-4\)/)
  })
})
