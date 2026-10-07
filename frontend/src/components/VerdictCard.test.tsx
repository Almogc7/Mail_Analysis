import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ResultsView } from './ResultsView'
import { VerdictCard } from './VerdictCard'
import { indicatorsToCsv, indicatorsToText } from './IndicatorsPanel'
import { makeAnalysisResult, makeBlocker, makeChecks, makeCoverageItem, makeFinding, makeVerdictV2 } from '../test/fixtures'
import { readSrc } from '../test/readSource'
import type { AnalysisResult, VerdictV2 } from '../types'

const appCss = readSrc('app.css')
const cardSource = readSrc('components/VerdictCard.tsx')
const cssBlock = (selector: string) => {
  const start = appCss.indexOf(`${selector} {`)
  return start < 0 ? '' : appCss.slice(start, appCss.indexOf('}', start) + 1)
}

const TIERS: [VerdictV2['tier'], string, string][] = [
  ['confirmed_malicious', 'Confirmed malicious', 'tier--malicious'],
  ['suspicious', 'Suspicious', 'tier--suspicious'],
  ['needs_analyst', 'Needs analyst', 'tier--inconclusive'],
  ['no_indicators_found', 'No indicators found', 'tier--none-found'],
]

function resultFor(tier: VerdictV2['tier'], label: string, overrides: Partial<VerdictV2> = {}, extra: Partial<AnalysisResult> = {}) {
  return makeAnalysisResult({ verdict_v2: makeVerdictV2({ tier, label, ...overrides }), checks_completed: makeChecks(), verdict_v2_status: 'ok', ...extra })
}

const card = () => screen.getByRole('region', { name: 'Verdict' })

describe('VerdictCard: one card per tier (docs/UI_DESIGN.md 8.2)', () => {
  it.each(TIERS)('%s: the written label, its outline class, and the blockers block always present', (tier, label, outline) => {
    render(<VerdictCard result={resultFor(tier, label)} />)
    expect(screen.getByRole('heading', { level: 2, name: label })).toBeInTheDocument()
    expect(card()).toHaveClass('tier', outline)
    const blockers = within(card()).getByRole('group', { name: 'Blockers' })
    expect(within(blockers).getByText('None.')).toBeInTheDocument()  // an explicit "none" line, so its absence is never read as a missing block
  })

  it('shows blockers with their code, detail, text and how to clear them, directly after the label and route', () => {
    const blockers = [
      makeBlocker({ code: 'static_analysis_off', detail: 'pdf', text: 'An attachment of an active or unrecognised type was not examined. (a PDF)', how_to_clear: 'Analyse it in your sandbox.' }),
      makeBlocker(),
    ]
    render(<VerdictCard result={resultFor('needs_analyst', 'Needs analyst', { blockers, needs_analyst_reason: 'signals_present', priority: 41.5 })} />)
    const group = within(card()).getByRole('group', { name: 'Blockers' })
    expect(within(group).getByText('static_analysis_off')).toBeInTheDocument()
    expect(within(group).getByText('detail: pdf')).toBeInTheDocument()
    expect(within(group).getByText(/was not examined/)).toBeInTheDocument()
    expect(within(group).getByText('To clear: Analyse it in your sandbox.')).toBeInTheDocument()
    expect(within(group).queryByText('None.')).toBeNull()
    // the blockers block comes before the reasons and before the priority
    const text = card().textContent ?? ''
    expect(text.indexOf('Blockers')).toBeGreaterThan(text.indexOf('Needs analyst'))
    expect(text.indexOf('Blockers')).toBeLessThan(text.indexOf('Reasons'))
  })

  it('Confirmed malicious lists its hard evidence with the defanged indicator and the source', () => {
    const hard = [{ code: 'H2' as const, indicator: 'hxxps://evil[.]example[.]com/a', source: 'threatfox' }]
    render(<VerdictCard result={resultFor('confirmed_malicious', 'Confirmed malicious', { route: 'HARD_EVIDENCE', hard_evidence: hard })} />)
    expect(screen.getByRole('heading', { name: 'Hard evidence' })).toBeInTheDocument()
    const indicator = screen.getByText('hxxps://evil[.]example[.]com/a')
    expect(indicator).toHaveAttribute('dir', 'auto')
    expect(screen.getByText('threatfox')).toBeInTheDocument()
    expect(screen.getByText(/ThreatFox with a confidence of at least 75/)).toBeInTheDocument()
  })

  it('the other tiers do not show a hard-evidence block', () => {
    render(<VerdictCard result={resultFor('suspicious', 'Suspicious')} />)
    expect(screen.queryByRole('heading', { name: 'Hard evidence' })).toBeNull()
  })

  it('shows the route in plain words, not the route id', () => {
    render(<VerdictCard result={resultFor('suspicious', 'Suspicious', { route: 'R2' })} />)
    expect(screen.getByText('A receiver you trust reported an authentication failure.')).toBeInTheDocument()
    expect(card().textContent).not.toContain('R2')
  })

  it('lists each finding reason with its class and severity and the finding title the page already shows', () => {
    const findings = [
      makeFinding({ module: 'auth_check', severity: 'medium', title: 'Links point at the entity the sender claims to be', evidence: { structural: true, family: 'claim', signal: 'C3' } }),
      makeFinding({ module: 'content_analysis', severity: 'low', title: 'Images hot-linked from a third party that also hosts the links', evidence: { structural: true, family: 'link', signal: 'L2' } }),
    ]
    const reasons = [
      { kind: 'finding' as const, code: 'AUTH_CLAIM_DECOY_LINKS', text: 'registry template', evidence_ref: '0' },
      { kind: 'finding' as const, code: 'CONTENT_LINK_HOTLINKED_ASSETS', text: 'registry template', evidence_ref: '1' },
    ]
    render(<VerdictCard result={resultFor('suspicious', 'Suspicious', { reasons }, { findings })} />)
    const items = within(card()).getAllByRole('listitem')
    const first = items.find((li) => li.textContent?.includes('Links point at the entity'))!
    expect(within(first).getByText('claim')).toBeInTheDocument()  // the class follows the family tag, not the module
    expect(within(first).getByText('medium')).toBeInTheDocument()
    const second = items.find((li) => li.textContent?.includes('Images hot-linked'))!
    expect(within(second).getByText('link')).toBeInTheDocument()
    expect(within(second).getByText('low')).toBeInTheDocument()
  })

  it('shows the evidence conflict reason in its own block when present', () => {
    const reasons = [{ kind: 'evidence_conflict' as const, code: 'evidence_conflict', text: 'A provider flagged an indicator on a domain from your known-sender or own-domain list.' }]
    render(<VerdictCard result={resultFor('suspicious', 'Suspicious', { route: 'R6', reasons })} />)
    const conflict = screen.getByRole('group', { name: 'Evidence conflict' })
    expect(within(conflict).getByText(/known-sender or own-domain list/)).toBeInTheDocument()
  })

  it('Needs analyst: the sub-reason in words and the priority with its exact label; no other tier shows a priority', () => {
    render(<VerdictCard result={resultFor('needs_analyst', 'Needs analyst', { needs_analyst_reason: 'no_signals_insufficient_evidence', priority: 12.34 })} />)
    expect(screen.getByText('Nothing was flagged, and nothing positive was established either.')).toBeInTheDocument()
    expect(screen.getByText(/Queue priority \(ordering aid, not a probability\):/)).toBeInTheDocument()
    expect(screen.getByText('12.3')).toBeInTheDocument()
  })

  it.each(TIERS.filter(([tier]) => tier !== 'needs_analyst'))('%s shows no queue priority even if the API sent one', (tier, label) => {
    render(<VerdictCard result={resultFor(tier, label, { priority: 55 })} />)
    expect(screen.queryByText(/Queue priority/)).toBeNull()
  })

  it.each(TIERS)('%s: no numeric score, no confidence percentage, no "/100"', (tier, label) => {
    render(<VerdictCard result={resultFor(tier, label, {}, { score: 63, confidence: 0.8 })} />)
    expect(card().textContent).not.toMatch(/\/100|Confidence|63|80%/)
  })
})

describe('VerdictCard: "No indicators found" is neutral and never reassuring (D1)', () => {
  const neutral = () => resultFor('no_indicators_found', 'No indicators found', { route: 'T4_POSITIVE_EVIDENCE' })

  it('says "not a safety verdict" in its own element, in the primary text colour, directly in the card', () => {
    render(<VerdictCard result={neutral()} />)
    const sentence = screen.getByText('This is a statement about what was and was not found, not a safety verdict.')
    expect(card()).toContainElement(sentence)
    expect(sentence).toHaveClass('tier-disclaimer')
    expect(cssBlock('.tier-disclaimer')).toMatch(/color:\s*var\(--text-primary\)/)
  })

  it('has no check mark, no shield, no green and no reassuring word in the markup or the style', () => {
    const { container } = render(<VerdictCard result={neutral()} />)
    expect(container.innerHTML).not.toMatch(/[✓✔✅\u{1F6E1}]|<svg|<img/u)
    expect(container.textContent).not.toMatch(/\b(ok|clean|legit|harmless|all clear)\b/i)
    expect(cardSource).not.toMatch(/green|accent|legit/i)
    const style = cssBlock('.tier--none-found') + cssBlock('.tier--none-found .tier-band')
    expect(style).not.toMatch(/green|accent|legit|#/i)
    expect(cssBlock('.tier--none-found')).toMatch(/border:\s*1px dotted var\(--border-control\)/)
  })

  it('its label is no smaller and no lighter than the label of any other tier (one rule for all of them)', () => {
    expect(cssBlock('.tier-label')).toMatch(/font-size:\s*var\(--text-xl\)[^}]*font-weight:\s*700/)
    expect(appCss).not.toMatch(/\.tier--none-found[^{]*\.tier-label/)
  })

  it('shows its blockers block (with "None.") together with the sentence', () => {
    render(<VerdictCard result={neutral()} />)
    expect(within(card()).getByRole('group', { name: 'Blockers' })).toBeInTheDocument()
  })

  it('the other tiers do not carry the neutral-tier sentence', () => {
    render(<VerdictCard result={resultFor('needs_analyst', 'Needs analyst')} />)
    expect(screen.queryByText(/not a safety verdict/)).toBeNull()
  })
})

describe('VerdictCard: the outline styles are the ones in docs/UI_DESIGN.md 8.2', () => {
  it.each([
    ['.tier--malicious', /border:\s*4px solid var\(--verdict-malicious\)/],
    ['.tier--suspicious', /border:\s*3px solid var\(--verdict-suspicious\)/],
    ['.tier--inconclusive', /border:\s*2px dashed var\(--verdict-inconclusive\)/],
    ['.tier--none-found', /border:\s*1px dotted var\(--border-control\)/],
  ])('%s', (selector, expected) => {
    expect(cssBlock(selector)).toMatch(expected)
  })

  it('the bands: filled for Confirmed malicious, tint for Suspicious and Needs analyst, muted for the neutral tier', () => {
    expect(cssBlock('.tier--malicious .tier-band')).toMatch(/background:\s*var\(--verdict-malicious\);\s*color:\s*var\(--bg-root\)/)
    expect(cssBlock('.tier--suspicious .tier-band')).toMatch(/var\(--verdict-suspicious-tint\)/)
    expect(cssBlock('.tier--inconclusive .tier-band')).toMatch(/var\(--verdict-inconclusive-tint\)/)
    expect(cssBlock('.tier--none-found .tier-band')).toMatch(/var\(--bg-muted\)/)
  })

  it('keeps the outline in forced-colors mode, with a double rule for the filled band', () => {
    const forced = appCss.slice(appCss.indexOf('@media (forced-colors: active)'))
    expect(forced).toMatch(/\.tier \{ border-color: CanvasText; \}/)
    expect(forced).toMatch(/\.tier--malicious \.tier-band \{[^}]*4px double CanvasText/)
  })
})

describe('VerdictCard: unavailable and old-shape results', () => {
  const unavailable = () =>
    makeAnalysisResult({
      verdict: 'malicious',
      score: 80,
      verdict_v2: null,
      verdict_v2_status: 'unavailable',
      coverage_report: [
        makeCoverageItem({ area: 'Verdict v2', status: 'not_checked', reason: 'verdict_v2_unavailable', how_to_clear: 'Look at the console log for the cause, then analyse the message again.', detail: '' }),
      ],
    })

  it('shows a neutral "Verdict unavailable" card with the coverage item reason and no tier and no v1 label', () => {
    const { container } = render(<VerdictCard result={unavailable()} />)
    expect(screen.getByRole('heading', { level: 2, name: 'Verdict unavailable' })).toBeInTheDocument()
    expect(card()).toHaveClass('tier--unavailable')
    expect(within(card()).getByText('verdict_v2_unavailable')).toBeInTheDocument()
    expect(within(card()).getByText(/Look at the console log for the cause/)).toBeInTheDocument()
    for (const label of ['Confirmed malicious', 'Suspicious', 'Needs analyst', 'No indicators found', 'Malicious', 'Inconclusive']) expect(container.textContent).not.toContain(label)
    expect(container.querySelector('.verdict-banner, .verdict-label, .score-label, [class*="verdict-malicious"]')).toBeNull()
    expect(container.querySelector('[class*="tier--malicious"], [class*="tier--suspicious"], [class*="tier--inconclusive"], [class*="tier--none-found"]')).toBeNull()
  })

  it('an unavailable status without a coverage item still shows the card and the reason code', () => {
    render(<VerdictCard result={makeAnalysisResult({ verdict: 'benign', verdict_v2: null, verdict_v2_status: 'unavailable', coverage_report: null })} />)
    expect(screen.getByRole('heading', { name: 'Verdict unavailable' })).toBeInTheDocument()
    expect(screen.getByText('verdict_v2_unavailable')).toBeInTheDocument()
  })

  it('an OLD-shape result (no verdict_v2 and no status field) still renders the old v1 card', () => {
    const old = makeAnalysisResult({ verdict: 'suspicious', score: 31 })
    expect('verdict_v2' in old || 'verdict_v2_status' in old).toBe(false)
    const { container } = render(<VerdictCard result={old} />)
    expect(container.querySelector('.verdict-banner')).not.toBeNull()
    expect(screen.getByText('31/100')).toBeInTheDocument()
  })

  it('a stored job whose status field is explicitly null is also the old shape', () => {
    const { container } = render(<VerdictCard result={makeAnalysisResult({ verdict: 'benign', verdict_v2: null, verdict_v2_status: null })} />)
    expect(container.querySelector('.verdict-banner')).not.toBeNull()
  })
})

describe('V13: with verdict_v2 present the v1 verdict is nowhere on the page or in the exports', () => {
  const demoted = () =>
    makeAnalysisResult({
      verdict: 'malicious',
      score: 83,
      confidence: 0.9,
      scoring: {
        categories: [{ category: 'enrichment', subscore: 100, weight: 0.4, contribution: 40, coverage: 1, finding_count: 1 }],
        weighted_score: 83,
        applied_overrides: [{ rule: 'enrichment_floor', effect: 'floor=suspicious', reason: 'a provider score of 70 or more' }],
      },
      verdict_v2: makeVerdictV2({ tier: 'suspicious', label: 'Suspicious', route: 'R3B' }),
      checks_completed: makeChecks(),
      verdict_v2_status: 'ok',
    })

  it('renders no v1 verdict element, label, score, confidence or override, by element and field', () => {
    const { container } = render(<ResultsView result={demoted()} onReset={vi.fn()} />)
    expect(container.querySelector('.verdict-banner')).toBeNull()
    expect(container.querySelector('.verdict-label')).toBeNull()
    expect(container.querySelector('.score-label')).toBeNull()
    expect(container.querySelector('.confidence-line')).toBeNull()
    expect(container.querySelector('.applied-overrides')).toBeNull()
    expect(container.querySelector('[class*="verdict-malicious"], [class*="verdict-benign"], [class*="verdict-inconclusive"], [class*="verdict-suspicious"]')).toBeNull()
    // no element anywhere carries the v1 value as an attribute, and no element is the v1 label
    expect([...container.querySelectorAll('*')].filter((el) => ['malicious', 'verdict-malicious', 'Malicious'].includes(el.getAttribute('data-verdict') ?? ''))).toEqual([])
    expect([...container.querySelectorAll('*')].filter((el) => el.children.length === 0 && ['Malicious', 'malicious', 'Inconclusive: analyst review', 'benign'].includes((el.textContent ?? '').trim()))).toEqual([])
    expect(container.textContent).not.toMatch(/83\/100|floor=suspicious|Overrides applied|Top drivers/)
    expect(screen.getByRole('heading', { level: 2, name: 'Suspicious' })).toBeInTheDocument()
  })

  it('renders the v2 label in the verdict card', () => {
    render(<ResultsView result={demoted()} onReset={vi.fn()} />)
    expect(within(card()).getByRole('heading', { name: 'Suspicious' })).toBeInTheDocument()
  })

  it('the indicator copy and CSV exports have no verdict column or value', () => {
    const indicators = [{ kind: 'domain' as const, value: 'evil.example.com', seen_in: ['body'], count: 1, status: 'provider_hit' as const, note: '', providers: {}, pivots: [], manual_check: false, filename: null }]
    const csv = indicatorsToCsv(indicators, true)
    expect(csv.split('\n')[0]).toBe('kind,indicator,status,manual_check,seen_in,count,note')
    expect(csv.toLowerCase()).not.toContain('verdict')
    expect(indicatorsToText(indicators, true).toLowerCase()).not.toContain('verdict')
  })
})

describe('VerdictCard: Hebrew and mixed text (dir="auto" on everything that can show message content)', () => {
  const hebrewTitle = 'חשבונית מס מזויפת לכאורה'
  const result = () =>
    resultFor(
      'suspicious',
      'Suspicious',
      {
        reasons: [{ kind: 'finding', code: 'CONTENT_URGENCY_LANGUAGE', text: 'registry template', evidence_ref: '0' }],
        blockers: [makeBlocker({ text: `${hebrewTitle} (a PDF)`, how_to_clear: `בדקו ידנית: ${hebrewTitle}` })],
        hard_evidence: [],
      },
      { findings: [makeFinding({ module: 'content_analysis', severity: 'medium', title: hebrewTitle })] },
    )

  it('puts dir="auto" on every reason and every blocker and on the text inside them', () => {
    render(<VerdictCard result={result()} />)
    const items = within(card()).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    for (const li of items) {
      expect(li).toHaveAttribute('dir', 'auto')
      for (const span of li.querySelectorAll('.wb-text, .wb-small')) expect(span).toHaveAttribute('dir', 'auto')
    }
  })

  it('renders the Hebrew text exactly, as plain text, in the reason and in the blocker', () => {
    render(<VerdictCard result={result()} />)
    expect(within(card()).getByText(hebrewTitle)).toBeInTheDocument()
    expect(within(card()).getByText(`${hebrewTitle} (a PDF)`)).toBeInTheDocument()
    expect(within(card()).getByText(`To clear: בדקו ידנית: ${hebrewTitle}`)).toBeInTheDocument()
  })

  it('keeps the chrome (the label, the headings) left to right: no dir on them', () => {
    render(<VerdictCard result={result()} />)
    expect(screen.getByRole('heading', { level: 2, name: 'Suspicious' })).not.toHaveAttribute('dir')
    expect(screen.getByRole('heading', { name: 'Reasons' })).not.toHaveAttribute('dir')
  })
})
