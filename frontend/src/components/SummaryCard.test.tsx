import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SummaryCard } from './SummaryCard'
import { makeAnalysisResult, makeFinding } from '../test/fixtures'
import { readSrc } from '../test/readSource'

const appCss = readSrc('app.css')
const summarySource = readSrc('components/SummaryCard.tsx')

describe('SummaryCard', () => {
  it('renders the verdict, score, and confidence', () => {
    const result = makeAnalysisResult({ verdict: 'suspicious', score: 31, confidence: 1.0 })
    render(<SummaryCard result={result} />)

    expect(screen.getByText('Suspicious')).toBeInTheDocument()
    expect(screen.getByText('31/100')).toBeInTheDocument()
    expect(screen.getByText(/100%/)).toBeInTheDocument()
  })

  it('orders top drivers by contribution descending', () => {
    const result = makeAnalysisResult({
      scoring: {
        categories: [
          { category: 'content_analysis', subscore: 20, weight: 0.25, contribution: 5, coverage: 1, finding_count: 1 },
          { category: 'auth_check', subscore: 75, weight: 0.35, contribution: 26.25, coverage: 1, finding_count: 3 },
          { category: 'enrichment', subscore: 0, weight: 0.4, contribution: 0, coverage: 1, finding_count: 0 },
        ],
        weighted_score: 31.25,
        applied_overrides: [],
      },
    })
    render(<SummaryCard result={result} />)

    const items = screen.getAllByRole('listitem').filter((li) => /pts \(subscore/.test(li.textContent ?? ''))
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent('auth_check')
    expect(items[1]).toHaveTextContent('content_analysis')
  })

  it('shows applied overrides when present', () => {
    const result = makeAnalysisResult({
      scoring: {
        categories: [],
        weighted_score: 8.75,
        applied_overrides: [{ rule: 'auth_check_floor', effect: 'floor=suspicious', reason: 'SPF failed' }],
      },
    })
    render(<SummaryCard result={result} />)

    expect(screen.getByText(/floor=suspicious/)).toBeInTheDocument()
  })
})

describe('SummaryCard: "No indicators found" is neutral and never reassuring (D1)', () => {
  const cssBlock = (selector: string) => {
    const start = appCss.indexOf(selector)
    return appCss.slice(start, appCss.indexOf('}', start) + 1)
  }

  it('has no green, no accent colour and no legacy "legit" colour in its style', () => {
    const block = cssBlock('.verdict-benign {')
    expect(block.length).toBeGreaterThan(40)  // the block was really found
    expect(block).toContain('var(--text-secondary)')
    for (const forbidden of ['--verdict-legit', '--accent-green', '#39ff88', 'green']) expect(block).not.toContain(forbidden)
  })

  it('has no check mark, shield or safe-sounding word anywhere in the component source', () => {
    expect(summarySource.length).toBeGreaterThan(500)
    for (const mark of ['✓', '✔', '☑', '🛡', '✅']) expect(summarySource).not.toContain(mark)
    // whole words only: "not a safety verdict" is the opposite of a safe label
    for (const word of [/\bsafe\b/i, /\bclean\b/i, /\blegit\b/i]) expect(summarySource).not.toMatch(word)
  })

  it('says what the label is and is not, and points at what was not checked', () => {
    render(<SummaryCard result={makeAnalysisResult({ verdict: 'benign' })} />)
    expect(screen.getByText('No indicators found')).toBeInTheDocument()
    expect(screen.getByText(/not a safety verdict/i)).toBeInTheDocument()
    expect(screen.getByText(/what was not checked is listed below/i)).toBeInTheDocument()
    expect(screen.getByText(/never use it to auto-close/i)).toBeInTheDocument()
  })

  it('shows no such note on the other verdicts', () => {
    render(<SummaryCard result={makeAnalysisResult({ verdict: 'suspicious' })} />)
    expect(screen.queryByText(/not a safety verdict/i)).toBeNull()
  })
})

describe('SummaryCard: why', () => {
  it('lists the findings above info severity, at most five, and nothing for info', () => {
    const findings = [
      ...Array.from({ length: 7 }, (_, i) => makeFinding({ severity: 'medium', title: `Finding number ${i}` })),
      makeFinding({ severity: 'info', title: 'Only a note' }),
    ]
    render(<SummaryCard result={makeAnalysisResult({ findings, verdict: 'suspicious' })} />)
    expect(screen.getAllByText(/^medium: Finding number/)).toHaveLength(5)
    expect(screen.queryByText(/Only a note/)).toBeNull()
  })

  it('says plainly when there is nothing above info severity', () => {
    render(<SummaryCard result={makeAnalysisResult({ findings: [makeFinding({ severity: 'info', title: 'note' })] })} />)
    expect(screen.getByText('No finding above info severity.')).toBeInTheDocument()
  })

  it('explains an inconclusive verdict in words, first', () => {
    const base = makeAnalysisResult({ verdict: 'inconclusive', findings: [makeFinding({ severity: 'low', title: 'A signal' })] })
    const scoring = { ...base.scoring!, inconclusive_reason: 'signals_present' }
    render(<SummaryCard result={{ ...base, scoring }} />)
    const items = screen.getAllByRole('listitem').map((li) => li.textContent)
    expect(items.indexOf('Something was flagged, but not enough to call it either way.')).toBeLessThan(items.indexOf('low: A signal'))
  })

  it('renders a hostile finding title as text, never as markup', () => {
    const title = '<img src=x onerror=alert(1)> <script>alert(2)</script>'
    const { container } = render(<SummaryCard result={makeAnalysisResult({ findings: [makeFinding({ severity: 'high', title })] })} />)
    expect(container.querySelector('img, script, iframe')).toBeNull()
    expect(container.textContent).toContain(title)
  })
})
