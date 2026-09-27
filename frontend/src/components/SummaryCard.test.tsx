import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SummaryCard } from './SummaryCard'
import { makeAnalysisResult } from '../test/fixtures'

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

    const items = screen.getAllByRole('listitem')
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
