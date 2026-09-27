import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeModuleResult } from '../test/fixtures'

describe('ResultsView', () => {
  it('renders a fully clean result with no crashes', () => {
    render(<ResultsView result={makeAnalysisResult()} onReset={vi.fn()} />)
    expect(screen.getByText(/legit/i)).toBeInTheDocument()
  })

  it('renders an unavailable llm_opinion distinctly, not silently', () => {
    const result = makeAnalysisResult({
      llm_opinion: { narrative: '', flags: [], model: 'gemini-flash-latest', status: 'unavailable', error: 'GOOGLE_API_KEY is not configured' },
    })
    render(<ResultsView result={result} onReset={vi.fn()} />)

    expect(screen.getByText(/GOOGLE_API_KEY is not configured/)).toBeInTheDocument()
  })

  it('still renders the other modules when one has status=error', () => {
    const result = makeAnalysisResult({
      module_results: [
        makeModuleResult({ module: 'auth_check', status: 'ok' }),
        makeModuleResult({ module: 'enrichment', status: 'error', raw_data: { error: 'boom' } }),
        makeModuleResult({ module: 'content_analysis', status: 'ok' }),
      ],
    })
    render(<ResultsView result={result} onReset={vi.fn()} />)

    expect(screen.getByText(/this check could not run: boom/i)).toBeInTheDocument()
    expect(screen.getAllByText('No findings.')).toHaveLength(2)
  })
})
