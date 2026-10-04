import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeCoverageItem, makeEvidence, makeModuleResult } from '../test/fixtures'

describe('ResultsView', () => {
  it('renders a fully clean result with no crashes', () => {
    render(<ResultsView result={makeAnalysisResult()} onReset={vi.fn()} />)
    expect(screen.getByText(/no indicators found/i)).toBeInTheDocument()
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

  it('offers analyst feedback only when it knows the job id', () => {
    const { rerender } = render(<ResultsView result={makeAnalysisResult()} onReset={vi.fn()} />)
    expect(screen.queryByRole('region', { name: 'Analyst feedback' })).not.toBeInTheDocument()

    rerender(<ResultsView result={makeAnalysisResult()} jobId="job1" onReset={vi.fn()} />)
    expect(screen.getByRole('region', { name: 'Analyst feedback' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Agree' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Disagree' })).toBeInTheDocument()
  })

  it('renders an older result that has no evidence or coverage exactly as before, with none of the new panels', () => {
    render(<ResultsView result={makeAnalysisResult()} onReset={vi.fn()} />)
    for (const name of ['Coverage', 'Sender and authentication', 'Links', 'Attachments', 'Body', 'Images', 'Raw headers']) {
      expect(screen.queryByRole('region', { name })).toBeNull()
    }
  })

  it('shows every workbench panel in the wireframe order when the backend sent them', () => {
    const indicators = {
      indicators: [{ kind: 'domain' as const, value: 'evil.example.org', seen_in: ['body'], count: 1, status: 'unknown' as const, note: '', providers: {}, pivots: [], manual_check: false, filename: null }],
      counts: { domain: 1 },
      manual_check_count: 0,
    }
    const result = makeAnalysisResult({ evidence: makeEvidence(), coverage_report: [makeCoverageItem()], schema_version: 2, indicators })
    render(<ResultsView result={result} onReset={vi.fn()} />)
    const order = ['Coverage', 'Sender and authentication', 'Links', 'Attachments', 'Body', 'Images', 'Indicators', 'Raw headers']
    const positions = order.map((name) => screen.getByRole('region', { name }))
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i - 1].compareDocumentPosition(positions[i]) & Node.DOCUMENT_POSITION_FOLLOWING, order[i]).toBeTruthy()
    }
  })

  it('never renders message HTML even when the body text is hostile markup', () => {
    const hostile = '<img src="https://track.example.org/p.gif"><script>alert(1)</script>'
    const base = makeAnalysisResult({ evidence: makeEvidence(), coverage_report: [] })
    const result = { ...base, parsed_email: { ...base.parsed_email, body_text: hostile, body_html: hostile } }
    const { container } = render(<ResultsView result={result} onReset={vi.fn()} />)
    expect(container.querySelector('img, script, iframe, a[href]')).toBeNull()
  })
})
