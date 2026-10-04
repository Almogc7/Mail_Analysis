import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { FindingsByFamily, familyOf } from './FindingsByFamily'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeFinding } from '../test/fixtures'

const f = (title: string, module: string, severity = 'medium', evidence: Record<string, unknown> = {}) =>
  makeFinding({ title, module: module as never, severity: severity as never, evidence })

describe('familyOf: the same tags the verdict floors read', () => {
  it('uses the structural family tag first, whatever module produced the finding', () => {
    expect(familyOf(f('x', 'auth_check', 'medium', { structural: true, family: 'claim', signal: 'C1' }))).toBe('claim')
    expect(familyOf(f('x', 'auth_check', 'medium', { structural: true, family: 'sender', signal: 'S1' }))).toBe('sender')
    expect(familyOf(f('x', 'content_analysis', 'low', { structural: true, family: 'link', signal: 'L1' }))).toBe('link')
  })

  it('falls back to the module for findings that carry no family', () => {
    expect(familyOf(f('x', 'auth_check'))).toBe('auth')
    expect(familyOf(f('x', 'enrichment'))).toBe('reputation')
    expect(familyOf(f('x', 'content_analysis'))).toBe('content')
  })

  it('ignores a tag that is not one of the three floor families', () => {
    expect(familyOf(f('x', 'content_analysis', 'low', { family: 'something-else' }))).toBe('content')
    expect(familyOf(f('x', 'auth_check', 'low', { family: 'something-else' }))).toBe('auth')
  })
})

describe('FindingsByFamily', () => {
  const findings = [
    f('SPF check failed', 'auth_check', 'high'),
    f('Machine-provisioned sender', 'auth_check', 'medium', { structural: true, family: 'sender', signal: 'S1' }),
    f('Display-name spoof', 'auth_check', 'medium', { structural: true, family: 'claim', signal: 'C1' }),
    f('Click tracker mismatch', 'content_analysis', 'low', { structural: true, family: 'link', signal: 'L1' }),
    f('Urgency language', 'content_analysis', 'low'),
    f('Suspicious host: x.example', 'enrichment', 'low'),
  ]

  it('shows every finding exactly once, grouped by family', () => {
    render(<FindingsByFamily findings={findings} />)
    const groups = Object.fromEntries(
      ['Sender', 'Links', 'Claims', 'Content', 'Authentication', 'Reputation lookups'].map((t) => [t, screen.getByRole('group', { name: `${t} findings` })]),
    )
    expect(within(groups['Sender']).getByText('Machine-provisioned sender')).toBeInTheDocument()
    expect(within(groups['Links']).getByText('Click tracker mismatch')).toBeInTheDocument()
    expect(within(groups['Claims']).getByText('Display-name spoof')).toBeInTheDocument()
    expect(within(groups['Content']).getByText('Urgency language')).toBeInTheDocument()
    expect(within(groups['Authentication']).getByText('SPF check failed')).toBeInTheDocument()
    expect(within(groups['Reputation lookups']).getByText('Suspicious host: x.example')).toBeInTheDocument()
    for (const finding of findings) expect(screen.getAllByText(finding.title)).toHaveLength(1)
  })

  it('names the families whose structural signals fired, and says one family alone never raises the verdict', () => {
    render(<FindingsByFamily findings={findings} />)
    expect(screen.getByText(/Structural signals fired in: sender, link, claim\./)).toBeInTheDocument()
    expect(screen.getByText(/one family alone never raises the verdict/)).toBeInTheDocument()
  })

  it('says so when no structural signal fired, and does not count a tag on a non-structural finding', () => {
    render(<FindingsByFamily findings={[f('Urgency language', 'content_analysis', 'low', { family: 'claim' })]} />)
    expect(screen.getByText(/No structural signal fired in the sender, link or claim families\./)).toBeInTheDocument()
  })

  it('lists the most severe finding first inside a family', () => {
    render(<FindingsByFamily findings={[f('low one', 'auth_check', 'low'), f('high one', 'auth_check', 'high'), f('info one', 'auth_check', 'info'), f('medium one', 'auth_check', 'medium')]} />)
    const titles = within(screen.getByRole('group', { name: 'Authentication findings' })).getAllByText(/ one$/).map((e) => e.textContent)
    expect(titles).toEqual(['high one', 'medium one', 'low one', 'info one'])
  })

  it('omits empty families and renders nothing for a result without findings', () => {
    const { container, rerender } = render(<FindingsByFamily findings={[f('only this', 'auth_check')]} />)
    expect(screen.queryByRole('group', { name: 'Links findings' })).toBeNull()
    rerender(<FindingsByFamily findings={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('does not change the findings it was given', () => {
    const before = JSON.stringify(findings)
    render(<FindingsByFamily findings={findings} />)
    expect(JSON.stringify(findings)).toBe(before)
  })

  it('renders hostile finding text as text', () => {
    const hostile = '<img src=x onerror=alert(1)>'
    const { container } = render(<FindingsByFamily findings={[f(hostile, 'content_analysis')]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })
})

describe('ResultsView keeps the per-module detail next to the family view', () => {
  it('shows the family panel before the coverage panel and still lists the findings under their modules', () => {
    const result = makeAnalysisResult({
      findings: [f('SPF check failed', 'auth_check', 'high')],
      module_results: [
        { module: 'auth_check', status: 'ok', findings: [f('SPF check failed', 'auth_check', 'high')], raw_data: null },
        { module: 'enrichment', status: 'ok', findings: [], raw_data: null },
        { module: 'content_analysis', status: 'ok', findings: [], raw_data: null },
      ],
      coverage_report: [],
      evidence: undefined,
    })
    render(<ResultsView result={result} onReset={vi.fn()} />)
    expect(screen.getByRole('heading', { name: 'Detail by module' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Findings by family' })).toBeInTheDocument()
    expect(screen.getAllByText('SPF check failed')).toHaveLength(2) // once in the family view, once in its module
    const family = screen.getByRole('region', { name: 'Findings by family' })
    const coverage = screen.getByRole('region', { name: 'Coverage' })
    expect(family.compareDocumentPosition(coverage) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})
