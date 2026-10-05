import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { FindingItem } from './FindingItem'
import { FindingsByFamily } from './FindingsByFamily'
import { LlmOpinionCard } from './LlmOpinionCard'
import { ModuleDetailSection } from './ModuleDetailSection'
import { ModulePanel } from './ModulePanel'
import { ResultsView } from './ResultsView'
import { UploadView } from './UploadView'
import { lowerSeverityNote, startsExpanded } from './findingRules'
import { makeAnalysisResult, makeFinding, makeModuleResult } from '../test/fixtures'
import type { Finding, Severity } from '../types'

const HEBREW = 'חשבונית חודשית לתשלום'
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const finding = (severity: Severity, over: Partial<Finding> = {}): Finding =>
  makeFinding({ severity, title: `${severity} title`, description: `${severity} description`, evidence: { key: `${severity} evidence` }, ...over })

describe('FindingItem: medium, high and critical start expanded; low and info start collapsed', () => {
  it.each(['medium', 'high', 'critical'] as Severity[])('%s starts expanded with its description and evidence visible', (severity) => {
    render(<FindingItem finding={finding(severity)} />)
    const header = screen.getByRole('button', { name: new RegExp(`${severity} title`) })
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(`${severity} description`)).toBeInTheDocument()
    expect(screen.getByText(`${severity} evidence`)).toBeInTheDocument()
  })

  it.each(['low', 'info'] as Severity[])('%s starts collapsed: the header (severity and title) is there, the body is not', (severity) => {
    render(<FindingItem finding={finding(severity)} />)
    const header = screen.getByRole('button', { name: new RegExp(`${severity} title`) })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(header).toHaveTextContent(severity)
    expect(screen.queryByText(`${severity} description`)).toBeNull()
    expect(screen.queryByText(`${severity} evidence`)).toBeNull()
  })

  it('opens and closes with its real button, whatever the starting state', () => {
    render(<FindingItem finding={finding('low')} />)
    const header = screen.getByRole('button')
    fireEvent.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('low description')).toBeInTheDocument()
    fireEvent.click(header)
    expect(screen.queryByText('low description')).toBeNull()
    const open = render(<FindingItem finding={finding('high')} />)
    fireEvent.click(within(open.container).getByRole('button'))
    expect(within(open.container).queryByText('high description')).toBeNull()
  })

  it('a collapsed finding without evidence can still be opened to read its description (the button is never disabled)', () => {
    render(<FindingItem finding={finding('info', { evidence: {} })} />)
    const header = screen.getByRole('button')
    expect(header).not.toBeDisabled()
    fireEvent.click(header)
    expect(screen.getByText('info description')).toBeInTheDocument()
  })

  it('keeps dir="auto" on a Hebrew low-severity finding once opened, and on a Hebrew high one that starts open', () => {
    const low = render(<FindingItem finding={finding('low', { title: `${HEBREW} low`, description: `${HEBREW} desc`, evidence: { subject: `${HEBREW} ev` } })} />)
    expect(screen.getByText(`${HEBREW} low`)).toHaveAttribute('dir', 'auto')  // the title is in the header, so it is there while collapsed
    fireEvent.click(screen.getByRole('button'))
    for (const part of ['desc', 'ev']) expect(screen.getByText(`${HEBREW} ${part}`)).toHaveAttribute('dir', 'auto')
    low.unmount()
    render(<FindingItem finding={finding('high', { title: `${HEBREW} high`, description: `${HEBREW} hdesc`, evidence: { subject: `${HEBREW} hev` } })} />)
    for (const part of ['high', 'hdesc', 'hev']) expect(screen.getByText(`${HEBREW} ${part}`)).toHaveAttribute('dir', 'auto')
  })

  it('has one pure rule for the starting state and for the count line', () => {
    expect(SEVERITIES.map(startsExpanded)).toEqual([true, true, true, false, false])
    expect(lowerSeverityNote([finding('high')])).toBeNull()
    expect(lowerSeverityNote([finding('low')])).toBe('1 lower-severity finding (low or info) starts collapsed')
    expect(lowerSeverityNote([finding('low'), finding('info'), finding('critical')])).toBe('2 lower-severity findings (low or info) start collapsed')
  })
})

describe('the family panel keeps every finding, in the same order, and says how many start collapsed', () => {
  // Same family (auth), severities out of order on purpose: the panel sorts most severe first, as it did before.
  const findings = [finding('info', { title: 'a-info' }), finding('critical', { title: 'b-critical' }), finding('low', { title: 'c-low' }), finding('high', { title: 'd-high' }), finding('medium', { title: 'e-medium' })]

  it('lists all five in the existing order, with the lower ones collapsed and the others open', () => {
    render(<FindingsByFamily findings={findings} />)
    const headers = screen.getAllByRole('button')
    expect(headers.map((h) => (h.querySelector('.finding-title') as HTMLElement).textContent)).toEqual(['b-critical', 'd-high', 'e-medium', 'c-low', 'a-info'])
    expect(headers.map((h) => h.getAttribute('aria-expanded'))).toEqual(['true', 'true', 'true', 'false', 'false'])
    expect(screen.getByText('2 lower-severity findings (low or info) start collapsed')).toBeInTheDocument()
  })

  it('shows no count line when nothing starts collapsed', () => {
    render(<FindingsByFamily findings={[finding('high')]} />)
    expect(screen.queryByText(/lower-severity/)).toBeNull()
  })
})

describe('Detail by module', () => {
  it('shows the count line for the findings that start collapsed, and keeps every finding header', () => {
    const module = makeModuleResult({ findings: [finding('high', { title: 'h' }), finding('low', { title: 'l' }), finding('info', { title: 'i' })] })
    render(<ModulePanel result={module} />)
    expect(screen.getByText('2 lower-severity findings (low or info) start collapsed')).toBeInTheDocument()
    expect(screen.getAllByRole('button').filter((b) => b.classList.contains('finding-header'))).toHaveLength(3)
  })

  it('says "ran" for a module that finished and "error" for one that failed', () => {
    const { container, rerender } = render(<ModulePanel result={makeModuleResult({ status: 'ok', findings: [] })} />)
    expect(container.querySelector('.module-status')).toHaveTextContent(/^ran$/)
    expect(screen.queryByText('ok')).toBeNull()
    rerender(<ModulePanel result={makeModuleResult({ status: 'error', raw_data: { error: 'boom' }, findings: [] })} />)
    expect(container.querySelector('.module-status')).toHaveTextContent(/^error$/)
  })

  it('applies the same defaults inside the opened section of the results view', () => {
    const result = makeAnalysisResult({ findings: [], module_results: [makeModuleResult({ module: 'auth_check', findings: [finding('low', { title: 'quiet' })] })] })
    render(<ResultsView result={result} onReset={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /^Detail by module/ }))
    expect(screen.getByRole('button', { name: /quiet/ })).toHaveAttribute('aria-expanded', 'false')
  })

  it('still renders through the section component on its own', () => {
    render(<ModuleDetailSection modules={[makeModuleResult({ findings: [finding('medium', { title: 'mid' })] })]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Detail by module (1)' }))
    expect(screen.getByRole('button', { name: /mid/ })).toHaveAttribute('aria-expanded', 'true')
  })
})

describe('the AI opinion card', () => {
  const opinion = { narrative: `${HEBREW} narrative`, flags: [`${HEBREW} flag`], model: 'm', status: 'ok' as const, error: null }

  it('is labelled "AI opinion, not a verdict" and the old label is gone', () => {
    render(<LlmOpinionCard opinion={opinion} />)
    expect(screen.getByText('AI opinion, not a verdict')).toBeInTheDocument()
    expect(screen.queryByText('AI-generated commentary')).toBeNull()
  })

  it('keeps Hebrew text readable: the narrative and each flag carry dir="auto"', () => {
    render(<LlmOpinionCard opinion={opinion} />)
    expect(screen.getByText(`${HEBREW} narrative`)).toHaveAttribute('dir', 'auto')
    expect(screen.getByText(`${HEBREW} flag`)).toHaveAttribute('dir', 'auto')
  })
})

describe('the upload form', () => {
  it('has a visible label tied to the file input', () => {
    render(<UploadView onSubmit={vi.fn()} submitting={false} submitError={null} />)
    const input = screen.getByLabelText('Email file (.eml or .msg)')
    expect(input).toHaveAttribute('type', 'file')
    expect(screen.getByText('Email file (.eml or .msg)').tagName).toBe('LABEL')
  })
})
