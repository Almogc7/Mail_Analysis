import { fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ResultsView } from './ResultsView'
import { RawHeadersPanel } from './RawHeadersPanel'
import { makeAnalysisResult, makeCoverageItem, makeEvidence, makeFinding } from '../test/fixtures'
import type { AnalysisResult } from '../types'

const HEBREW = 'חשבונית חודשית לתשלום'
const indicators = {
  indicators: [{ kind: 'domain' as const, value: 'evil.example.org', seen_in: ['body'], count: 1, status: 'unknown' as const, note: '', providers: {}, pivots: [], manual_check: true, filename: null }],
  counts: { domain: 1 },
  manual_check_count: 1,
}
const full = (): AnalysisResult => {
  const base = makeAnalysisResult({ findings: [makeFinding()], evidence: makeEvidence(), coverage_report: [makeCoverageItem()], schema_version: 2, indicators })
  return { ...base, parsed_email: { ...base.parsed_email, headers: [{ name: 'X-Test', value: 'ok' }] } }
}

const LABELS = ['Findings', 'Coverage', 'Sender', 'Links', 'Attachments', 'Body', 'Indicators', 'Raw headers']
const PANELS = ['Findings by family', 'Coverage', 'Sender and authentication', 'Links', 'Attachments', 'Body', 'Indicators', 'Raw headers']
const nav = () => screen.getByRole('navigation', { name: 'Jump to a panel' })

let scroll: ReturnType<typeof vi.fn>

beforeEach(() => {
  scroll = vi.fn()
  Element.prototype.scrollIntoView = scroll as unknown as typeof Element.prototype.scrollIntoView  // jsdom does not implement it
})
afterEach(() => {
  vi.unstubAllGlobals()
  delete (Element.prototype as Partial<Element>).scrollIntoView
})

describe('jump row', () => {
  it('is a row of real buttons, one per panel, placed under the verdict and above the findings', () => {
    const { container } = render(<ResultsView result={full()} onReset={vi.fn()} />)
    const buttons = within(nav()).getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual(LABELS)
    for (const b of buttons) {
      expect(b.tagName).toBe('BUTTON')
      expect(b).toHaveAttribute('type', 'button')
      expect(b).not.toHaveAttribute('tabindex', '-1')  // in the tab order, so the keyboard reaches it
    }
    expect(nav().querySelector('a, [href]')).toBeNull()  // buttons only, never links
    const verdict = container.querySelector('.summary-card')!
    const findings = screen.getByRole('region', { name: 'Findings by family' })
    expect(verdict.compareDocumentPosition(nav()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(nav().compareDocumentPosition(findings) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it.each(LABELS.map((label, i) => [label, PANELS[i]]))('"%s" scrolls its panel into view and moves focus to the panel heading', (label, panel) => {
    render(<ResultsView result={full()} onReset={vi.fn()} />)
    fireEvent.click(within(nav()).getByRole('button', { name: label }))
    const section = screen.getByRole('region', { name: panel })
    const heading = section.querySelector('h2')!
    expect(scroll).toHaveBeenCalledTimes(1)
    expect(scroll.mock.instances[0]).toBe(section)
    expect(heading).toHaveAttribute('tabindex', '-1')
    expect(document.activeElement).toBe(heading)
  })

  it('scrolls smoothly normally and with behavior "auto" when the reader prefers reduced motion', () => {
    const query = (matches: boolean) => vi.stubGlobal('matchMedia', (q: string) => ({ matches: matches && q.includes('prefers-reduced-motion'), media: q, addEventListener() {}, removeEventListener() {} }))
    query(false)
    const first = render(<ResultsView result={full()} onReset={vi.fn()} />)
    fireEvent.click(within(nav()).getByRole('button', { name: 'Links' }))
    expect(scroll).toHaveBeenLastCalledWith(expect.objectContaining({ behavior: 'smooth' }))
    first.unmount()
    query(true)
    render(<ResultsView result={full()} onReset={vi.fn()} />)
    fireEvent.click(within(nav()).getByRole('button', { name: 'Links' }))
    expect(scroll).toHaveBeenLastCalledWith(expect.objectContaining({ behavior: 'auto' }))
  })

  it('opens the raw headers panel when it is collapsed, then focuses its heading', () => {
    render(<ResultsView result={full()} onReset={vi.fn()} />)
    expect(screen.queryByLabelText('Header text')).toBeNull()
    const toggle = screen.getByRole('button', { name: 'Show headers' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(within(nav()).getByRole('button', { name: 'Raw headers' }))
    expect(screen.getByRole('button', { name: 'Hide headers' })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByLabelText('Header text')).toBeInTheDocument()
    expect(document.activeElement).toBe(screen.getByRole('region', { name: 'Raw headers' }).querySelector('h2'))
  })

  it('leaves an already-open raw headers panel open and still lets the reader close it afterwards', () => {
    render(<ResultsView result={full()} onReset={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    fireEvent.click(within(nav()).getByRole('button', { name: 'Raw headers' }))
    expect(screen.getByLabelText('Header text')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Hide headers' }))
    expect(screen.queryByLabelText('Header text')).toBeNull()
  })

  it('lists only the panels the result has: none for an older result, no evidence panels without evidence', () => {
    const { rerender } = render(<ResultsView result={makeAnalysisResult()} onReset={vi.fn()} />)
    expect(screen.queryByRole('navigation', { name: 'Jump to a panel' })).toBeNull()  // no findings, no coverage, no evidence, no indicators
    rerender(<ResultsView result={makeAnalysisResult({ findings: [makeFinding()], coverage_report: [], indicators })} onReset={vi.fn()} />)
    expect(within(nav()).getAllByRole('button').map((b) => b.textContent)).toEqual(['Findings', 'Coverage', 'Indicators'])
  })

  it('does nothing harmful when a target is not on the page (no scroll, no error)', () => {
    render(<ResultsView result={full()} onReset={vi.fn()} />)
    const links = screen.getByRole('region', { name: 'Links' })
    links.remove()
    expect(() => fireEvent.click(within(nav()).getByRole('button', { name: 'Links' }))).not.toThrow()
    expect(scroll).not.toHaveBeenCalled()
  })

  it('does not disturb a Hebrew message: the heading it focuses and the content below keep their dir="auto" text', () => {
    const base = full()
    const result = { ...base, parsed_email: { ...base.parsed_email, headers: [{ name: 'Subject', value: HEBREW }] } }
    render(<ResultsView result={result} onReset={vi.fn()} />)
    fireEvent.click(within(nav()).getByRole('button', { name: 'Raw headers' }))
    expect(screen.getByLabelText('Header text')).toHaveAttribute('dir', 'auto')
    expect(screen.getByLabelText('Header text')).toHaveTextContent(HEBREW)
  })
})

describe('RawHeadersPanel on its own', () => {
  it('still keeps its own open state when nothing controls it', () => {
    render(<RawHeadersPanel headers={[{ name: 'X', value: '1' }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    expect(screen.getByLabelText('Header text')).toBeInTheDocument()
  })

  it('follows the open prop and reports the reader\'s toggle', () => {
    const onOpenChange = vi.fn()
    const { rerender } = render(<RawHeadersPanel headers={[{ name: 'X', value: '1' }]} open={false} onOpenChange={onOpenChange} />)
    expect(screen.queryByLabelText('Header text')).toBeNull()
    rerender(<RawHeadersPanel headers={[{ name: 'X', value: '1' }]} open onOpenChange={onOpenChange} />)
    expect(screen.getByLabelText('Header text')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Hide headers' }))
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
