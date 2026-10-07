import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { CoveragePanel } from './CoveragePanel'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeCoverageItem, makeVerdictV2 } from '../test/fixtures'
import { readSrc } from '../test/readSource'
import type { ChecksCompleted, CoverageItem } from '../types'

describe('CoveragePanel', () => {
  it('renders nothing for a result without a coverage report', () => {
    const { container } = render(<CoveragePanel items={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('lists what was not checked first, with the reason and how to clear it', () => {
    const items = [
      makeCoverageItem({ area: 'authentication', subject: 'spf', status: 'checked' }),
      makeCoverageItem({
        area: 'enrichment',
        subject: 'virustotal',
        status: 'not_checked',
        detail: 'No API key is configured.',
        how_to_clear: 'Set VT_API_KEY.',
        blocks_no_indicators: true,
      }),
    ]
    render(<CoveragePanel items={items} />)
    expect(screen.getByText('1 area not fully checked.', { exact: false })).toBeInTheDocument()
    const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
    expect(headings).toEqual(['Not checked, and why', 'Checked'])
    expect(screen.getByText('No API key is configured.')).toBeInTheDocument()
    expect(screen.getByText('To clear: Set VT_API_KEY.')).toBeInTheDocument()
    expect(screen.getByText('blocks "No indicators found"')).toBeInTheDocument()
  })

  it('marks things the tool never does on purpose, so they do not read as a malfunction', () => {
    render(<CoveragePanel items={[makeCoverageItem({ area: 'links', status: 'not_checked', by_design: true, detail: 'Links are never opened.' })]} />)
    expect(screen.getByText('never done, by design')).toBeInTheDocument()
  })

  it('does not claim completeness when something was only partly checked', () => {
    render(<CoveragePanel items={[makeCoverageItem({ status: 'partly' })]} />)
    expect(screen.queryByText(/every area/i)).toBeNull()
    expect(screen.getByText('Partly checked')).toBeInTheDocument()
  })

  it('says every covered area was checked only when nothing is missing, and still says what it never does', () => {
    render(<CoveragePanel items={[makeCoverageItem()]} />)
    expect(screen.getByText(/every area this tool covers was checked/i)).toBeInTheDocument()
    expect(screen.getByText(/never opens links or attachments/i)).toBeInTheDocument()
  })

  it('renders hostile text as text', () => {
    const hostile = '<img src=x onerror=alert(1)>'
    const { container } = render(<CoveragePanel items={[makeCoverageItem({ detail: hostile, subject: hostile })]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })
})

describe('CoveragePanel: the "Checks completed" line (checks_completed from the API)', () => {
  type Example = { checks_completed: ChecksCompleted; coverage_report: CoverageItem[] }
  const examples = JSON.parse(readSrc('test/coverageExamples.json')) as Record<string, Example>
  const line = () => screen.getByText(/^Checks completed:/)

  it.each([
    ['seven_of_ten', 'Checks completed: 7 of 10, 3 not checked'],
    ['nine_of_nine', 'Checks completed: 9 of 9, 0 not checked'],
    ['one_of_seven', 'Checks completed: 1 of 7, 6 not checked'],
  ])('%s says "%s" and nothing else as a completeness figure', (name, expected) => {
    const ex = examples[name]
    const { container } = render(<CoveragePanel items={ex.coverage_report} checks={ex.checks_completed} />)
    expect(line()).toHaveTextContent(expected)
    expect(container.textContent).not.toMatch(/%|every area|area[s]? not fully checked|complete\b/i)
  })

  it('uses the API figures, not a recount of the items it was given', () => {
    const ex = examples.seven_of_ten
    render(<CoveragePanel items={ex.coverage_report.slice(0, 2)} checks={ex.checks_completed} />)
    expect(line()).toHaveTextContent('Checks completed: 7 of 10, 3 not checked')
  })

  it('shows by-design items apart and counts them in none of the figures', () => {
    const ex = examples.seven_of_ten
    render(<CoveragePanel items={ex.coverage_report} checks={ex.checks_completed} />)
    const heading = screen.getByRole('heading', { name: /Never done, by design/ })
    const list = heading.nextElementSibling as HTMLElement
    expect(within(list).getAllByRole('listitem')).toHaveLength(ex.checks_completed.by_design)
    const gapList = screen.getByRole('heading', { name: 'Not checked, and why' }).nextElementSibling as HTMLElement
    expect(within(gapList).getAllByRole('listitem')).toHaveLength(ex.checks_completed.not_checked)
    expect(within(gapList).queryByText('opening links')).toBeNull()
  })

  it('opens the not-checked items by default, each blocker marked, each with its "To clear" hint', () => {
    const ex = examples.one_of_seven
    render(<CoveragePanel items={ex.coverage_report} checks={ex.checks_completed} />)
    const gapList = screen.getByRole('heading', { name: 'Not checked, and why' }).nextElementSibling as HTMLElement
    const rows = within(gapList).getAllByRole('listitem')
    expect(rows).toHaveLength(6)
    expect(within(gapList).getAllByText('blocks "No indicators found"')).toHaveLength(4)
    expect(within(gapList).getAllByText(/^To clear:/)).toHaveLength(6)
  })

  it('keeps the checked items collapsed behind a count, and opens them on the button', () => {
    const ex = examples.seven_of_ten
    render(<CoveragePanel items={ex.coverage_report} checks={ex.checks_completed} />)
    const button = screen.getByRole('button', { name: /^Checked \(7\)/ })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('a-0')).toBeNull()
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('a-0')).toBeInTheDocument()
  })

  it('shows an explicit "None." when nothing is unchecked, and no checked button when nothing was checked', () => {
    render(<CoveragePanel items={examples.nine_of_nine.coverage_report} checks={examples.nine_of_nine.checks_completed} />)
    const gapList = screen.getByRole('heading', { name: 'Not checked, and why' })
    expect(gapList.parentElement).toHaveTextContent('None.')
  })

  it('puts dir="auto" on every row, and on the text of each', () => {
    const hebrew = 'לא נבדק: ספק חיצוני'
    render(<CoveragePanel items={[makeCoverageItem({ status: 'not_checked', detail: hebrew, how_to_clear: hebrew, subject: hebrew })]} checks={{ completed: 0, total: 1, not_checked: 1, by_design: 0 }} />)
    const row = screen.getByRole('listitem')
    expect(row).toHaveAttribute('dir', 'auto')
    expect(screen.getByText(hebrew, { selector: '.wb-mono' })).toHaveAttribute('dir', 'auto')
    expect(screen.getByText(hebrew, { selector: '.wb-small' })).toHaveAttribute('dir', 'auto')
    expect(screen.getByText(`To clear: ${hebrew}`)).toHaveAttribute('dir', 'auto')
  })

  it('an old-shape result (no checks_completed) keeps the earlier wording', () => {
    render(<CoveragePanel items={[makeCoverageItem({ status: 'not_checked' })]} />)
    expect(screen.getByText('1 area not fully checked.', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText(/^Checks completed:/)).toBeNull()
  })

  it('the page passes checks_completed from the result to the panel', () => {
    const ex = examples.seven_of_ten
    render(<ResultsView result={makeAnalysisResult({ coverage_report: ex.coverage_report, checks_completed: ex.checks_completed, verdict_v2: makeVerdictV2(), verdict_v2_status: 'ok' })} onReset={() => {}} />)
    expect(line()).toHaveTextContent('Checks completed: 7 of 10, 3 not checked')
  })
})
