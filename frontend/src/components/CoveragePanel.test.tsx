import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { CoveragePanel } from './CoveragePanel'
import { makeCoverageItem } from '../test/fixtures'

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
