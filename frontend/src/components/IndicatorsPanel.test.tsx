import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { defang, IndicatorsPanel, indicatorsToCsv, indicatorsToText } from './IndicatorsPanel'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult } from '../test/fixtures'
import type { Indicator, IndicatorPack } from '../types'

function indicator(overrides: Partial<Indicator> = {}): Indicator {
  return {
    kind: 'domain',
    value: 'evil.example.org',
    seen_in: ['clickable link (call to action)'],
    count: 1,
    status: 'nothing_found',
    note: 'Every source that was asked reported nothing. That is not proof of safety.',
    providers: { VirusTotal: 'answered' },
    pivots: [{ name: 'VirusTotal', url: 'https://www.virustotal.com/gui/domain/evil.example.org' }],
    manual_check: false,
    filename: null,
    ...overrides,
  }
}

function pack(items: Indicator[]): IndicatorPack {
  return { indicators: items, counts: {}, manual_check_count: items.filter((i) => i.manual_check).length }
}

describe('defang / export helpers', () => {
  it('defangs domains, ips and emails but never hashes', () => {
    expect(defang('domain', 'a.b.example.org')).toBe('a[.]b[.]example[.]org')
    expect(defang('ip', '8.8.4.4')).toBe('8[.]8[.]4[.]4')
    expect(defang('email', 'x@y.example.org')).toBe('x[@]y[.]example[.]org')
    expect(defang('hash', 'abc123')).toBe('abc123')
  })

  it('lists raw or defanged values one per line', () => {
    const items = [indicator(), indicator({ kind: 'email', value: 'a@b.example.org' })]
    expect(indicatorsToText(items, false)).toBe('evil.example.org\na@b.example.org')
    expect(indicatorsToText(items, true)).toBe('evil[.]example[.]org\na[@]b[.]example[.]org')
  })

  it('writes a csv with the documented columns, quoting and defanging', () => {
    const csv = indicatorsToCsv([indicator({ note: 'has, a comma and "quotes"', seen_in: ['a', 'b'] })], true)
    const [header, row] = csv.trim().split('\n')
    expect(header).toBe('kind,indicator,status,manual_check,seen_in,count,note')
    expect(row).toBe('domain,evil[.]example[.]org,nothing_found,no,a; b,1,"has, a comma and ""quotes"""')
  })

  it('neutralises spreadsheet formulas in an indicator or a note', () => {
    const csv = indicatorsToCsv([indicator({ kind: 'email', value: '+cmd@x.example.org', note: '=HYPERLINK("x")' })], false)
    expect(csv).toContain("'+cmd@x.example.org")
    expect(csv).toContain(`"'=HYPERLINK(""x"")"`)
  })
})

describe('IndicatorsPanel', () => {
  it('renders nothing without a pack or with an empty one', () => {
    const { container, rerender } = render(<IndicatorsPanel pack={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<IndicatorsPanel pack={pack([])} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('says the list adds nothing to the verdict and counts the manual checks', () => {
    render(<IndicatorsPanel pack={pack([indicator({ status: 'unknown', manual_check: true }), indicator({ value: 'b.example.org' })])} />)
    expect(screen.getByText(/adds nothing to the verdict/i)).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('Unknown: check by hand')).toBeInTheDocument()
    expect(screen.getByText('Nothing found (not proof of safety)')).toBeInTheDocument()
  })

  it('shows a shared-platform link and an unseen hash as things to check, never as clean', () => {
    const { container } = render(
      <IndicatorsPanel
        pack={pack([
          indicator({ value: 'docs.google.com', status: 'shared_platform', manual_check: true, note: 'Open the specific link in your sandbox.' }),
          indicator({ kind: 'hash', value: 'a'.repeat(64), status: 'unknown', manual_check: true, filename: 'image.png', note: 'No source has a record of this file (never seen)' }),
        ])}
      />,
    )
    expect(screen.getByText('Shared platform: check by hand')).toBeInTheDocument()
    expect(screen.getByText(/image\.png/)).toBeInTheDocument()
    const labels = Array.from(container.querySelectorAll('.indicator-status')).map((e) => e.textContent ?? '')
    expect(labels).toHaveLength(2)
    expect(labels.every((l) => /check by hand/.test(l) && !/clean|safe/i.test(l))).toBe(true)
  })

  it('opens pivot links in a new tab without leaking the opener', () => {
    render(<IndicatorsPanel pack={pack([indicator()])} />)
    const link = screen.getByRole('link', { name: 'VirusTotal' })
    expect(link).toHaveAttribute('href', 'https://www.virustotal.com/gui/domain/evil.example.org')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(link.getAttribute('rel')).toContain('noreferrer')
  })

  it('can show only the manual checks', () => {
    render(<IndicatorsPanel pack={pack([indicator({ value: 'clean.example.org' }), indicator({ value: 'check.example.org', status: 'unknown', manual_check: true })])} />)
    expect(screen.getByText('clean.example.org')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText(/only manual checks/i))
    expect(screen.queryByText('clean.example.org')).toBeNull()
    expect(screen.getByText('check.example.org')).toBeInTheDocument()
  })

  it('copies the raw and the defanged list and reports the outcome', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<IndicatorsPanel pack={pack([indicator()])} />)
    fireEvent.click(screen.getByText('Copy defanged'))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('evil[.]example[.]org'))
    expect(await screen.findByText('Defanged list: copied')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Copy list'))
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith('evil.example.org'))
  })

  it('reports a failed copy instead of pretending it worked', async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
    render(<IndicatorsPanel pack={pack([indicator()])} />)
    fireEvent.click(screen.getByText('Copy list'))
    expect(await screen.findByText('Raw list: copy failed')).toBeInTheDocument()
  })

  it('appears in the results view when the result carries indicators, and is absent otherwise', () => {
    const { rerender } = render(<ResultsView result={makeAnalysisResult()} onReset={() => {}} />)
    expect(screen.queryByText('Indicators to check')).toBeNull()
    rerender(<ResultsView result={makeAnalysisResult({ indicators: pack([indicator()]) })} onReset={() => {}} />)
    expect(screen.getByText('Indicators to check')).toBeInTheDocument()
  })
})
