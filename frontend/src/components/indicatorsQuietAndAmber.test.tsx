import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { IndicatorsPanel, indicatorsToCsv, indicatorsToText } from './IndicatorsPanel'
import { blocksNoIndicators, notLookedUpByDesign } from './indicatorRules'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeCoverageItem, makeEvidence } from '../test/fixtures'
import type { CoverageItem, Indicator, IndicatorPack } from '../types'

const HEBREW = 'חשבונית חודשית לתשלום'

function indicator(over: Partial<Indicator> = {}): Indicator {
  return {
    kind: 'domain', value: 'quiet.example.org', seen_in: ['link in the message'], count: 1, status: 'nothing_found',
    note: 'Every source that was asked reported nothing. That is not proof of safety.', providers: { VirusTotal: 'answered' }, pivots: [],
    manual_check: false, filename: null, ...over,
  }
}
const pack = (items: Indicator[]): IndicatorPack => ({ indicators: items, counts: {}, manual_check_count: items.filter((i) => i.manual_check).length })
const quietButton = () => screen.queryByRole('button', { name: /with nothing found \(not proof of safety\)$/ })

// Coverage items as the backend writes them (app/coverage.py): the two gaps that block "No indicators found" and the two that do not.
const SHARED_BLOCKS: CoverageItem = makeCoverageItem({ area: 'Lookups', status: 'not_checked', reason: 'shared_platform', subject: 'hosts on shared platforms', blocks_no_indicators: true })
const INTERNAL_BLOCKS: CoverageItem = makeCoverageItem({ area: 'Lookups', status: 'not_checked', reason: 'internal_host_not_sent', subject: 'internal-looking hosts', by_design: true, blocks_no_indicators: true })
const LIMIT: CoverageItem = makeCoverageItem({ area: 'Lookups', status: 'not_checked', reason: 'limit_reached', subject: 'indicators over the per-email limit' })
const NO_ENRICHMENT: CoverageItem = makeCoverageItem({ area: 'Lookups', status: 'not_checked', reason: 'enrichment_did_not_run', subject: 'all providers' })
const HEALTHY: CoverageItem = makeCoverageItem({ area: 'VirusTotal', status: 'checked', reason: 'answered', subject: 'domains' })

describe('rows that say "Nothing found" are folded into one collapsed group', () => {
  const items = [
    indicator({ value: 'unknown.example.org', status: 'unknown', manual_check: true, note: 'No source gave a usable answer.' }),
    indicator({ value: 'one.example.org' }),
    indicator({ value: 'two.example.org' }),
    indicator({ kind: 'hash', value: 'a'.repeat(64) }),
  ]

  it('shows a button header with the count, aria-expanded false, and none of those rows', () => {
    render(<IndicatorsPanel pack={pack(items)} />)
    const header = quietButton()!
    expect(header).toHaveTextContent('3 indicators with nothing found (not proof of safety)')
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(header.closest('h3')).not.toBeNull()
    for (const v of ['one.example.org', 'two.example.org', 'a'.repeat(64)]) expect(screen.queryByText(v)).toBeNull()
    expect(screen.getByText('unknown.example.org')).toBeInTheDocument()  // rows that need attention stay in view
  })

  it('uses the singular for one, and opens to show every row with its own wording', () => {
    render(<IndicatorsPanel pack={pack([indicator()])} />)
    const header = quietButton()!
    expect(header).toHaveTextContent('1 indicator with nothing found (not proof of safety)')
    fireEvent.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('quiet.example.org')).toBeInTheDocument()
    expect(screen.getByText('Nothing found (not proof of safety)')).toBeInTheDocument()
    fireEvent.click(header)
    expect(screen.queryByText('quiet.example.org')).toBeNull()
  })

  it('has no group at all when no row says "nothing found"', () => {
    render(<IndicatorsPanel pack={pack([indicator({ status: 'unknown', manual_check: true })])} />)
    expect(quietButton()).toBeNull()
  })

  it('keeps dir="auto" on a Hebrew file name inside the group once opened', () => {
    render(<IndicatorsPanel pack={pack([indicator({ kind: 'hash', value: 'b'.repeat(64), filename: `${HEBREW}.docx` })])} />)
    expect(screen.queryByText(new RegExp(HEBREW))).toBeNull()
    fireEvent.click(quietButton()!)
    expect(screen.getByText(new RegExp(`${HEBREW}\\.docx`))).toHaveAttribute('dir', 'auto')
    expect(screen.getByText('b'.repeat(64))).toHaveAttribute('dir', 'auto')
  })

  it('leaves the "N need a manual check" count exactly as the pack says, folded or not', () => {
    const { container } = render(<IndicatorsPanel pack={{ ...pack(items), manual_check_count: 7 }} />)
    expect(container.querySelector('.indicators-lead strong')).toHaveTextContent('7')
    fireEvent.click(quietButton()!)
    expect(container.querySelector('.indicators-lead strong')).toHaveTextContent('7')
  })
})

describe('the exports still contain every indicator, folded or not', () => {
  const items = [indicator({ value: 'unknown.example.org', status: 'unknown', manual_check: true }), indicator({ value: 'quiet.example.org' }), indicator({ kind: 'hash', value: 'c'.repeat(64) })]

  it('copies the raw and the defanged list with the folded rows included', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<IndicatorsPanel pack={pack(items)} />)
    expect(screen.queryByText('quiet.example.org')).toBeNull()  // folded on screen
    fireEvent.click(screen.getByText('Copy list'))
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith(indicatorsToText(items, false)))
    expect(writeText.mock.calls.at(-1)![0]).toBe(`unknown.example.org\nquiet.example.org\n${'c'.repeat(64)}`)
    fireEvent.click(screen.getByText('Copy defanged'))
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith(indicatorsToText(items, true)))
    expect(writeText.mock.calls.at(-1)![0]).toBe(`unknown[.]example[.]org\nquiet[.]example[.]org\n${'c'.repeat(64)}`)
  })

  it('downloads a CSV with a row for every indicator, identical to the helper output', async () => {
    let blob: Blob | undefined
    Object.assign(URL, { createObjectURL: vi.fn((b: Blob) => { blob = b; return 'blob:x' }), revokeObjectURL: vi.fn() })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})  // no real navigation in jsdom
    render(<IndicatorsPanel pack={pack(items)} />)
    fireEvent.click(screen.getByText('Download CSV (defanged)'))
    const csv = await new Promise<string>((resolve) => { const r = new FileReader(); r.onload = () => resolve(String(r.result)); r.readAsText(blob!) })
    expect(csv).toBe(indicatorsToCsv(items, true))
    expect(csv.trim().split('\n')).toHaveLength(4)  // header + three indicators
    expect(csv).toContain('quiet[.]example[.]org,nothing_found')
  })
})

describe('amber only where the gap blocks "No indicators found"', () => {
  const rowOf = (value: string) => screen.getByText(value).closest('li') as HTMLElement

  it('marks a shared-platform host and an internal-looking name as blocking when the coverage report says they block', () => {
    render(
      <IndicatorsPanel
        pack={pack([indicator({ value: 'docs.example.net', status: 'shared_platform', manual_check: true }), indicator({ value: 'intranet.corp.example', status: 'internal', manual_check: true })])}
        coverage={[SHARED_BLOCKS, INTERNAL_BLOCKS]}
      />,
    )
    expect(rowOf('docs.example.net')).toHaveClass('indicator--blocks')
    expect(rowOf('intranet.corp.example')).toHaveClass('indicator--blocks')
    expect(within(rowOf('docs.example.net')).getByText('Shared platform: check by hand')).toBeInTheDocument()  // the words stay
  })

  it('does not mark an unknown host, a hit, or a shared platform whose coverage item does not block', () => {
    render(
      <IndicatorsPanel
        pack={pack([indicator({ value: 'unknown.example.org', status: 'unknown', manual_check: true }), indicator({ value: 'shared.example.net', status: 'shared_platform', manual_check: true }), indicator({ value: 'hit.example.org', status: 'provider_hit' })])}
        coverage={[{ ...SHARED_BLOCKS, blocks_no_indicators: false }, HEALTHY]}
      />,
    )
    for (const v of ['unknown.example.org', 'shared.example.net', 'hit.example.org']) expect(rowOf(v)).not.toHaveClass('indicator--blocks')
  })

  it('falls back to the status when the result has no coverage report', () => {
    render(<IndicatorsPanel pack={pack([indicator({ value: 'docs.example.net', status: 'shared_platform', manual_check: true }), indicator({ value: 'unknown.example.org', status: 'unknown', manual_check: true })])} />)
    expect(rowOf('docs.example.net')).toHaveClass('indicator--blocks')
    expect(rowOf('unknown.example.org')).not.toHaveClass('indicator--blocks')
  })

  it('never marks the analyst\'s own gateway', () => {
    expect(blocksNoIndicators(indicator({ status: 'internal', gateway: true }), [INTERNAL_BLOCKS])).toBe(false)
  })
})

describe('"Not looked up (by design)"', () => {
  const notLooked = (value: string) => indicator({ value, kind: 'ip', status: 'not_looked_up', manual_check: true, note: 'Not looked up. Check it by hand.', providers: {} })

  it('is shown, neutral and without the amber class, when the lookups ran and none was cut short', () => {
    render(<IndicatorsPanel pack={pack([notLooked('203.0.113.7')])} coverage={[HEALTHY]} />)
    const row = screen.getByText('203.0.113.7').closest('li') as HTMLElement
    expect(within(row).getByText('Not looked up (by design)')).toBeInTheDocument()
    expect(row).not.toHaveClass('indicator--blocks')
    expect(screen.queryByText('Not looked up: check by hand')).toBeNull()
    expect(within(row).getByText('Not looked up. Check it by hand.')).toBeInTheDocument()  // the note still tells the analyst
  })

  it.each([
    ['the per-email limit was reached', [HEALTHY, LIMIT]],
    ['enrichment did not run', [NO_ENRICHMENT]],
    ['there is no coverage report', undefined],
  ] as [string, CoverageItem[] | undefined][])('keeps the plain wording when %s (it cannot be told to be by design)', (_why, coverage) => {
    render(<IndicatorsPanel pack={pack([notLooked('203.0.113.7')])} coverage={coverage} />)
    expect(screen.getByText('Not looked up: check by hand')).toBeInTheDocument()
    expect(screen.queryByText('Not looked up (by design)')).toBeNull()
    expect(screen.getByText('203.0.113.7').closest('li')).not.toHaveClass('indicator--blocks')
  })

  it('is decided by a pure rule that ignores the gateway and every other status', () => {
    expect(notLookedUpByDesign(notLooked('203.0.113.7'), [HEALTHY])).toBe(true)
    expect(notLookedUpByDesign({ ...notLooked('203.0.113.7'), gateway: true }, [HEALTHY])).toBe(false)
    expect(notLookedUpByDesign(indicator({ status: 'unknown' }), [HEALTHY])).toBe(false)
  })

  it('does not change the manual-check count: by-design rows still count as the backend says', () => {
    const { container } = render(<IndicatorsPanel pack={pack([notLooked('203.0.113.7'), notLooked('203.0.113.8')])} coverage={[HEALTHY]} />)
    expect(container.querySelector('.indicators-lead strong')).toHaveTextContent('2')
  })
})

describe('the results view hands the coverage report to the indicators panel', () => {
  it('uses it to decide what is amber', () => {
    const items = [indicator({ value: 'docs.example.net', status: 'shared_platform', manual_check: true }), indicator({ value: 'unknown.example.org', status: 'unknown', manual_check: true })]
    const result = makeAnalysisResult({ evidence: makeEvidence(), coverage_report: [SHARED_BLOCKS], schema_version: 2, indicators: pack(items) })
    render(<ResultsView result={result} onReset={vi.fn()} />)
    expect(screen.getByText('docs.example.net').closest('li')).toHaveClass('indicator--blocks')
    expect(screen.getByText('unknown.example.org').closest('li')).not.toHaveClass('indicator--blocks')
  })
})
