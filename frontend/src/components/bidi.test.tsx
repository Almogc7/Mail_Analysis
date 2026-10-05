import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AttachmentsPanel } from './AttachmentsPanel'
import { BodyPanel } from './BodyPanel'
import { CoveragePanel } from './CoveragePanel'
import { FindingItem } from './FindingItem'
import { ImagesPanel } from './ImagesPanel'
import { IndicatorsPanel } from './IndicatorsPanel'
import { LinksPanel } from './LinksPanel'
import { RawHeadersPanel } from './RawHeadersPanel'
import { SenderPanel } from './SenderPanel'
import { SummaryCard } from './SummaryCard'
import { makeAnalysisResult, makeCoverageItem, makeEvidence, makeFinding } from '../test/fixtures'
import type { AttachmentEntry, LinkEntry } from '../types'

// Text that comes out of an email can be right-to-left (Hebrew, Arabic) or mixed with Latin. dir="auto" makes the browser choose the direction from the
// text itself, so a Hebrew subject reads right to left and a defanged URL stays left to right, whatever the page direction is.
const HEBREW = 'חשבונית חודשית לתשלום'
const dirOf = (text: string | RegExp) => screen.getByText(text).closest('[dir]')?.getAttribute('dir')

describe('email-derived text carries dir="auto"', () => {
  it('finding titles in the Why list', () => {
    render(<SummaryCard result={makeAnalysisResult({ findings: [makeFinding({ severity: 'high', title: HEBREW })] })} />)
    expect(dirOf(new RegExp(HEBREW))).toBe('auto')
  })

  it('finding title, description and evidence values', () => {
    // A low-severity finding starts collapsed, so the click below opens it (a high one starts open: see findingCollapse.test.tsx).
    render(<FindingItem finding={makeFinding({ severity: 'low', title: `${HEBREW} title`, description: `${HEBREW} description`, evidence: { subject: `${HEBREW} evidence` } })} />)
    fireEvent.click(screen.getByRole('button'))
    for (const part of ['title', 'description', 'evidence']) expect(dirOf(`${HEBREW} ${part}`)).toBe('auto')
  })

  it('sender display name, reply-to, and a hop host', () => {
    const ev = makeEvidence()
    ev.sender.from_address = { display_name: HEBREW, address: 'a@example.com', domain: 'example.com' }
    ev.sender.mismatches = [`${HEBREW} mismatch`]
    const hop = { index: 1, from_host: 'host-שרת.example', by_host: 'b.example', from_ip: null, protocol: null, tls: false, authenticated: false, local_submission: false,
      timestamp: null, delay_seconds_from_previous: null, clock_skew: false, trusted_receiver: false, is_origin: true }
    render(<SenderPanel sender={ev.sender} hops={[hop]} />)
    fireEvent.click(screen.getByRole('button', { name: /show path/i }))
    const fromCell = screen.getByText((_, el) => el?.tagName === 'TD' && el.textContent === `${HEBREW} <a@example.com>`)
    expect(fromCell).toHaveAttribute('dir', 'auto')
    expect(dirOf(HEBREW)).toBe('auto')
    expect(dirOf('<a@example.com>')).toBe('auto')
    expect(dirOf(`${HEBREW} mismatch`)).toBe('auto')
    expect(dirOf(/host-שרת\.example/)).toBe('auto')
  })

  it('a link and the text shown to the reader', () => {
    const link: LinkEntry = { url: 'https://x.example/a', url_defanged: 'hxxps://x[.]example/a', host: 'x.example', registrable_domain: 'x.example', display_text: HEBREW, kind: 'direct',
      platform: null, anchor_mismatch: false, occurrences: 1, sources: ['html'], status: 'unknown' }
    render(<LinksPanel links={[link]} />)
    expect(dirOf('hxxps://x[.]example/a')).toBe('auto')
    expect(dirOf(HEBREW)).toBe('auto')
  })

  it('an attachment file name and an image file name', () => {
    const att: AttachmentEntry = { filename: `${HEBREW}.pdf`, declared_type: 'application/pdf', detected_type: null, extension: 'pdf', size_bytes: 1, sha256: 'a'.repeat(64),
      risk_class: 'document', active_content: false, double_extension: false, static_analysis: null }
    const { unmount } = render(<AttachmentsPanel attachments={[att]} />)
    expect(dirOf(`${HEBREW}.pdf`)).toBe('auto')
    unmount()
    render(<ImagesPanel images={[{ source: 'attachment', host: null, url_defanged: null, filename: `${HEBREW}.png`, size_bytes: 1, decoded: null }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Images (1)' }))  // the images panel is collapsed by default
    expect(dirOf(`${HEBREW}.png`)).toBe('auto')
  })

  it('the body text and the raw headers', () => {
    const { unmount } = render(<BodyPanel body={makeEvidence().body} text={HEBREW} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show body text' }))
    expect(screen.getByLabelText('Body text')).toHaveAttribute('dir', 'auto')
    unmount()
    render(<RawHeadersPanel headers={[{ name: 'Subject', value: HEBREW }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    expect(screen.getByLabelText('Header text')).toHaveAttribute('dir', 'auto')
  })

  // Human-language Hebrew uses the UI font (the mono faces have no complete Hebrew coverage); machine tokens stay mono. Each keeps dir="auto".
  it('Hebrew human-language text is on the UI font class and machine tokens on the mono class', () => {
    const ev = makeEvidence()
    ev.sender.from_address = { display_name: HEBREW, address: 'a@example.com', domain: 'example.com' }
    const sender = render(<SenderPanel sender={ev.sender} hops={[]} />)
    expect(screen.getByText(HEBREW)).toHaveClass('wb-text')
    expect(screen.getByText('<a@example.com>')).toHaveClass('wb-mono')
    sender.unmount()

    const link: LinkEntry = { url: 'https://x.example/a', url_defanged: 'hxxps://x[.]example/a', host: 'x.example', registrable_domain: 'x.example', display_text: HEBREW, kind: 'direct',
      platform: null, anchor_mismatch: false, occurrences: 1, sources: ['html'], status: 'unknown' }
    const links = render(<LinksPanel links={[link]} />)
    expect(screen.getByText(HEBREW)).toHaveClass('wb-text')
    expect(screen.getByText('hxxps://x[.]example/a')).toHaveClass('wb-mono')
    links.unmount()

    const att: AttachmentEntry = { filename: `${HEBREW}.pdf`, declared_type: 'application/pdf', detected_type: null, extension: 'pdf', size_bytes: 1, sha256: 'a'.repeat(64),
      risk_class: 'document', active_content: false, double_extension: false, static_analysis: null }
    const attachments = render(<AttachmentsPanel attachments={[att]} />)
    expect(screen.getByText(`${HEBREW}.pdf`)).toHaveClass('wb-text')
    expect(screen.getByText('a'.repeat(64))).toHaveClass('wb-mono')
    attachments.unmount()

    const images = render(<ImagesPanel images={[{ source: 'attachment', host: null, url_defanged: null, filename: `${HEBREW}.png`, size_bytes: 1, decoded: null },
      { source: 'html', host: 'x.example', url_defanged: 'hxxps://x[.]example/i.png', filename: null, size_bytes: null, decoded: null }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Images (2)' }))
    expect(screen.getByText(`${HEBREW}.png`)).toHaveClass('wb-text')
    expect(screen.getByText('hxxps://x[.]example/i.png')).toHaveClass('wb-mono')
    images.unmount()

    const body = render(<BodyPanel body={makeEvidence().body} text={HEBREW} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show body text' }))
    expect(screen.getByLabelText('Body text')).toHaveClass('wb-pre--text')
    expect(screen.getByLabelText('Body text')).toHaveAttribute('tabindex', '0')
    body.unmount()

    render(<RawHeadersPanel headers={[{ name: 'Subject', value: HEBREW }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    expect(screen.getByLabelText('Header text')).not.toHaveClass('wb-pre--text')
    expect(screen.getByLabelText('Header text')).toHaveAttribute('tabindex', '0')
  })

  it('an indicator value and its file name, and a coverage subject', () => {
    const pack = { indicators: [{ kind: 'hash' as const, value: 'b'.repeat(64), seen_in: ['attachment'], count: 1, status: 'unknown' as const, note: '', providers: {}, pivots: [], manual_check: true, filename: `${HEBREW}.docx` }], counts: { hash: 1 }, manual_check_count: 1 }
    const { unmount } = render(<IndicatorsPanel pack={pack} />)
    expect(dirOf('b'.repeat(64))).toBe('auto')
    expect(dirOf(new RegExp(`${HEBREW}\\.docx`))).toBe('auto')
    unmount()
    render(<CoveragePanel items={[makeCoverageItem({ subject: HEBREW })]} />)
    expect(dirOf(HEBREW)).toBe('auto')
  })
})
