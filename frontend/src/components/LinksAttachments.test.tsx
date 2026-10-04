import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AttachmentsPanel } from './AttachmentsPanel'
import { LinksPanel } from './LinksPanel'
import type { AttachmentEntry, LinkEntry } from '../types'

const link = (over: Partial<LinkEntry> = {}): LinkEntry => ({
  url: 'https://evil.example.org/pay?id=1', url_defanged: 'hxxps://evil[.]example[.]org/pay?id=1', host: 'evil.example.org',
  registrable_domain: 'example.org', display_text: null, kind: 'direct', platform: null, anchor_mismatch: false, occurrences: 1, sources: ['html'],
  status: 'unknown', ...over,
})

const attachment = (over: Partial<AttachmentEntry> = {}): AttachmentEntry => ({
  filename: 'invoice.pdf', declared_type: 'application/pdf', detected_type: null, extension: 'pdf', size_bytes: 2048, sha256: 'a'.repeat(64),
  risk_class: 'document', active_content: false, double_extension: false, static_analysis: null, ...over,
})

describe('LinksPanel', () => {
  it('shows only the defanged form, never the live URL, and never as an anchor', () => {
    const { container } = render(<LinksPanel links={[link()]} />)
    expect(screen.getByText('hxxps://evil[.]example[.]org/pay?id=1')).toBeInTheDocument()
    expect(container.textContent).not.toContain('https://evil.example.org')
    expect(container.querySelector('a, [href]')).toBeNull()
  })

  it('copies the defanged form', async () => {
    const copied: string[] = []
    Object.assign(navigator, { clipboard: { writeText: async (t: string) => void copied.push(t) } })
    render(<LinksPanel links={[link()]} />)
    screen.getByRole('button', { name: 'Copy defanged' }).click()
    await screen.findByText('Copied')
    expect(copied).toEqual(['hxxps://evil[.]example[.]org/pay?id=1'])
  })

  it('flags a display text that names a different place, and shows that text as text', () => {
    const hostile = '<a href="https://bank.example.com">bank.example.com</a>'
    const { container } = render(<LinksPanel links={[link({ anchor_mismatch: true, display_text: hostile })]} />)
    expect(screen.getByText('shown text names a different place')).toBeInTheDocument()
    expect(container.querySelector('a')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })

  it('says it does not know where a redirect ends, and says so for an empty list', () => {
    render(<LinksPanel links={[]} />)
    expect(screen.getByText(/never opens or resolves a link/i)).toBeInTheDocument()
    expect(screen.getByText('No links in the message.')).toBeInTheDocument()
  })

  it('labels kind, platform, repeats and status in words', () => {
    render(<LinksPanel links={[link({ kind: 'wrapper', platform: 'Safelinks', occurrences: 3, status: 'shared_platform' })]} />)
    expect(screen.getByText('security wrapper')).toBeInTheDocument()
    expect(screen.getByText('Safelinks')).toBeInTheDocument()
    expect(screen.getByText('seen 3 times')).toBeInTheDocument()
    expect(screen.getByText('shared platform, not judged by host')).toBeInTheDocument()
  })
})

describe('AttachmentsPanel', () => {
  it('shows name, type, size and hash with a copy button, and no download or link', () => {
    const { container } = render(<AttachmentsPanel attachments={[attachment()]} />)
    expect(screen.getByText('invoice.pdf')).toBeInTheDocument()
    expect(screen.getByText(/declared application\/pdf · extension \.pdf · 2\.0 KB/)).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy hash' })).toBeInTheDocument()
    expect(container.querySelector('a, [href], [download]')).toBeNull()
  })

  it('warns about active content and double extensions', () => {
    render(<AttachmentsPanel attachments={[attachment({ filename: 'invoice.pdf.exe', active_content: true, double_extension: true, risk_class: 'executable' })]} />)
    expect(screen.getByText('can run or contain code')).toBeInTheDocument()
    expect(screen.getByText('double extension')).toBeInTheDocument()
  })

  it('says plainly that contents are not analysed, and handles a missing filename', () => {
    render(<AttachmentsPanel attachments={[attachment({ filename: null })]} />)
    expect(screen.getByText('(no filename)')).toBeInTheDocument()
    expect(screen.getByText(/contents are not analysed/i)).toBeInTheDocument()
  })

  it('renders a hostile filename as text', () => {
    const hostile = '<img src=x onerror=alert(1)>.pdf'
    const { container } = render(<AttachmentsPanel attachments={[attachment({ filename: hostile })]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })

  it('says so when there are none', () => {
    render(<AttachmentsPanel attachments={[]} />)
    expect(screen.getByText('No attachments.')).toBeInTheDocument()
  })
})
