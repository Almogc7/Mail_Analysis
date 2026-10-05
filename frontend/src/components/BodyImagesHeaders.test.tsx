import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BodyPanel } from './BodyPanel'
import { ImagesPanel } from './ImagesPanel'
import { RawHeadersPanel } from './RawHeadersPanel'
import { makeEvidence } from '../test/fixtures'

const body = makeEvidence().body
const HOSTILE = '<img src="https://track.example.org/p.gif" onerror="alert(1)"><script>alert(2)</script><b>bold</b>'

describe('BodyPanel', () => {
  it('keeps the text hidden until asked, then shows it as text with no markup elements', () => {
    const { container } = render(<BodyPanel body={body} text={HOSTILE} />)
    expect(screen.queryByLabelText('Body text')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show body text' }))
    const pre = screen.getByLabelText('Body text')
    expect(pre.textContent).toBe(HOSTILE)
    expect(container.querySelector('img, script, b, iframe, a')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Hide body text' }))
    expect(screen.queryByLabelText('Body text')).toBeNull()
  })

  it('says an HTML-only message is not rendered, rather than showing markup', () => {
    render(<BodyPanel body={{ ...body, has_html: true, html_chars: 500 }} text={null} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show body text' }))
    expect(screen.getByText(/only an HTML part\. It is not rendered here/i)).toBeInTheDocument()
  })

  it('says the text is short-lived and never loads remote images', () => {
    render(<BodyPanel body={body} text="hi" />)
    expect(screen.getByText(/never rendered and remote images are never loaded/i)).toBeInTheDocument()
    expect(screen.getByText(/not\s+stored, logged or exported/i)).toBeInTheDocument()
  })

  it('shows the counts', () => {
    render(<BodyPanel body={{ ...body, links: 4, forms: 1, remote_images: 2 }} text="hi" />)
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })
})

const openImages = () => fireEvent.click(screen.getByRole('button', { name: /^Images \(\d+\)$/ }))

describe('ImagesPanel', () => {
  it('lists images without drawing any, and says QR codes are not decoded', () => {
    const { container } = render(
      <ImagesPanel images={[{ source: 'html', host: 'track.example.org', url_defanged: 'hxxps://track[.]example[.]org/p.gif', filename: null, size_bytes: null, decoded: null }]} />,
    )
    openImages()
    expect(container.querySelector('img, picture, canvas, svg, [src]')).toBeNull()
    expect(screen.getByText('hxxps://track[.]example[.]org/p.gif')).toBeInTheDocument()
    expect(screen.getByText(/QR codes in images are not decoded yet/i)).toBeInTheDocument()
    expect(screen.getByText('host track.example.org · not decoded')).toBeInTheDocument()
  })

  it('renders an attached image by filename, as text', () => {
    const { container } = render(<ImagesPanel images={[{ source: 'attachment', host: null, url_defanged: null, filename: HOSTILE, size_bytes: 10, decoded: null }]} />)
    openImages()
    expect(container.querySelector('img, script, b')).toBeNull()
    expect(container.textContent).toContain(HOSTILE)
  })

  it('says so when there are none', () => {
    render(<ImagesPanel images={[]} />)
    openImages()
    expect(screen.getByText('No images found.')).toBeInTheDocument()
  })
})

describe('RawHeadersPanel', () => {
  const headers = [{ name: 'Subject', value: HOSTILE }, { name: 'X-Test', value: 'ok' }]

  it('is collapsed by default and shows name: value lines as text when opened', () => {
    const { container } = render(<RawHeadersPanel headers={headers} />)
    expect(screen.queryByLabelText('Header text')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    expect(screen.getByLabelText('Header text').textContent).toBe(`Subject: ${HOSTILE}\nX-Test: ok`)
    expect(container.querySelector('img, script, b')).toBeNull()
  })

  it('offers a copy button for the whole block', () => {
    render(<RawHeadersPanel headers={headers} />)
    expect(screen.getByRole('button', { name: 'Copy headers' })).toBeInTheDocument()
  })

  it('says so when there are no headers', () => {
    render(<RawHeadersPanel headers={[]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show headers' }))
    expect(screen.getByText('No headers.')).toBeInTheDocument()
  })
})
