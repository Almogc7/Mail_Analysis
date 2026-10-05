import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SenderPanel } from './SenderPanel'
import { makeEvidence } from '../test/fixtures'
import type { HopEntry } from '../types'

const hop = (over: Partial<HopEntry> = {}): HopEntry => ({
  index: 1, from_host: 'mx.sender.example', by_host: 'in.example.net', from_ip: null, protocol: 'ESMTPS', tls: true, authenticated: false,
  local_submission: false, timestamp: '2026-01-01T10:00:00+00:00', delay_seconds_from_previous: null, clock_skew: false, trusted_receiver: false,
  is_origin: false, ...over,
})

const openPath = () => fireEvent.click(screen.getByRole('button', { name: /show path/i }))

describe('SenderPanel', () => {
  it('shows From, Reply-To and Return-Path, and says "none" rather than leaving a gap', () => {
    const ev = makeEvidence()
    render(<SenderPanel sender={ev.sender} hops={[]} />)
    // The display name (human language) and the address (machine token) are separate elements; the cell still reads as one value.
    expect(screen.getByText((_, el) => el?.tagName === 'TD' && el.textContent === 'Alice <alice@example.com>')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toHaveClass('wb-text')
    expect(screen.getByText('<alice@example.com>')).toHaveClass('wb-mono')
    expect(screen.getAllByText('none')).toHaveLength(2)
  })

  it('says that, with no trusted receivers configured, an auth result is only a claim', () => {
    const ev = makeEvidence()
    render(<SenderPanel sender={ev.sender} hops={[]} />)
    expect(screen.getByText(/claim from an unknown source, not a verified check/i)).toBeInTheDocument()
  })

  it('shows an unevaluated method with its reason, never as a pass', () => {
    const ev = makeEvidence()
    ev.sender.auth = [
      { method: 'spf', evaluated: false, result: 'pass', receiver: null, reason: 'no_trusted_receivers_configured', source: null },
      { method: 'dkim', evaluated: true, result: 'pass', receiver: 'mx.trusted.example', reason: null, source: null },
    ]
    ev.sender.trusted_receivers_configured = true
    render(<SenderPanel sender={ev.sender} hops={[]} />)
    expect(screen.getByText('not evaluated (no trusted receivers configured)')).toBeInTheDocument()
    expect(screen.getByText('pass as written by mx.trusted.example')).toBeInTheDocument()
    expect(screen.queryByText(/claim from an unknown source/i)).toBeNull()
  })

  it('shows mismatches and unknown alignment honestly', () => {
    const ev = makeEvidence()
    ev.sender.mismatches = ['Reply-To domain differs from From domain']
    ev.sender.alignment = { spf: null, dkim: false }
    render(<SenderPanel sender={ev.sender} hops={[]} />)
    expect(screen.getByText('Reply-To domain differs from From domain')).toBeInTheDocument()
    expect(screen.getByText('not known')).toBeInTheDocument()
    expect(screen.getByText('no')).toBeInTheDocument()
  })

  it('draws the hop timeline oldest first with origin, trusted and clock-skew markers', () => {
    const ev = makeEvidence()
    const hops = [
      hop({ index: 1, is_origin: true, from_ip: '203.0.113.9' }),
      hop({ index: 2, trusted_receiver: true, delay_seconds_from_previous: 300 }),
      hop({ index: 3, clock_skew: true, delay_seconds_from_previous: 9000 }),
    ]
    render(<SenderPanel sender={ev.sender} hops={hops} />)
    openPath()
    const list = screen.getByRole('list', { name: /received hops, oldest first/i })
    const items = within(list).getAllByRole('listitem')
    expect(items.map((li) => li.querySelector('strong')?.textContent)).toEqual(['Hop 1', 'Hop 2', 'Hop 3'])
    expect(within(items[0]).getByText('entered the mail system here')).toBeInTheDocument()
    expect(within(items[0]).getByText(/\[203\.0\.113\.9\]/)).toBeInTheDocument()
    expect(within(items[1]).getByText('trusted receiver')).toBeInTheDocument()
    expect(within(items[1]).getByText(/5 min later/)).toBeInTheDocument()
    expect(within(items[2]).getByText('timestamp earlier than the previous hop')).toBeInTheDocument()
    expect(within(items[2]).getByText(/2\.5 h later/)).toBeInTheDocument()
  })

  it('says so when there are no Received headers', () => {
    render(<SenderPanel sender={makeEvidence().sender} hops={[]} />)
    openPath()
    expect(screen.getByText('No Received headers were present.')).toBeInTheDocument()
  })

  it('renders hostile header text as text', () => {
    const hostile = '<img src=x onerror=alert(1)>'
    const ev = makeEvidence()
    ev.sender.from_address = { display_name: hostile, address: 'a@example.com', domain: 'example.com' }
    const { container } = render(<SenderPanel sender={ev.sender} hops={[hop({ from_host: hostile })]} />)
    openPath()
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })
})

describe('SenderPanel: hops between the analyst\'s own systems', () => {
  const blank = (over: Partial<HopEntry>): HopEntry =>
    hop({ from_host: null, by_host: null, from_ip: null, protocol: null, tls: false, internal: true, ...over })

  it('collapses consecutive internal hops into one row with a count, and keeps the others', () => {
    const hops = [hop({ index: 1, is_origin: true }), blank({ index: 2 }), blank({ index: 3, trusted_receiver: true }), hop({ index: 4, from_host: 'next.example.net' })]
    render(<SenderPanel sender={makeEvidence().sender} hops={hops} />)
    openPath()
    const items = within(screen.getByRole('list', { name: /received hops/i })).getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(within(items[1]).getByText('Hops 2 to 3')).toBeInTheDocument()
    expect(within(items[1]).getByText('2 hops hidden by local config')).toBeInTheDocument()
    expect(within(items[1]).getByText('one wrote a trusted authentication result')).toBeInTheDocument()
  })

  it('shows a single hidden hop in the singular and no trusted note when none wrote a result', () => {
    render(<SenderPanel sender={makeEvidence().sender} hops={[hop({ index: 1 }), blank({ index: 2 })]} />)
    openPath()
    expect(screen.getByText('Hop 2')).toBeInTheDocument()
    expect(screen.getByText('1 hop hidden by local config')).toBeInTheDocument()
    expect(screen.queryByText(/trusted authentication result/)).toBeNull()
  })

  it('separates two runs that have a visible hop between them', () => {
    const hops = [blank({ index: 1 }), hop({ index: 2 }), blank({ index: 3 })]
    render(<SenderPanel sender={makeEvidence().sender} hops={hops} />)
    openPath()
    expect(screen.getAllByText('1 hop hidden by local config')).toHaveLength(2)
  })
})


describe('SenderPanel: the path is collapsed by default', () => {
  it('starts closed with a count, and opens and closes on request', () => {
    render(<SenderPanel sender={makeEvidence().sender} hops={[hop({ index: 1 }), hop({ index: 2 })]} />)
    expect(screen.queryByRole('list', { name: /received hops/i })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show path (2 hops)' }))
    expect(screen.getByRole('list', { name: /received hops/i })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Hide path' }))
    expect(screen.queryByRole('list', { name: /received hops/i })).toBeNull()
  })

  it('uses the singular for one hop', () => {
    render(<SenderPanel sender={makeEvidence().sender} hops={[hop({ index: 1 })]} />)
    expect(screen.getByRole('button', { name: 'Show path (1 hop)' })).toBeInTheDocument()
  })
})

describe('SenderPanel: hops below the trust boundary are claims', () => {
  it('labels an unverified hop "claimed / unverified", keeps its names visible, and explains why once', () => {
    const forged = hop({ index: 1, from_host: 'gw.claimed-internal.example', unverified: true })
    render(<SenderPanel sender={makeEvidence().sender} hops={[forged, hop({ index: 2, unverified: false })]} />)
    openPath()
    const items = within(screen.getByRole('list', { name: /received hops/i })).getAllByRole('listitem')
    expect(within(items[0]).getByText('claimed / unverified')).toBeInTheDocument()
    expect(within(items[0]).getByText(/gw\.claimed-internal\.example/)).toBeInTheDocument()
    expect(within(items[1]).queryByText('claimed / unverified')).toBeNull()
    expect(screen.getAllByText(/Read every field\s+of those hops as a claim/)).toHaveLength(1)
  })

  it('shows neither badge nor explanation when every hop is at or above the trust boundary', () => {
    render(<SenderPanel sender={makeEvidence().sender} hops={[hop({ index: 1 }), hop({ index: 2 })]} />)
    openPath()
    expect(screen.queryByText('claimed / unverified')).toBeNull()
    expect(screen.queryByText(/Read every field/)).toBeNull()
  })

  it('never shows a hidden row for an unverified hop (the backend does not hide those), and a hidden row carries no claimed badge', () => {
    const hidden = hop({ index: 2, from_host: null, by_host: null, from_ip: null, protocol: null, tls: false, internal: true, unverified: false })
    render(<SenderPanel sender={makeEvidence().sender} hops={[hop({ index: 1, unverified: true }), hidden]} />)
    openPath()
    const items = within(screen.getByRole('list', { name: /received hops/i })).getAllByRole('listitem')
    expect(within(items[1]).getByText('1 hop hidden by local config')).toBeInTheDocument()
    expect(within(items[1]).queryByText('claimed / unverified')).toBeNull()
  })
})
