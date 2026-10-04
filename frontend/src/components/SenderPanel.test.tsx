import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SenderPanel } from './SenderPanel'
import { makeEvidence } from '../test/fixtures'
import type { HopEntry } from '../types'

const hop = (over: Partial<HopEntry> = {}): HopEntry => ({
  index: 1, from_host: 'mx.sender.example', by_host: 'in.example.net', from_ip: null, protocol: 'ESMTPS', tls: true, authenticated: false,
  local_submission: false, timestamp: '2026-01-01T10:00:00+00:00', delay_seconds_from_previous: null, clock_skew: false, trusted_receiver: false,
  is_origin: false, ...over,
})

describe('SenderPanel', () => {
  it('shows From, Reply-To and Return-Path, and says "none" rather than leaving a gap', () => {
    const ev = makeEvidence()
    render(<SenderPanel sender={ev.sender} hops={[]} />)
    expect(screen.getByText('Alice <alice@example.com>')).toBeInTheDocument()
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
    expect(screen.getByText('No Received headers were present.')).toBeInTheDocument()
  })

  it('renders hostile header text as text', () => {
    const hostile = '<img src=x onerror=alert(1)>'
    const ev = makeEvidence()
    ev.sender.from_address = { display_name: hostile, address: 'a@example.com', domain: 'example.com' }
    const { container } = render(<SenderPanel sender={ev.sender} hops={[hop({ from_host: hostile })]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain(hostile)
  })
})
