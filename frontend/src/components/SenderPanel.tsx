import { useState } from 'react'
import type { AuthRow, EmailAddress, HopEntry, SenderEvidence } from '../types'

function addr(a: EmailAddress | null): string {
  if (!a || !a.address) return 'none'
  return a.display_name ? `${a.display_name} <${a.address}>` : a.address
}

function delay(seconds: number | null): string | null {
  if (seconds === null) return null
  if (seconds < 1) return 'under a second later'
  if (seconds < 120) return `${Math.round(seconds)} s later`
  if (seconds < 7200) return `${Math.round(seconds / 60)} min later`
  return `${(seconds / 3600).toFixed(1)} h later`
}

function authText(row: AuthRow): string {
  if (!row.evaluated) return `not evaluated${row.reason ? ` (${row.reason.replaceAll('_', ' ')})` : ''}`
  return `${row.result ?? 'no result'}${row.receiver ? ` as written by ${row.receiver}` : ''}`
}

type Row = { kind: 'hop'; hop: HopEntry } | { kind: 'hidden'; hops: HopEntry[] }

/** Consecutive hops sent from the analyst's own systems become one summary row. */
function group(hops: HopEntry[]): Row[] {
  const rows: Row[] = []
  for (const hop of hops) {
    const last = rows[rows.length - 1]
    if (!hop.internal) rows.push({ kind: 'hop', hop })
    else if (last?.kind === 'hidden') last.hops.push(hop)
    else rows.push({ kind: 'hidden', hops: [hop] })
  }
  return rows
}

export function HopTimeline({ hops }: { hops: HopEntry[] }) {
  if (hops.length === 0) return <p className="wb-note">No Received headers were present.</p>
  return (
    <>
    {hops.some((h) => h.unverified) && (
      <p className="wb-note">
        Hops marked claimed / unverified were written before the message reached a server you trust, so the sender controls them. Read every field
        of those hops as a claim.
      </p>
    )}
    <ol className="hop-list" aria-label="Received hops, oldest first">
      {group(hops).map((row) => {
        if (row.kind === 'hidden') {
          const trusted = row.hops.filter((h) => h.trusted_receiver).length
          const first = row.hops[0].index
          const last = row.hops[row.hops.length - 1].index
          return (
            <li key={`hidden-${first}`} className="hop hop--hidden">
              <div className="wb-row-main">
                <strong>{first === last ? `Hop ${first}` : `Hops ${first} to ${last}`}</strong>
                <span className="wb-badge">
                  {row.hops.length} hop{row.hops.length === 1 ? '' : 's'} hidden by local config
                </span>
                {trusted > 0 && <span className="wb-badge wb-badge--info">{trusted === 1 ? 'one' : trusted} wrote a trusted authentication result</span>}
              </div>
            </li>
          )
        }
        const h = row.hop
        const later = delay(h.delay_seconds_from_previous)
        return (
          <li key={h.index} className={`hop${h.is_origin ? ' hop--origin' : ''}${h.trusted_receiver ? ' hop--trusted' : ''}`}>
            <div className="wb-row-main">
              <strong>Hop {h.index}</strong>
              <span className="wb-mono" dir="auto">
                {h.from_host ?? 'unknown host'}
                {h.from_ip ? ` [${h.from_ip}]` : ''} to {h.by_host ?? 'unknown host'}
              </span>
              {h.is_origin && <span className="wb-badge wb-badge--info">entered the mail system here</span>}
              {h.trusted_receiver && <span className="wb-badge wb-badge--info">trusted receiver</span>}
              {h.clock_skew && <span className="wb-badge wb-badge--warn">timestamp earlier than the previous hop</span>}
              {h.local_submission && <span className="wb-badge">local submission</span>}
              {h.unverified && <span className="wb-badge wb-badge--warn">claimed / unverified</span>}
            </div>
            <div className="wb-small">
              {[h.protocol, h.tls ? 'TLS' : 'no TLS recorded', h.authenticated ? 'authenticated' : null, h.timestamp, later].filter(Boolean).join(' · ')}
            </div>
          </li>
        )
      })}
    </ol>
    </>
  )
}

export function SenderPanel({ sender, hops }: { sender: SenderEvidence; hops: HopEntry[] }) {
  const [pathOpen, setPathOpen] = useState(false)  // collapsed by default: the path matters for the first outside hop, rarely for the rest
  const alignment = Object.entries(sender.alignment)
  return (
    <section className="view-card wb-panel" aria-label="Sender and authentication">
      <h2 className="wb-title">Sender and authentication</h2>
      <div className="wb-columns">
        <div>
          <h3 className="wb-subtitle">Addresses</h3>
          <table className="wb-table">
            <tbody>
              <tr><th scope="row">From</th><td className="wb-mono" dir="auto">{addr(sender.from_address)}</td></tr>
              <tr><th scope="row">Reply-To</th><td className="wb-mono" dir="auto">{addr(sender.reply_to)}</td></tr>
              <tr><th scope="row">Return-Path</th><td className="wb-mono" dir="auto">{addr(sender.return_path)}</td></tr>
            </tbody>
          </table>
          {sender.mismatches.length > 0 && (
            <ul className="wb-list">
              {sender.mismatches.map((m, i) => (
                <li key={i} className="wb-row wb-row--notice" dir="auto">{m}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h3 className="wb-subtitle">Authentication</h3>
          {!sender.trusted_receivers_configured && (
            <p className="wb-note">No trusted receivers are configured, so a result in the headers is a claim from an unknown source, not a verified check.</p>
          )}
          <table className="wb-table">
            <tbody>
              {sender.auth.map((row) => (
                <tr key={row.method}>
                  <th scope="row">{row.method.toUpperCase()}</th>
                  <td>{authText(row)}</td>
                </tr>
              ))}
              {alignment.map(([name, value]) => (
                <tr key={`al-${name}`}>
                  <th scope="row">{name.replaceAll('_', ' ')} aligned</th>
                  <td>{value === null ? 'not known' : value ? 'yes' : 'no'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div>
        <h3 className="wb-subtitle">Path the message took</h3>
        <button type="button" className="wb-toggle" aria-expanded={pathOpen} onClick={() => setPathOpen((o) => !o)}>
          {pathOpen ? 'Hide path' : `Show path (${hops.length} hop${hops.length === 1 ? '' : 's'})`}
        </button>
        {pathOpen && <HopTimeline hops={hops} />}
      </div>
    </section>
  )
}
