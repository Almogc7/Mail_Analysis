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

export function HopTimeline({ hops }: { hops: HopEntry[] }) {
  if (hops.length === 0) return <p className="wb-note">No Received headers were present.</p>
  return (
    <ol className="hop-list" aria-label="Received hops, oldest first">
      {hops.map((h) => {
        const later = delay(h.delay_seconds_from_previous)
        return (
          <li key={h.index} className={`hop${h.is_origin ? ' hop--origin' : ''}${h.trusted_receiver ? ' hop--trusted' : ''}`}>
            <div className="wb-row-main">
              <strong>Hop {h.index}</strong>
              <span className="wb-mono">
                {h.from_host ?? 'unknown host'}
                {h.from_ip ? ` [${h.from_ip}]` : ''} to {h.by_host ?? 'unknown host'}
              </span>
              {h.is_origin && <span className="wb-badge wb-badge--info">entered the mail system here</span>}
              {h.trusted_receiver && <span className="wb-badge wb-badge--info">trusted receiver</span>}
              {h.clock_skew && <span className="wb-badge wb-badge--warn">timestamp earlier than the previous hop</span>}
              {h.local_submission && <span className="wb-badge">local submission</span>}
            </div>
            <div className="wb-small">
              {[h.protocol, h.tls ? 'TLS' : 'no TLS recorded', h.authenticated ? 'authenticated' : null, h.timestamp, later].filter(Boolean).join(' · ')}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

export function SenderPanel({ sender, hops }: { sender: SenderEvidence; hops: HopEntry[] }) {
  const alignment = Object.entries(sender.alignment)
  return (
    <section className="view-card wb-panel" aria-label="Sender and authentication">
      <h2 className="wb-title">Sender and authentication</h2>
      <div className="wb-columns">
        <div>
          <h3 className="wb-subtitle">Addresses</h3>
          <table className="wb-table">
            <tbody>
              <tr><th scope="row">From</th><td className="wb-mono">{addr(sender.from_address)}</td></tr>
              <tr><th scope="row">Reply-To</th><td className="wb-mono">{addr(sender.reply_to)}</td></tr>
              <tr><th scope="row">Return-Path</th><td className="wb-mono">{addr(sender.return_path)}</td></tr>
            </tbody>
          </table>
          {sender.mismatches.length > 0 && (
            <ul className="wb-list">
              {sender.mismatches.map((m, i) => (
                <li key={i} className="wb-row wb-row--notice">{m}</li>
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
                  <th scope="row">{name} aligned</th>
                  <td>{value === null ? 'not known' : value ? 'yes' : 'no'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div>
        <h3 className="wb-subtitle">Path the message took</h3>
        <HopTimeline hops={hops} />
      </div>
    </section>
  )
}
