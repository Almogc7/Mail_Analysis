import { useState } from 'react'
import type { Indicator, IndicatorPack, IndicatorStatus } from '../types'

const STATUS_LABELS: Record<IndicatorStatus, string> = {
  provider_hit: 'A source reported something',
  unknown: 'Unknown: check by hand',
  shared_platform: 'Shared platform: check by hand',
  not_looked_up: 'Not looked up: check by hand',
  internal: 'Internal name, not sent anywhere: check by hand',
  nothing_found: 'Nothing found (not proof of safety)',
  'n/a': '',
}

const KIND_LABELS: Record<Indicator['kind'], string> = {
  domain: 'Domains',
  ip: 'IP addresses',
  email: 'Email addresses',
  hash: 'File hashes',
}

const KIND_ORDER: Indicator['kind'][] = ['domain', 'ip', 'email', 'hash']

/** Make an indicator safe to paste into a ticket or chat: it can no longer be clicked or auto-linked. */
export function defang(kind: Indicator['kind'], value: string): string {
  if (kind === 'hash') return value
  const dotted = value.replace(/\./g, '[.]')
  return kind === 'email' ? dotted.replace('@', '[@]') : dotted
}

/** Spreadsheet programs run a cell that starts with = + - @ as a formula; neutralise that. */
function csvCell(text: string): string {
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

export function indicatorsToCsv(indicators: Indicator[], defanged: boolean): string {
  const header = ['kind', 'indicator', 'status', 'manual_check', 'seen_in', 'count', 'note']
  const rows = indicators.map((i) => [
    i.kind,
    defanged ? defang(i.kind, i.value) : i.value,
    i.status,
    i.manual_check ? 'yes' : 'no',
    i.seen_in.join('; '),
    String(i.count),
    i.note,
  ])
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\n') + '\n'
}

export function indicatorsToText(indicators: Indicator[], defanged: boolean): string {
  return indicators.map((i) => (defanged ? defang(i.kind, i.value) : i.value)).join('\n')
}

async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

function downloadCsv(csv: string) {
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = 'indicators.csv'
  a.click()
  URL.revokeObjectURL(url)
}

export function IndicatorsPanel({ pack }: { pack: IndicatorPack | null | undefined }) {
  const [onlyManual, setOnlyManual] = useState(false)
  const [message, setMessage] = useState('')
  const hiddenCount = pack?.hidden_by_config_count ?? 0
  if (!pack || (pack.indicators.length === 0 && hiddenCount === 0)) return null

  const shown = pack.indicators.filter((i) => !onlyManual || i.manual_check)
  const run = async (label: string, text: string) => setMessage((await copy(text)) ? `${label}: copied` : `${label}: copy failed`)

  return (
    <section className="view-card indicators-panel" aria-label="Indicators">
      <h2 className="indicators-title">Indicators to check</h2>
      <p className="indicators-lead">
        Everything the message contains, in one place. This list adds nothing to the verdict.{' '}
        <strong>{pack.manual_check_count}</strong> need a manual check: the app could not judge them, which is not the same as
        clean. The links open third-party sites only when you click them.
      </p>

      {hiddenCount > 0 && (
        <p className="indicators-lead">
          {hiddenCount} indicator{hiddenCount === 1 ? '' : 's'} hidden by local config (addresses of your own mail systems). Raw headers still show everything.
        </p>
      )}

      <div className="indicators-toolbar">
        <label>
          <input type="checkbox" checked={onlyManual} onChange={(e) => setOnlyManual(e.target.checked)} /> Only manual checks
        </label>
        <button onClick={() => run('Raw list', indicatorsToText(shown, false))}>Copy list</button>
        <button onClick={() => run('Defanged list', indicatorsToText(shown, true))}>Copy defanged</button>
        <button onClick={() => downloadCsv(indicatorsToCsv(shown, true))}>Download CSV (defanged)</button>
        <span className="indicators-message" role="status">{message}</span>
      </div>

      {KIND_ORDER.map((kind) => {
        const group = shown.filter((i) => i.kind === kind)
        if (group.length === 0) return null
        return (
          <div key={kind} className="indicators-group">
            <h3>{KIND_LABELS[kind]} ({group.length})</h3>
            <ul className="indicator-list">
              {group.map((i) => (
                <li key={`${i.kind}:${i.value}`} className={`indicator indicator--${i.status}`}>
                  <div className="indicator-main">
                    <code className="indicator-value">{i.value}</code>
                    {i.filename && <span className="indicator-file"> ({i.filename})</span>}
                    {STATUS_LABELS[i.status] && (
                      <span className={`indicator-status indicator-status--${i.status}`}>{STATUS_LABELS[i.status]}</span>
                    )}
                    <button className="indicator-copy" onClick={() => run(i.value, i.value)} aria-label={`Copy ${i.value}`}>
                      Copy
                    </button>
                  </div>
                  <div className="indicator-seen">
                    Seen as: {i.seen_in.join('; ')}
                    {i.count > 1 ? ` (${i.count} times)` : ''}
                  </div>
                  {i.note && <div className="indicator-note">{i.note}</div>}
                  {Object.keys(i.providers).length > 0 && (
                    <div className="indicator-providers">
                      {Object.entries(i.providers).map(([name, state]) => `${name}: ${state}`).join(' · ')}
                    </div>
                  )}
                  {i.pivots.length > 0 && (
                    <div className="indicator-pivots">
                      Look up:{' '}
                      {i.pivots.map((p) => (
                        <a key={p.name} href={p.url} target="_blank" rel="noopener noreferrer">
                          {p.name}
                        </a>
                      ))}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </section>
  )
}
