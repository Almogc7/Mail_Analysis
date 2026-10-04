import type { AnalysisResult } from '../types'

const VERDICT_LABELS: Record<string, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  inconclusive: 'Inconclusive: analyst review',
  benign: 'No indicators found',
}

const INCONCLUSIVE_REASON: Record<string, string> = {
  signals_present: 'Something was flagged, but not enough to call it either way.',
  no_signals_insufficient_evidence: 'Nothing was flagged, and nothing positive was established either.',
}

const MAX_REASONS = 5

export function SummaryCard({ result }: { result: AnalysisResult }) {
  const verdict = result.verdict ?? 'inconclusive'
  const reasons: string[] = result.findings
    .filter((f) => f.severity !== 'info')
    .slice(0, MAX_REASONS)
    .map((f) => `${f.severity}: ${f.title}`)
  const inconclusive = result.scoring?.inconclusive_reason
  if (inconclusive && INCONCLUSIVE_REASON[inconclusive]) reasons.unshift(INCONCLUSIVE_REASON[inconclusive])
  const topDrivers = [...(result.scoring?.categories ?? [])]
    .sort((a, b) => b.contribution - a.contribution)
    .filter((c) => c.contribution > 0)

  return (
    <div className="view-card summary-card">
      <div className={`verdict-banner verdict-${verdict}`}>
        <span className="verdict-label">{VERDICT_LABELS[verdict] ?? verdict}</span>
        <span className="score-label">{result.score ?? '—'}/100</span>
      </div>
      {verdict === 'benign' && (
        <p className="benign-note">
          This is a statement about what was and was not found, not a safety verdict. What was not checked is listed below. A person
          decides. Never use it to auto-close, release or delete mail.
        </p>
      )}
      <p className="confidence-line">
        Confidence: {result.confidence !== null ? `${Math.round(result.confidence * 100)}%` : 'n/a'}
      </p>

      <div className="why-list">
        <p className="top-drivers-heading">Why</p>
        <ul>
          {reasons.length === 0 ? (
            <li>No finding above info severity.</li>
          ) : (
            reasons.map((r, i) => <li key={i} dir="auto">{r}</li>)
          )}
        </ul>
      </div>

      {topDrivers.length > 0 && (
        <div className="top-drivers">
          <p className="top-drivers-heading">Top drivers</p>
          <ul>
            {topDrivers.map((c) => (
              <li key={c.category}>
                {c.category}: {c.contribution.toFixed(1)} pts (subscore {c.subscore}, weight {c.weight})
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.scoring && result.scoring.applied_overrides.length > 0 && (
        <div className="applied-overrides">
          <p className="overrides-heading">Overrides applied</p>
          <ul>
            {result.scoring.applied_overrides.map((o, i) => (
              <li key={i}>
                <strong>{o.effect}</strong> — {o.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
