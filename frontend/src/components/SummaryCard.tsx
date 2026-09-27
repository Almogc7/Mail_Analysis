import type { AnalysisResult } from '../types'

const VERDICT_LABELS: Record<string, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  needs_review: 'Needs Manual Review',
  legit: 'Legit',
}

export function SummaryCard({ result }: { result: AnalysisResult }) {
  const verdict = result.verdict ?? 'needs_review'
  const topDrivers = [...(result.scoring?.categories ?? [])]
    .sort((a, b) => b.contribution - a.contribution)
    .filter((c) => c.contribution > 0)

  return (
    <div className="view-card summary-card">
      <div className={`verdict-banner verdict-${verdict}`}>
        <span className="verdict-label">{VERDICT_LABELS[verdict] ?? verdict}</span>
        <span className="score-label">{result.score ?? '—'}/100</span>
      </div>
      <p className="confidence-line">
        Confidence: {result.confidence !== null ? `${Math.round(result.confidence * 100)}%` : 'n/a'}
      </p>

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
