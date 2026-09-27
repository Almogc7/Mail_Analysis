import { useState } from 'react'
import type { Finding } from '../types'

function formatEvidenceValue(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

export function FindingItem({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const hasEvidence = Object.keys(finding.evidence).length > 0

  return (
    <div className={`finding-item severity-${finding.severity}`}>
      <button
        className="finding-header"
        onClick={() => setExpanded((v) => !v)}
        disabled={!hasEvidence}
        aria-expanded={expanded}
      >
        <span className="severity-badge">{finding.severity}</span>
        <span className="finding-title">{finding.title}</span>
        {hasEvidence && <span className="expand-caret">{expanded ? '▾' : '▸'}</span>}
      </button>
      <p className="finding-description">{finding.description}</p>
      {expanded && hasEvidence && (
        <dl className="finding-evidence">
          {Object.entries(finding.evidence).map(([key, value]) => (
            <div className="evidence-row" key={key}>
              <dt>{key}</dt>
              <dd>{formatEvidenceValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}
