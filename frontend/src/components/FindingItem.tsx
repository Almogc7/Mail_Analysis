import { useState } from 'react'
import type { Finding } from '../types'
import { startsExpanded } from './findingRules'

function formatEvidenceValue(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

/**
 * One finding. The header is a real button (aria-expanded) and always shows the severity word and the title. Medium, high and critical findings start
 * expanded (description and evidence); low and info start collapsed. Every finding stays in the DOM, in the order it was given.
 */
export function FindingItem({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(startsExpanded(finding.severity))
  const hasEvidence = Object.keys(finding.evidence).length > 0

  return (
    <div className={`finding-item severity-${finding.severity}`}>
      <button className="finding-header" onClick={() => setExpanded((v) => !v)} aria-expanded={expanded}>
        <span className="severity-badge">{finding.severity}</span>
        <span className="finding-title" dir="auto">{finding.title}</span>
        <span className="expand-caret" aria-hidden="true">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <>
          <p className="finding-description" dir="auto">{finding.description}</p>
          {hasEvidence && (
            <dl className="finding-evidence">
              {Object.entries(finding.evidence).map(([key, value]) => (
                <div className="evidence-row" key={key}>
                  <dt>{key}</dt>
                  <dd dir="auto">{formatEvidenceValue(value)}</dd>
                </div>
              ))}
            </dl>
          )}
        </>
      )}
    </div>
  )
}
