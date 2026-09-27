import { useState } from 'react'
import type { ModuleResult } from '../types'
import { FindingItem } from './FindingItem'
import { EnrichmentRawData } from './EnrichmentRawData'

const MODULE_LABELS: Record<string, string> = {
  auth_check: 'Authentication & Identity',
  enrichment: 'URL / Attachment Enrichment',
  content_analysis: 'Content Heuristics',
}

interface ModulePanelProps {
  result: ModuleResult
}

export function ModulePanel({ result }: ModulePanelProps) {
  const [expanded, setExpanded] = useState(true)
  const label = MODULE_LABELS[result.module] ?? result.module
  const isError = result.status === 'error'
  const errorMessage = isError ? String(result.raw_data?.error ?? 'Unknown error') : null

  return (
    <section className={`module-panel${isError ? ' module-panel--error' : ''}`}>
      <button className="module-panel-header" onClick={() => setExpanded((v) => !v)} aria-expanded={expanded}>
        <span className="module-title">{label}</span>
        <span className={`module-status module-status--${result.status}`}>{result.status}</span>
        <span className="expand-caret">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <div className="module-panel-body">
          {isError ? (
            <p className="module-unavailable">This check could not run: {errorMessage}</p>
          ) : result.findings.length === 0 ? (
            <p className="module-clean">No findings.</p>
          ) : (
            result.findings.map((finding, i) => <FindingItem finding={finding} key={i} />)
          )}
          {result.module === 'enrichment' && result.raw_data && !isError && (
            <EnrichmentRawData rawData={result.raw_data} />
          )}
        </div>
      )}
    </section>
  )
}
