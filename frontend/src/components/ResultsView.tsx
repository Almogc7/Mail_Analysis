import type { AnalysisResult } from '../types'
import { SummaryCard } from './SummaryCard'
import { ModulePanel } from './ModulePanel'
import { LlmOpinionCard } from './LlmOpinionCard'

const MODULE_ORDER = ['auth_check', 'enrichment', 'content_analysis']

interface ResultsViewProps {
  result: AnalysisResult
  onReset: () => void
}

export function ResultsView({ result, onReset }: ResultsViewProps) {
  const orderedModules = [...result.module_results].sort(
    (a, b) => MODULE_ORDER.indexOf(a.module) - MODULE_ORDER.indexOf(b.module),
  )

  return (
    <div className="results-view">
      <SummaryCard result={result} />

      <div className="module-panels">
        {orderedModules.map((m) => (
          <ModulePanel result={m} key={m.module} />
        ))}
      </div>

      {result.llm_opinion && <LlmOpinionCard opinion={result.llm_opinion} />}

      <button className="reset-button" onClick={onReset}>
        Analyze another email
      </button>
    </div>
  )
}
