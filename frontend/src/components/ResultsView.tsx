import type { AnalysisResult } from '../types'
import { SummaryCard } from './SummaryCard'
import { ModulePanel } from './ModulePanel'
import { LlmOpinionCard } from './LlmOpinionCard'
import { FeedbackBar } from './FeedbackBar'

const MODULE_ORDER = ['auth_check', 'enrichment', 'content_analysis']

interface ResultsViewProps {
  result: AnalysisResult
  onReset: () => void
  /** When present, the analyst can record agree/disagree for this analysis. */
  jobId?: string
}

export function ResultsView({ result, onReset, jobId }: ResultsViewProps) {
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

      {jobId && <FeedbackBar jobId={jobId} />}

      <button className="reset-button" onClick={onReset}>
        Analyze another email
      </button>
    </div>
  )
}
