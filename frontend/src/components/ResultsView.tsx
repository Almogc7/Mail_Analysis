import { useRef, useState } from 'react'
import type { AnalysisResult } from '../types'
import { VerdictCard } from './VerdictCard'
import { ModuleDetailSection } from './ModuleDetailSection'
import { LlmOpinionCard } from './LlmOpinionCard'
import { FeedbackBar } from './FeedbackBar'
import { IndicatorsPanel } from './IndicatorsPanel'
import { CoveragePanel } from './CoveragePanel'
import { SenderPanel } from './SenderPanel'
import { LinksPanel } from './LinksPanel'
import { AttachmentsPanel } from './AttachmentsPanel'
import { BodyPanel } from './BodyPanel'
import { ImagesPanel } from './ImagesPanel'
import { RawHeadersPanel } from './RawHeadersPanel'
import { FindingsByFamily } from './FindingsByFamily'
import { JumpNav } from './JumpNav'
import { JUMP_TARGETS, jumpToPanel } from './jumpToPanel'

const MODULE_ORDER = ['auth_check', 'enrichment', 'content_analysis']

interface ResultsViewProps {
  result: AnalysisResult
  onReset: () => void
  /** When present, the analyst can record agree/disagree for this analysis. */
  jobId?: string
}

/**
 * Page order (docs/DESIGN_V2.md, phase A): verdict and reasons, a row of jump buttons, findings by signal family, coverage, sender and path, links, attachments, body, images, indicators,
 * the per-module detail, raw headers, the LLM opinion, feedback. The evidence panels appear only when the backend sent an evidence block, so an
 * older result still renders as before.
 */
export function ResultsView({ result, onReset, jobId }: ResultsViewProps) {
  const orderedModules = [...result.module_results].sort(
    (a, b) => MODULE_ORDER.indexOf(a.module) - MODULE_ORDER.indexOf(b.module),
  )
  const evidence = result.evidence
  const rootRef = useRef<HTMLDivElement>(null)
  const [rawHeadersOpen, setRawHeadersOpen] = useState(false)

  // The jump row lists only the panels this result actually renders (the same conditions the panels below use).
  const indicators = result.indicators
  const present: Record<string, boolean> = {
    'Findings by family': result.findings.length > 0,
    Coverage: !!result.coverage_report,
    'Sender and authentication': !!evidence,
    Links: !!evidence,
    Attachments: !!evidence,
    Body: !!evidence,
    Indicators: !!indicators && (indicators.indicators.length > 0 || (indicators.hidden_by_config_count ?? 0) > 0),
    'Raw headers': !!evidence,
  }
  const jumpTargets = JUMP_TARGETS.filter((t) => present[t.panel])
  const jump = (panel: string) => {
    if (panel === 'Raw headers') setRawHeadersOpen(true)  // a panel that is collapsed is opened on arrival
    if (rootRef.current) jumpToPanel(rootRef.current, panel)
  }

  return (
    <div className="results-view" ref={rootRef}>
      <VerdictCard result={result} />

      <JumpNav targets={jumpTargets} onJump={(t) => jump(t.panel)} />

      <FindingsByFamily findings={result.findings} />

      <CoveragePanel items={result.coverage_report} />

      {evidence && (
        <>
          <SenderPanel sender={evidence.sender} hops={evidence.hop_timeline} />
          <LinksPanel links={evidence.links} />
          <AttachmentsPanel attachments={evidence.attachments} />
          <BodyPanel body={evidence.body} text={result.parsed_email.body_text} />
          <ImagesPanel images={evidence.images} />
        </>
      )}

      <IndicatorsPanel pack={result.indicators} coverage={result.coverage_report} />

      <ModuleDetailSection modules={orderedModules} />

      {evidence && <RawHeadersPanel headers={result.parsed_email.headers} open={rawHeadersOpen} onOpenChange={setRawHeadersOpen} />}

      {result.llm_opinion && <LlmOpinionCard opinion={result.llm_opinion} />}

      {jobId && <FeedbackBar jobId={jobId} />}

      <button className="reset-button" onClick={onReset}>
        Analyze another email
      </button>
    </div>
  )
}
