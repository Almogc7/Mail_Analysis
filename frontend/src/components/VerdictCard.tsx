import type { AnalysisResult, Finding, V2Blocker, V2HardEvidence, V2Reason, VerdictV2 } from '../types'
import { SummaryCard } from './SummaryCard'

/**
 * The verdict card of verdict v2 (docs/UI_DESIGN.md 6, 8.2 and 13; docs/DESIGN_V2.md 2.1, 2.3, D1, D19, V13).
 *
 * Which card renders:
 *  - the result has `verdict_v2`: the tier card below, and the v1 verdict (label, value, score, confidence, overrides) appears nowhere on the page (V13);
 *  - it has `verdict_v2_status` but no `verdict_v2`: a neutral "Verdict unavailable" card with the coverage item's reason, no tier and no v1 label;
 *  - an OLD-shape result (no verdict_v2 and no verdict_v2_status field, such as a stored job): the old v1 card, unchanged.
 *
 * Every string shown here is fixed text of this file or text the API sent (reason and blocker text, finding titles the page already lists). Message content is plain text with dir="auto".
 */

const ROUTE_TEXT: Record<string, string> = {
  R1: 'Signals from two different families corroborate each other.',
  R2: 'A receiver you trust reported an authentication failure.',
  R3: 'The weighted score is in the suspicious band, with medium or stronger evidence from two classes.',
  R3B: 'The weighted score is 70 or more.',
  R4: 'Several strong content signals, plus a medium or stronger signal from another class.',
  R5: 'A provider reported a critical score, plus a medium or stronger signal from another class.',
  R6: 'A provider flagged a domain on your known-sender or own-domain list: an evidence conflict, which you decide.',
  HARD_EVIDENCE: 'Hard evidence from an independent source (listed below).',
  T4_POSITIVE_EVIDENCE: 'Positive evidence was found, and nothing that matters was left unchecked.',
  DEFAULT: 'There is not enough evidence either way.',
}

const NEEDS_ANALYST_REASON: Record<string, string> = {
  signals_present: 'Something was flagged, but not enough to call it either way.',
  no_signals_insufficient_evidence: 'Nothing was flagged, and nothing positive was established either.',
}

const HARD_EVIDENCE_RULE: Record<string, string> = {
  H1: 'Known malware sample (MalwareBazaar)',
  H2: 'Listed by ThreatFox with a confidence of at least 75',
  H3: 'At least 10 VirusTotal engines report it malicious',
}

const KIND_LABEL: Record<V2Reason['kind'], string> = {
  finding: 'finding',
  score: 'score',
  evidence_conflict: 'evidence conflict',
  gap: 'gap',
  positive_evidence: 'positive evidence',
}

/** Tier key to the CSS class of its outline (docs/UI_DESIGN.md 8.2) and the written label the API sent. */
const TIER_CLASS: Record<VerdictV2['tier'], string> = {
  confirmed_malicious: 'tier--malicious',
  suspicious: 'tier--suspicious',
  needs_analyst: 'tier--inconclusive',
  no_indicators_found: 'tier--none-found',
}

const MODULE_CLASS: Record<string, string> = { auth_check: 'auth', enrichment: 'enrichment', content_analysis: 'content' }

/** The reason class of a finding: the family tag it carries (sender, link, claim), else the class of its module. The same rule the backend table follows. */
export function reasonClass(finding: Finding): string {
  const family = finding.evidence?.family
  if (finding.evidence?.structural === true && (family === 'sender' || family === 'link' || family === 'claim')) return family
  return MODULE_CLASS[finding.module] ?? finding.module
}

function Reason({ reason, findings }: { reason: V2Reason; findings: Finding[] }) {
  const finding = reason.kind === 'finding' && reason.evidence_ref != null ? findings[Number(reason.evidence_ref)] : undefined
  return (
    <li className="tier-item" dir="auto">
      <span className="tier-item-badges">
        <span className="wb-badge">{finding ? reasonClass(finding) : KIND_LABEL[reason.kind]}</span>
        {finding && <span className="wb-badge">{finding.severity}</span>}
      </span>
      <span className="wb-text" dir="auto">{finding ? finding.title : reason.text}</span>
    </li>
  )
}

function Blockers({ blockers }: { blockers: V2Blocker[] }) {
  return (
    <div className="tier-blockers" role="group" aria-label="Blockers">
      <h3 className="tier-heading">Blockers: what was not checked</h3>
      {blockers.length === 0 ? (
        <p className="tier-none">None.</p>
      ) : (
        <ul className="tier-list">
          {blockers.map((b, i) => (
            <li key={`${b.code}-${b.detail ?? ''}-${i}`} className="tier-item tier-item--blocker" dir="auto">
              <span className="tier-item-badges">
                <span className="wb-badge wb-badge--warn">blocker</span>
                <span className="wb-badge wb-mono">{b.code}</span>
                {b.detail && <span className="wb-badge wb-mono">detail: {b.detail}</span>}
              </span>
              <span className="wb-text" dir="auto">{b.text}</span>
              <span className="wb-small" dir="auto">To clear: {b.how_to_clear}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function HardEvidence({ items }: { items: V2HardEvidence[] }) {
  return (
    <div className="tier-evidence">
      <h3 className="tier-heading">Hard evidence</h3>
      <ul className="tier-list">
        {items.map((h, i) => (
          <li key={i} className="tier-item" dir="auto">
            <span className="tier-item-badges">
              <span className="wb-badge wb-mono">{h.code}</span>
              <span className="wb-badge">{h.source}</span>
            </span>
            <span className="wb-mono" dir="auto">{h.indicator}</span>
            <span className="wb-small">{HARD_EVIDENCE_RULE[h.code] ?? ''}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function VerdictCardV2({ result, v2 }: { result: AnalysisResult; v2: VerdictV2 }) {
  const reasons = v2.reasons.filter((r) => r.kind !== 'evidence_conflict')
  const conflict = v2.reasons.find((r) => r.kind === 'evidence_conflict')
  return (
    <section className={`view-card tier ${TIER_CLASS[v2.tier]}`} aria-label="Verdict">
      <div className="tier-band">
        <h2 className="tier-label">{v2.label}</h2>
      </div>
      <div className="tier-body">
        <p className="tier-route">{ROUTE_TEXT[v2.route] ?? `Route: ${v2.route}`}</p>

        <Blockers blockers={v2.blockers} />

        {v2.tier === 'no_indicators_found' && (
          <div className="tier-neutral-note">
            <p className="tier-disclaimer">This is a statement about what was and was not found, not a safety verdict.</p>
            <p className="tier-route">A person decides. Never use it to auto-close, release or delete mail.</p>
          </div>
        )}

        {v2.tier === 'needs_analyst' && (
          <div className="tier-needs">
            {v2.needs_analyst_reason && <p className="tier-route">{NEEDS_ANALYST_REASON[v2.needs_analyst_reason] ?? v2.needs_analyst_reason}</p>}
            {v2.priority != null && (
              <p className="tier-priority">
                Queue priority (ordering aid, not a probability): <strong>{v2.priority.toFixed(1)}</strong>
              </p>
            )}
          </div>
        )}

        {v2.tier === 'confirmed_malicious' && v2.hard_evidence.length > 0 && <HardEvidence items={v2.hard_evidence} />}

        {conflict && (
          <div className="tier-conflict" role="group" aria-label="Evidence conflict">
            <h3 className="tier-heading">Evidence conflict</h3>
            <p className="tier-route" dir="auto">{conflict.text}</p>
          </div>
        )}

        <div className="tier-reasons">
          <h3 className="tier-heading">Reasons</h3>
          {reasons.length === 0 ? (
            <p className="tier-none">None listed.</p>
          ) : (
            <ul className="tier-list">
              {reasons.map((r, i) => (
                <Reason key={`${r.code}-${i}`} reason={r} findings={result.findings} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}

function VerdictUnavailable({ result }: { result: AnalysisResult }) {
  const item = (result.coverage_report ?? []).find((i) => i.reason === 'verdict_v2_unavailable')
  return (
    <section className="view-card tier tier--unavailable" aria-label="Verdict">
      <div className="tier-band">
        <h2 className="tier-label">Verdict unavailable</h2>
      </div>
      <div className="tier-body">
        <p className="tier-route">No verdict was built for this message, so none is shown. Read the findings and the coverage below.</p>
        <p className="wb-small">
          Reason: <span className="wb-mono">{item?.reason ?? 'verdict_v2_unavailable'}</span>
        </p>
        {item?.how_to_clear && <p className="wb-small" dir="auto">To clear: {item.how_to_clear}</p>}
      </div>
    </section>
  )
}

export function VerdictCard({ result }: { result: AnalysisResult }) {
  if (result.verdict_v2) return <VerdictCardV2 result={result} v2={result.verdict_v2} />
  if (result.verdict_v2_status != null) return <VerdictUnavailable result={result} />
  return <SummaryCard result={result} />
}
