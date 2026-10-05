import type { Finding } from '../types'
import { FindingItem } from './FindingItem'
import { lowerSeverityNote } from './findingRules'

/**
 * The page groups findings by signal family, using the same tags the verdict floors read (evidence.family: sender, link, claim; set only on
 * structural signals). A finding with no such tag falls back to where it came from: the authentication module, the lookups, or the content
 * heuristics. Display only: nothing here changes a finding, a verdict or a score, and the per-module section below still lists every finding.
 */
export type FamilyKey = 'sender' | 'link' | 'claim' | 'content' | 'auth' | 'reputation'

const FAMILIES: { key: FamilyKey; title: string; note: string }[] = [
  { key: 'sender', title: 'Sender', note: 'where and how the message was sent from' },
  { key: 'link', title: 'Links', note: 'how the links and images are built' },
  { key: 'claim', title: 'Claims', note: 'who the message says it is, against who sent it' },
  { key: 'content', title: 'Content', note: 'wording and language' },
  { key: 'auth', title: 'Authentication', note: 'SPF, DKIM, DMARC and sender identity checks' },
  { key: 'reputation', title: 'Reputation lookups', note: 'what outside sources reported about hosts and files' },
]

const FLOOR_FAMILIES: FamilyKey[] = ['sender', 'link', 'claim']
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function familyOf(finding: Finding): FamilyKey {
  const tag = finding.evidence?.family
  if (tag === 'sender' || tag === 'link' || tag === 'claim') return tag
  if (finding.module === 'auth_check') return 'auth'
  if (finding.module === 'enrichment') return 'reputation'
  return 'content'
}

export function FindingsByFamily({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null
  const rank = (f: Finding) => {
    const i = SEVERITY_ORDER.indexOf(f.severity)
    return i === -1 ? SEVERITY_ORDER.length : i
  }
  const firedFloorFamilies = FLOOR_FAMILIES.filter((key) =>
    findings.some((f) => f.evidence?.structural === true && f.evidence?.family === key),
  )

  return (
    <section className="view-card wb-panel" aria-label="Findings by family">
      <h2 className="wb-title">Findings by signal family</h2>
      <p className="wb-lead">
        {firedFloorFamilies.length === 0
          ? 'No structural signal fired in the sender, link or claim families.'
          : `Structural signals fired in: ${firedFloorFamilies.join(', ')}.`}{' '}
        Different families corroborate each other; one family alone never raises the verdict.
      </p>
      {lowerSeverityNote(findings) && <p className="wb-note">{lowerSeverityNote(findings)}</p>}
      {FAMILIES.map(({ key, title, note }) => {
        const group = findings.filter((f) => familyOf(f) === key).sort((a, b) => rank(a) - rank(b))
        if (group.length === 0) return null
        return (
          <div key={key} aria-label={`${title} findings`} role="group">
            <h3 className="wb-subtitle">
              {title} ({group.length}) <span className="wb-note">{note}</span>
            </h3>
            {group.map((f, i) => (
              <FindingItem key={`${f.module}-${f.title}-${i}`} finding={f} />
            ))}
          </div>
        )
      })}
    </section>
  )
}
