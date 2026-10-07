import { useState } from 'react'
import type { ChecksCompleted, CoverageItem } from '../types'

const STATUS_LABEL: Record<CoverageItem['status'], string> = {
  checked: 'Checked',
  partly: 'Partly checked',
  not_checked: 'Not checked',
}

function Row({ item }: { item: CoverageItem }) {
  return (
    <li className={`wb-row${item.status === 'checked' ? '' : ' wb-row--notice'}`} dir="auto">
      <div className="wb-row-main">
        <strong>{item.area}</strong>
        {item.subject && <span className="wb-mono" dir="auto">{item.subject}</span>}
        <span className={`wb-badge${item.status === 'checked' ? '' : ' wb-badge--warn'}`}>{STATUS_LABEL[item.status]}</span>
        {item.by_design && <span className="wb-badge">never done, by design</span>}
        {item.blocks_no_indicators && <span className="wb-badge wb-badge--warn">blocks "No indicators found"</span>}
      </div>
      {item.detail && <div className="wb-small" dir="auto">{item.detail}</div>}
      {item.how_to_clear && <div className="wb-small" dir="auto">To clear: {item.how_to_clear}</div>}
    </li>
  )
}

function List({ items }: { items: CoverageItem[] }) {
  return (
    <ul className="wb-list">
      {items.map((item, i) => (
        <Row key={i} item={item} />
      ))}
    </ul>
  )
}

/**
 * What was checked, what was not, and why. Text only: the backend sends counts and plain words, never message content.
 *
 * With `checks` (checks_completed from the API) the one completeness figure is "Checks completed: N of M, K not checked", taken from the API and not recounted here.
 * Items the tool never does by design are shown apart and are in none of the counts. Not-checked items are open by default; checked items are behind a count.
 * Without `checks` (an old stored result) the panel keeps its earlier wording.
 */
export function CoveragePanel({ items, checks }: { items: CoverageItem[] | null | undefined; checks?: ChecksCompleted | null }) {
  const [checkedOpen, setCheckedOpen] = useState(false)
  if (!items) return null
  if (!checks) return <OldCoveragePanel items={items} />

  const byDesign = items.filter((i) => i.by_design)
  const counted = items.filter((i) => !i.by_design)
  const checked = counted.filter((i) => i.status === 'checked')
  const gaps = counted.filter((i) => i.status !== 'checked')
  return (
    <section className="view-card wb-panel" aria-label="Coverage">
      <h2 className="wb-title">Coverage</h2>
      <p className="wb-lead">
        <strong className="coverage-figure">
          Checks completed: {checks.completed} of {checks.total}, {checks.not_checked} not checked
        </strong>
      </p>
      <p className="wb-lead">The tool never opens links or attachments.</p>
      <div>
        <h3 className="wb-subtitle">Not checked, and why</h3>
        {gaps.length === 0 ? <p className="wb-note">None.</p> : <List items={gaps} />}
      </div>
      {byDesign.length > 0 && (
        <div>
          <h3 className="wb-subtitle">Never done, by design (in none of the counts)</h3>
          <List items={byDesign} />
        </div>
      )}
      {checked.length > 0 && (
        <div>
          <h3 className="wb-title wb-title--toggle">
            <button type="button" className="wb-btn wb-disclosure" aria-expanded={checkedOpen} onClick={() => setCheckedOpen((o) => !o)}>
              <span className="wb-caret" aria-hidden="true">{checkedOpen ? '▾' : '▸'}</span>
              Checked ({checked.length})
            </button>
          </h3>
          {checkedOpen && <List items={checked} />}
        </div>
      )}
    </section>
  )
}

/** The panel of results from before checks_completed existed (a stored job): unchanged. */
function OldCoveragePanel({ items }: { items: CoverageItem[] }) {
  const checked = items.filter((i) => i.status === 'checked')
  const gaps = items.filter((i) => i.status !== 'checked')
  return (
    <section className="view-card wb-panel" aria-label="Coverage">
      <h2 className="wb-title">Coverage</h2>
      <p className="wb-lead">
        {gaps.length === 0 ? 'Every area this tool covers was checked.' : `${gaps.length} area${gaps.length === 1 ? '' : 's'} not fully checked.`} The
        tool never opens links or attachments.
      </p>
      {gaps.length > 0 && (
        <div>
          <h3 className="wb-subtitle">Not checked, and why</h3>
          <List items={gaps} />
        </div>
      )}
      {checked.length > 0 && (
        <div>
          <h3 className="wb-subtitle">Checked</h3>
          <List items={checked} />
        </div>
      )}
    </section>
  )
}
