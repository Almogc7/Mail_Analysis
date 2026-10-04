import type { CoverageItem } from '../types'

const STATUS_LABEL: Record<CoverageItem['status'], string> = {
  checked: 'Checked',
  partly: 'Partly checked',
  not_checked: 'Not checked',
}

function Row({ item }: { item: CoverageItem }) {
  return (
    <li className={`wb-row${item.status === 'checked' ? '' : ' wb-row--notice'}`}>
      <div className="wb-row-main">
        <strong>{item.area}</strong>
        {item.subject && <span className="wb-mono" dir="auto">{item.subject}</span>}
        <span className={`wb-badge${item.status === 'checked' ? '' : ' wb-badge--warn'}`}>{STATUS_LABEL[item.status]}</span>
        {item.by_design && <span className="wb-badge">never done, by design</span>}
        {item.blocks_no_indicators && <span className="wb-badge wb-badge--warn">blocks "No indicators found"</span>}
      </div>
      {item.detail && <div className="wb-small">{item.detail}</div>}
      {item.how_to_clear && <div className="wb-small">To clear: {item.how_to_clear}</div>}
    </li>
  )
}

/** What was checked, what was not, and why. Text only: the backend sends counts and plain words, never message content. */
export function CoveragePanel({ items }: { items: CoverageItem[] | null | undefined }) {
  if (!items) return null
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
          <ul className="wb-list">
            {gaps.map((item, i) => (
              <Row key={i} item={item} />
            ))}
          </ul>
        </div>
      )}
      {checked.length > 0 && (
        <div>
          <h3 className="wb-subtitle">Checked</h3>
          <ul className="wb-list">
            {checked.map((item, i) => (
              <Row key={i} item={item} />
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
