import type { LinkEntry } from '../types'
import { CopyButton } from './CopyButton'

const KIND_LABEL: Record<LinkEntry['kind'], string> = {
  direct: 'direct',
  tracker: 'tracking link',
  wrapper: 'security wrapper',
  shortener: 'URL shortener',
  redirector: 'redirector',
  shared_platform: 'shared platform',
}

const STATUS_LABEL: Record<string, string> = {
  provider_hit: 'a provider reported it',
  checked_no_hit: 'checked, no hit',
  unknown: 'not found at any source',
  shared_platform: 'shared platform, not judged by host',
  not_looked_up: 'not looked up',
  manual_check: 'check by hand',
}

/** Links are shown as plain defanged text: never an anchor, never opened, never resolved. */
export function LinksPanel({ links }: { links: LinkEntry[] }) {
  return (
    <section className="view-card wb-panel" aria-label="Links">
      <h2 className="wb-title">Links ({links.length})</h2>
      <p className="wb-lead">Shown defanged and not clickable. The tool never opens or resolves a link, so where a redirect ends up is not known.</p>
      {links.length === 0 ? (
        <p className="wb-note">No links in the message.</p>
      ) : (
        <ul className="wb-list">
          {links.map((l, i) => (
            <li key={i} className={`wb-row${l.anchor_mismatch ? ' wb-row--notice' : ''}`}>
              <div className="wb-row-main">
                <span className="wb-mono">{l.url_defanged}</span>
                <CopyButton text={l.url_defanged} label="Copy defanged" title="Copies the defanged form, never the live URL" />
              </div>
              <div className="wb-small">
                <span className="wb-badge">{KIND_LABEL[l.kind] ?? l.kind}</span>{' '}
                {l.platform && <span className="wb-badge">{l.platform}</span>}{' '}
                <span className="wb-badge">{STATUS_LABEL[l.status] ?? l.status}</span>{' '}
                {l.anchor_mismatch && <span className="wb-badge wb-badge--warn">shown text names a different place</span>}{' '}
                {l.occurrences > 1 && <span className="wb-badge">seen {l.occurrences} times</span>}
              </div>
              {l.display_text && <div className="wb-small">Shown to the reader as: <span className="wb-mono">{l.display_text}</span></div>}
              {l.sources.length > 0 && <div className="wb-small">Found in: {l.sources.join(', ')}</div>}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
