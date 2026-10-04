import type { AttachmentEntry } from '../types'
import { CopyButton } from './CopyButton'

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Metadata and hashes only. The file is never opened here and nothing offers it for download. */
export function AttachmentsPanel({ attachments }: { attachments: AttachmentEntry[] }) {
  return (
    <section className="view-card wb-panel" aria-label="Attachments">
      <h2 className="wb-title">Attachments ({attachments.length})</h2>
      <p className="wb-lead">Name, type, size and hash only. Attachments are never opened or offered for download, and their contents are not analysed.</p>
      {attachments.length === 0 ? (
        <p className="wb-note">No attachments.</p>
      ) : (
        <ul className="wb-list">
          {attachments.map((a, i) => (
            <li key={i} className={`wb-row${a.active_content || a.double_extension ? ' wb-row--notice' : ''}`}>
              <div className="wb-row-main">
                <strong className="wb-mono">{a.filename ?? '(no filename)'}</strong>
                <span className="wb-badge">{a.risk_class.replaceAll('_', ' ')}</span>
                {a.active_content && <span className="wb-badge wb-badge--warn">can run or contain code</span>}
                {a.double_extension && <span className="wb-badge wb-badge--warn">double extension</span>}
              </div>
              <div className="wb-small">
                {[a.declared_type ? `declared ${a.declared_type}` : 'no declared type', a.extension ? `extension .${a.extension}` : null, size(a.size_bytes)]
                  .filter(Boolean)
                  .join(' · ')}
              </div>
              <div className="wb-small">
                SHA-256 <span className="wb-mono">{a.sha256}</span> <CopyButton text={a.sha256} label="Copy hash" />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
