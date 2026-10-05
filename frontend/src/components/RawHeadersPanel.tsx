import { useState } from 'react'
import type { HeaderField } from '../types'
import { CopyButton } from './CopyButton'

/** The raw header block as plain text, collapsed by default, with a copy button. */
export function RawHeadersPanel({ headers }: { headers: HeaderField[] }) {
  const [open, setOpen] = useState(false)
  const text = headers.map((h) => `${h.name}: ${h.value}`).join('\n')
  return (
    <section className="view-card wb-panel" aria-label="Raw headers">
      <h2 className="wb-title">Raw headers ({headers.length})</h2>
      <div className="wb-row-main">
        <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? 'Hide headers' : 'Show headers'}
        </button>
        <CopyButton text={text} label="Copy headers" />
      </div>
      {open && (headers.length === 0 ? <p className="wb-note">No headers.</p> : <pre className="wb-pre" tabIndex={0} aria-label="Header text" dir="auto">{text}</pre>)}
    </section>
  )
}
