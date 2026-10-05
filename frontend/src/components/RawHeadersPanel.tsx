import { useState } from 'react'
import type { HeaderField } from '../types'
import { CopyButton } from './CopyButton'

interface RawHeadersPanelProps {
  headers: HeaderField[]
  /** Optional control from outside (the jump navigation opens the panel); without it the panel keeps its own state. */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

/** The raw header block as plain text, collapsed by default, with a copy button. */
export function RawHeadersPanel({ headers, open: controlledOpen, onOpenChange }: RawHeadersPanelProps) {
  const [ownOpen, setOwnOpen] = useState(false)
  const open = controlledOpen ?? ownOpen
  const setOpen = (next: (current: boolean) => boolean) => {
    const value = next(open)
    setOwnOpen(value)
    onOpenChange?.(value)
  }
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
