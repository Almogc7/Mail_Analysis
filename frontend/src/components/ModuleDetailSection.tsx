import { useState } from 'react'
import type { ModuleResult } from '../types'
import { ModulePanel } from './ModulePanel'

/** The per-module detail, collapsed by default. The header is a real button (aria-expanded) and shows how many modules are inside. */
export function ModuleDetailSection({ modules }: { modules: ModuleResult[] }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="wb-section" aria-label="Detail by module">
      <h2 className="wb-title wb-title--toggle">
        <button type="button" className="wb-btn wb-disclosure" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          <span className="wb-caret" aria-hidden="true">{open ? '▾' : '▸'}</span>
          Detail by module ({modules.length})
        </button>
      </h2>
      {open && (
        <div className="module-panels">
          {modules.map((m) => (
            <ModulePanel result={m} key={m.module} />
          ))}
        </div>
      )}
    </section>
  )
}
