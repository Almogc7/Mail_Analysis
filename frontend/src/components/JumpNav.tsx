import type { JumpTarget } from './jumpToPanel'

/** A compact row of buttons (never links) that jump to a panel. Plain native buttons, so Tab and Enter or Space work without extra code. */
export function JumpNav({ targets, onJump }: { targets: readonly JumpTarget[]; onJump: (target: JumpTarget) => void }) {
  if (targets.length === 0) return null
  return (
    <nav className="wb-nav" aria-label="Jump to a panel">
      <span className="wb-nav-label">Jump to</span>
      {targets.map((t) => (
        <button key={t.panel} type="button" className="wb-btn" onClick={() => onJump(t)}>
          {t.label}
        </button>
      ))}
    </nav>
  )
}
