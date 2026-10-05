/** The panels the jump row can reach: the visible label, and the aria-label of the panel's <section>. */
export const JUMP_TARGETS = [
  { label: 'Findings', panel: 'Findings by family' },
  { label: 'Coverage', panel: 'Coverage' },
  { label: 'Sender', panel: 'Sender and authentication' },
  { label: 'Links', panel: 'Links' },
  { label: 'Attachments', panel: 'Attachments' },
  { label: 'Body', panel: 'Body' },
  { label: 'Indicators', panel: 'Indicators' },
  { label: 'Raw headers', panel: 'Raw headers' },
] as const

export type JumpTarget = (typeof JUMP_TARGETS)[number]

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/**
 * Scrolls a panel into view and moves keyboard focus to its heading (tabindex -1, so it can take focus without joining the tab order). The scroll is
 * smooth unless the reader asked for reduced motion, in which case it jumps ("auto"). Returns false when the panel is not on the page.
 */
export function jumpToPanel(root: HTMLElement, panel: string): boolean {
  const section = Array.from(root.querySelectorAll<HTMLElement>('section[aria-label]')).find((s) => s.getAttribute('aria-label') === panel)
  if (!section) return false
  section.scrollIntoView?.({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' })
  const heading = section.querySelector<HTMLElement>('h2')
  if (heading) {
    heading.tabIndex = -1
    heading.focus({ preventScroll: true })
  }
  return true
}
