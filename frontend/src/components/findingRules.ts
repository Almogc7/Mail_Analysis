import type { Finding, Severity } from '../types'

/** Medium, high and critical findings start expanded; low and info start collapsed. Display only: no finding is removed and the order never changes. */
const EXPANDED_BY_DEFAULT: ReadonlySet<Severity> = new Set<Severity>(['medium', 'high', 'critical'])

export function startsExpanded(severity: Severity): boolean {
  return EXPANDED_BY_DEFAULT.has(severity)
}

/** "3 lower-severity findings (low or info) start collapsed", or null when none do. The words say "start": the reader can open any of them. */
export function lowerSeverityNote(findings: Finding[]): string | null {
  const n = findings.filter((f) => !startsExpanded(f.severity)).length
  if (n === 0) return null
  return n === 1 ? '1 lower-severity finding (low or info) starts collapsed' : `${n} lower-severity findings (low or info) start collapsed`
}
