import type { CoverageItem, Indicator, IndicatorStatus } from '../types'

/**
 * Amber is only for an indicator the app could not judge AND that blocks "No indicators found". The coverage report already says which gaps block:
 * a shared-platform host maps to the coverage item with reason "shared_platform" and an internal-looking name to "internal_host_not_sent", and
 * the indicator is amber only if that coverage item carries blocks_no_indicators. A result without a coverage report (an older backend) falls back to
 * the status itself, which names the same two cases. Everything else (unknown, not looked up) is shown plainly, with its words.
 */
const BLOCKING_COVERAGE_REASON: Partial<Record<IndicatorStatus, string>> = { shared_platform: 'shared_platform', internal: 'internal_host_not_sent' }

export function blocksNoIndicators(i: Indicator, coverage: CoverageItem[] | null | undefined): boolean {
  if (i.gateway) return false
  const reason = BLOCKING_COVERAGE_REASON[i.status]
  if (!reason) return false
  if (!coverage) return true
  return coverage.some((c) => c.reason === reason && c.blocks_no_indicators)
}

/**
 * "Not looked up (by design)" is only claimed when the coverage report shows the lookups ran and none were cut short. There is no per-indicator reason
 * code, so when enrichment did not run or the per-email limit was reached (either could be why THIS one was skipped) the plain wording stays.
 */
export function notLookedUpByDesign(i: Indicator, coverage: CoverageItem[] | null | undefined): boolean {
  if (i.gateway || i.status !== 'not_looked_up' || !coverage) return false
  return !coverage.some((c) => c.reason === 'enrichment_did_not_run' || c.reason === 'limit_reached')
}
