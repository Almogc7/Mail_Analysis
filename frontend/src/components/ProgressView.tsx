const STEP_LABELS: Record<string, string> = {
  parsing: 'Parsing email',
  auth_check: 'Checking SPF/DKIM/DMARC and sender identity',
  enrichment: 'Looking up URLs and attachment hashes against threat intel',
  content_analysis: 'Scanning content for phishing heuristics',
  scoring: 'Combining evidence into a verdict',
  llm_opinion: 'Generating analyst narrative',
}

interface ProgressViewProps {
  currentStep: string | null
  timedOut: boolean
  onKeepWaiting: () => void
}

export function ProgressView({ currentStep, timedOut, onKeepWaiting }: ProgressViewProps) {
  const label = currentStep ? (STEP_LABELS[currentStep] ?? currentStep) : 'Starting analysis…'

  return (
    <div className="view-card progress-view">
      <h2>Analyzing…</h2>
      <p className="current-step">{label}</p>
      <p className="hint">
        This can take a few minutes on emails with many links -- enrichment lookups are
        deliberately rate-limited to respect provider free-tier limits.
      </p>
      {timedOut && (
        <div className="timeout-notice">
          <p>This is taking longer than expected.</p>
          <button onClick={onKeepWaiting}>Keep waiting</button>
        </div>
      )}
    </div>
  )
}
