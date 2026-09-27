import type { LLMOpinion } from '../types'

export function LlmOpinionCard({ opinion }: { opinion: LLMOpinion }) {
  return (
    <div className="llm-opinion-card">
      <div className="llm-opinion-header">
        <span className="llm-badge">AI-generated commentary</span>
        <span className="llm-disclaimer">Explains the verdict above -- does not change it</span>
      </div>
      {opinion.status === 'ok' ? (
        <>
          <p className="llm-narrative">{opinion.narrative}</p>
          {opinion.flags.length > 0 && (
            <div className="llm-flags">
              <p className="llm-flags-heading">Worth a second look</p>
              <ul>
                {opinion.flags.map((flag, i) => (
                  <li key={i}>{flag}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : (
        <p className="llm-unavailable">
          LLM opinion {opinion.status}: {opinion.error ?? 'no details available'}
        </p>
      )}
    </div>
  )
}
