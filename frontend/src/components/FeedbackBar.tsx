import { useState } from 'react'
import { ApiError, submitFeedback } from '../api'

export const NOTE_MAX_CHARS = 500

interface FeedbackBarProps {
  jobId: string
}

type Status = 'idle' | 'sending' | 'recorded' | 'error'

/**
 * Analyst agree/disagree on a finished analysis. Stored locally by the backend as the file hash,
 * verdict and signal names only -- never email content. The optional note is the one free-text
 * field, so the UI says so. Disagreeing with a flagged verdict is what measures real-world
 * false positives over time.
 */
export function FeedbackBar({ jobId }: FeedbackBarProps) {
  const [choice, setChoice] = useState<boolean | null>(null)
  const [note, setNote] = useState('')
  const [status, setStatus] = useState<Status>('idle')
  const [error, setError] = useState<string | null>(null)

  const send = async (agree: boolean) => {
    setStatus('sending')
    setError(null)
    try {
      await submitFeedback(jobId, agree, note.trim() || null)
      setChoice(agree)
      setStatus('recorded')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not record feedback')
      setStatus('error')
    }
  }

  return (
    <section className="feedback-bar" aria-label="Analyst feedback">
      <h3 className="feedback-title">Do you agree with this verdict?</h3>
      <div className="feedback-actions">
        <button type="button" disabled={status === 'sending'} onClick={() => send(true)}>
          Agree
        </button>
        <button type="button" disabled={status === 'sending'} onClick={() => send(false)}>
          Disagree
        </button>
      </div>
      <label className="feedback-note">
        <span>Optional note (do not paste email content)</span>
        <textarea
          value={note}
          maxLength={NOTE_MAX_CHARS}
          rows={2}
          onChange={(e) => setNote(e.target.value)}
          placeholder="e.g. a newsletter I subscribed to"
        />
      </label>
      {status === 'recorded' && (
        <p className="feedback-status" role="status">
          Recorded: you {choice ? 'agree' : 'disagree'}. Saved locally as the file hash, verdict and signal names only.
        </p>
      )}
      {status === 'error' && (
        <p className="error-text" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}
