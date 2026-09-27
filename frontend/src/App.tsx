import { useEffect, useState } from 'react'
import { submitAnalysis, ApiError } from './api'
import { usePolling } from './hooks/usePolling'
import { UploadView } from './components/UploadView'
import { ProgressView } from './components/ProgressView'
import { ResultsView } from './components/ResultsView'
import { ErrorView } from './components/ErrorView'
import type { AnalysisResult } from './types'
import './app.css'

type Stage =
  | { name: 'upload' }
  | { name: 'in_progress'; jobId: string }
  | { name: 'results'; result: AnalysisResult }
  | { name: 'error'; message: string }

function App() {
  const [stage, setStage] = useState<Stage>({ name: 'upload' })
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const jobId = stage.name === 'in_progress' ? stage.jobId : null
  const { job, error: pollError, timedOut, extendTimeout } = usePolling(jobId)

  useEffect(() => {
    if (stage.name !== 'in_progress') return
    if (pollError) {
      setStage({ name: 'error', message: pollError })
      return
    }
    if (job?.status === 'done' && job.result) {
      setStage({ name: 'results', result: job.result })
    } else if (job?.status === 'error') {
      setStage({ name: 'error', message: job.error ?? 'Analysis failed for an unknown reason.' })
    }
  }, [stage.name, job, pollError])

  const handleSubmit = async (file: File) => {
    setSubmitting(true)
    setSubmitError(null)
    try {
      const { job_id } = await submitAnalysis(file)
      setStage({ name: 'in_progress', jobId: job_id })
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err.message : 'Failed to submit file')
    } finally {
      setSubmitting(false)
    }
  }

  const reset = () => setStage({ name: 'upload' })

  return (
    <main className="app-shell">
      {stage.name === 'upload' && (
        <UploadView onSubmit={handleSubmit} submitting={submitting} submitError={submitError} />
      )}
      {stage.name === 'in_progress' && (
        <ProgressView currentStep={job?.current_step ?? null} timedOut={timedOut} onKeepWaiting={extendTimeout} />
      )}
      {stage.name === 'results' && <ResultsView result={stage.result} onReset={reset} />}
      {stage.name === 'error' && <ErrorView message={stage.message} onReset={reset} />}
    </main>
  )
}

export default App
