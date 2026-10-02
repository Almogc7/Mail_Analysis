import type { AnalysisJob } from './types'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function submitAnalysis(file: File): Promise<{ job_id: string; status: string }> {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch('/analyze', { method: 'POST', body: formData })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new ApiError(response.status, body.detail ?? 'Failed to submit file')
  }
  return response.json()
}

export async function getJob(jobId: string): Promise<AnalysisJob> {
  const response = await fetch(`/analyze/${jobId}`)
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new ApiError(response.status, body.detail ?? 'Failed to fetch job')
  }
  return response.json()
}

export async function submitFeedback(jobId: string, agree: boolean, note: string | null): Promise<void> {
  const response = await fetch(`/analyze/${jobId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agree, note }),
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    const detail = typeof body.detail === 'string' ? body.detail : 'Failed to record feedback'
    throw new ApiError(response.status, detail)
  }
}
