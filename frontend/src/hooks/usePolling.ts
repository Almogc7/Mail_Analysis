import { useEffect, useRef, useState } from 'react'
import { ApiError, getJob } from '../api'
import type { AnalysisJob } from '../types'

const DEFAULT_POLL_INTERVAL_MS = 2000
const DEFAULT_OVERALL_TIMEOUT_MS = 8 * 60 * 1000
const MAX_TRANSIENT_RETRIES = 3

export interface UsePollingOptions {
  intervalMs?: number
  timeoutMs?: number
}

export interface UsePollingResult {
  job: AnalysisJob | null
  error: string | null
  timedOut: boolean
  extendTimeout: () => void
}

export function usePolling(jobId: string | null, options: UsePollingOptions = {}): UsePollingResult {
  const intervalMs = options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS
  const timeoutMs = options.timeoutMs ?? DEFAULT_OVERALL_TIMEOUT_MS

  const [job, setJob] = useState<AnalysisJob | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [timedOut, setTimedOut] = useState(false)
  const [deadline, setDeadline] = useState(() => Date.now() + timeoutMs)

  const extendTimeout = () => {
    setTimedOut(false)
    setDeadline(Date.now() + timeoutMs)
  }

  const deadlineRef = useRef(deadline)
  deadlineRef.current = deadline

  useEffect(() => {
    if (!jobId) return

    let cancelled = false
    let retries = 0
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      if (cancelled) return

      if (Date.now() > deadlineRef.current) {
        setTimedOut(true)
        timer = setTimeout(poll, intervalMs)
        return
      }

      try {
        const result = await getJob(jobId)
        if (cancelled) return
        retries = 0
        setJob(result)
        setError(null)
        if (result.status === 'done' || result.status === 'error') {
          return
        }
      } catch (err) {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 404) {
          setError('Job not found -- the server may have restarted.')
          return
        }
        retries += 1
        if (retries > MAX_TRANSIENT_RETRIES) {
          setError(err instanceof Error ? err.message : 'Failed to poll job status')
          return
        }
      }

      timer = setTimeout(poll, intervalMs)
    }

    poll()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [jobId, intervalMs])

  return { job, error, timedOut, extendTimeout }
}
