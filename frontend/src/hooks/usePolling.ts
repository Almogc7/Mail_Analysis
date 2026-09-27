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

interface Snapshot {
  jobId: string | null
  job: AnalysisJob | null
  error: string | null
  timedOut: boolean
}

const EMPTY_SNAPSHOT: Omit<Snapshot, 'jobId'> = { job: null, error: null, timedOut: false }

export function usePolling(jobId: string | null, options: UsePollingOptions = {}): UsePollingResult {
  const intervalMs = options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS
  const timeoutMs = options.timeoutMs ?? DEFAULT_OVERALL_TIMEOUT_MS

  // Snapshot is tagged with the jobId it was captured for. Reading it below always checks
  // that tag against the *current* jobId prop and falls back to EMPTY_SNAPSHOT otherwise --
  // a synchronous, render-time guard. This matters because setState calls inside this
  // hook's effect (resetting state for a new jobId) don't apply until the *next* render;
  // App.tsx's own effect (which triggers the stage transition to "results") runs in the
  // *same* post-render effect flush and would otherwise still observe the previous job's
  // stale "done" data for one tick -- jumping straight back to the last analysis's result
  // before the new one has even started. Deriving from the tag sidesteps effect ordering
  // entirely instead of racing against it.
  const [snapshot, setSnapshot] = useState<Snapshot>({ jobId: null, ...EMPTY_SNAPSHOT })
  const [deadline, setDeadline] = useState(() => Date.now() + timeoutMs)

  const extendTimeout = () => {
    setSnapshot((s) => ({ ...s, timedOut: false }))
    setDeadline(Date.now() + timeoutMs)
  }

  const deadlineRef = useRef(deadline)
  deadlineRef.current = deadline

  useEffect(() => {
    if (!jobId) return

    const newDeadline = Date.now() + timeoutMs
    deadlineRef.current = newDeadline
    setDeadline(newDeadline)

    let cancelled = false
    let retries = 0
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      if (cancelled) return

      if (Date.now() > deadlineRef.current) {
        setSnapshot((s) => (s.jobId === jobId ? { ...s, timedOut: true } : { jobId, ...EMPTY_SNAPSHOT, timedOut: true }))
        timer = setTimeout(poll, intervalMs)
        return
      }

      try {
        const result = await getJob(jobId)
        if (cancelled) return
        retries = 0
        setSnapshot({ jobId, job: result, error: null, timedOut: false })
        if (result.status === 'done' || result.status === 'error') {
          return
        }
      } catch (err) {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 404) {
          setSnapshot({ jobId, job: null, error: 'Job not found -- the server may have restarted.', timedOut: false })
          return
        }
        retries += 1
        if (retries > MAX_TRANSIENT_RETRIES) {
          setSnapshot({
            jobId,
            job: null,
            error: err instanceof Error ? err.message : 'Failed to poll job status',
            timedOut: false,
          })
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
  }, [jobId, intervalMs, timeoutMs])

  const current = snapshot.jobId === jobId ? snapshot : { jobId, ...EMPTY_SNAPSHOT }

  return { job: current.job, error: current.error, timedOut: current.timedOut, extendTimeout }
}
