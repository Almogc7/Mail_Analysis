import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { usePolling } from './usePolling'
import type { AnalysisJob } from '../types'

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response
}

const INTERVAL_MS = 20

describe('usePolling', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('polls repeatedly and stops once status is done', async () => {
    const running: AnalysisJob = { job_id: '1', status: 'running', current_step: 'enrichment', result: null, error: null }
    const done: AnalysisJob = { job_id: '1', status: 'done', current_step: null, result: {} as never, error: null }

    let call = 0
    const fetchMock = vi.fn(async () => jsonResponse(call++ < 2 ? running : done))
    vi.stubGlobal('fetch', fetchMock)

    const { result } = renderHook(() => usePolling('1', { intervalMs: INTERVAL_MS }))

    await waitFor(() => expect(result.current.job?.status).toBe('done'))
    const callsAtDone = fetchMock.mock.calls.length

    await new Promise((r) => setTimeout(r, INTERVAL_MS * 5))
    expect(fetchMock.mock.calls.length).toBe(callsAtDone) // stopped polling after "done"
  })

  it('treats a 404 as a terminal error without retrying', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ detail: 'Unknown job_id' }, 404))
    vi.stubGlobal('fetch', fetchMock)

    const { result } = renderHook(() => usePolling('missing', { intervalMs: INTERVAL_MS }))

    await waitFor(() => expect(result.current.error).toContain('restarted'))

    await new Promise((r) => setTimeout(r, INTERVAL_MS * 5))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries transient network failures before giving up', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('network down')
    })
    vi.stubGlobal('fetch', fetchMock)

    const { result } = renderHook(() => usePolling('1', { intervalMs: INTERVAL_MS }))

    await waitFor(() => expect(result.current.error).toContain('network down'))
    // 1 initial attempt + up to 3 retries = 4 calls before giving up
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(4)
  })

  it('flips timedOut after the overall deadline elapses', async () => {
    const running: AnalysisJob = { job_id: '1', status: 'running', current_step: 'enrichment', result: null, error: null }
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(running)))

    const { result } = renderHook(() => usePolling('1', { intervalMs: INTERVAL_MS, timeoutMs: INTERVAL_MS * 2 }))

    expect(result.current.timedOut).toBe(false)
    await waitFor(() => expect(result.current.timedOut).toBe(true))
  })

  it('clears the previous job/error/timedOut state as soon as jobId changes, before the new poll resolves', async () => {
    const doneA: AnalysisJob = { job_id: 'a', status: 'done', current_step: null, result: { marker: 'A' } as never, error: null }
    const doneB: AnalysisJob = { job_id: 'b', status: 'done', current_step: null, result: { marker: 'B' } as never, error: null }

    let resolveSecondFetch: (() => void) | undefined
    const secondFetchGate = new Promise<void>((resolve) => {
      resolveSecondFetch = resolve
    })

    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/a')) return jsonResponse(doneA)
      // Hang the second job's fetch until we've had a chance to inspect the reset state.
      await secondFetchGate
      return jsonResponse(doneB)
    })
    vi.stubGlobal('fetch', fetchMock)

    const { result, rerender } = renderHook(({ jobId }) => usePolling(jobId, { intervalMs: INTERVAL_MS }), {
      initialProps: { jobId: 'a' as string | null },
    })

    await waitFor(() => expect(result.current.job?.job_id).toBe('a'))
    expect((result.current.job?.result as unknown as { marker: string }).marker).toBe('A')

    rerender({ jobId: 'b' })

    // This is the actual bug: checked synchronously, with NO waitFor. rerender() flushes
    // React's render + effect-commit synchronously, so if the guard were effect-based (fixed
    // by setState inside an effect) rather than a render-time derivation, this exact
    // assertion would still see A's stale "done" result here -- the setState wouldn't have
    // applied until a subsequent render. It must already be null on this very check.
    expect(result.current.job).toBeNull()

    resolveSecondFetch?.()
    await waitFor(() => expect(result.current.job?.job_id).toBe('b'))
    expect((result.current.job?.result as unknown as { marker: string }).marker).toBe('B')
  })
})
