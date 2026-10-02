import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { FeedbackBar, NOTE_MAX_CHARS } from './FeedbackBar'

function mockFetch(response: { ok: boolean; status?: number; body?: unknown }) {
  const fn = vi.fn().mockResolvedValue({
    ok: response.ok,
    status: response.status ?? (response.ok ? 200 : 500),
    statusText: 'x',
    json: async () => response.body ?? {},
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => vi.unstubAllGlobals())

describe('FeedbackBar', () => {
  it('posts agree=true with no note to the job feedback endpoint', async () => {
    const fetchMock = mockFetch({ ok: true })
    render(<FeedbackBar jobId="job123" />)
    fireEvent.click(screen.getByRole('button', { name: 'Agree' }))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/you agree/i))
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/analyze/job123/feedback')
    expect(JSON.parse(init.body)).toEqual({ agree: true, note: null })
  })

  it('sends a trimmed note with a disagree', async () => {
    const fetchMock = mockFetch({ ok: true })
    render(<FeedbackBar jobId="j" />)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '  a newsletter I subscribed to  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Disagree' }))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/you disagree/i))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ agree: false, note: 'a newsletter I subscribed to' })
  })

  it('tells the analyst what is stored and warns against pasting email content', () => {
    render(<FeedbackBar jobId="j" />)
    expect(screen.getByText(/do not paste email content/i)).toBeInTheDocument()
  })

  it('caps the note at the backend limit', () => {
    render(<FeedbackBar jobId="j" />)
    expect(screen.getByRole('textbox')).toHaveAttribute('maxlength', String(NOTE_MAX_CHARS))
    expect(NOTE_MAX_CHARS).toBe(500)
  })

  it('shows the backend error and does not claim success', async () => {
    mockFetch({ ok: false, status: 409, body: { detail: 'Analysis is not finished' } })
    render(<FeedbackBar jobId="j" />)
    fireEvent.click(screen.getByRole('button', { name: 'Agree' }))

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Analysis is not finished'))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('disables both buttons while a request is in flight', async () => {
    let release: (v: unknown) => void = () => {}
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise((r) => (release = r))))
    render(<FeedbackBar jobId="j" />)
    fireEvent.click(screen.getByRole('button', { name: 'Agree' }))

    expect(screen.getByRole('button', { name: 'Agree' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Disagree' })).toBeDisabled()
    release({ ok: true, status: 200, statusText: 'x', json: async () => ({}) })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Agree' })).toBeEnabled())
  })
})
