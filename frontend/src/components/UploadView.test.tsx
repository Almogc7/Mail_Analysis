import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { UploadView } from './UploadView'

function makeFile(name: string): File {
  return new File(['content'], name, { type: 'message/rfc822' })
}

describe('UploadView', () => {
  it('rejects a non .eml/.msg file before submit', () => {
    const onSubmit = vi.fn()
    render(<UploadView onSubmit={onSubmit} submitting={false} submitError={null} />)

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(fileInput, { target: { files: [makeFile('notes.txt')] } })

    expect(screen.getByText(/must be a \.eml or \.msg file/i)).toBeInTheDocument()
  })

  it('calls onSubmit with the file on valid submit', () => {
    const onSubmit = vi.fn()
    render(<UploadView onSubmit={onSubmit} submitting={false} submitError={null} />)

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = makeFile('sample.eml')
    fireEvent.change(fileInput, { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))

    expect(onSubmit).toHaveBeenCalledWith(file)
  })

  it('shows the server-side submit error when present', () => {
    render(<UploadView onSubmit={vi.fn()} submitting={false} submitError="File exceeds the limit" />)
    expect(screen.getByText('File exceeds the limit')).toBeInTheDocument()
  })
})
