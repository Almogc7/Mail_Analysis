import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { CopyButton } from './CopyButton'

describe('CopyButton', () => {
  it('copies exactly the text it was given and says so', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<CopyButton text="hxxps://evil[.]example[.]org/a" label="Copy defanged" />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy defanged' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('hxxps://evil[.]example[.]org/a'))
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('reports a failed copy instead of pretending it worked', async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
    render(<CopyButton text="x" label="Copy" />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    expect(await screen.findByText('Copy failed')).toBeInTheDocument()
  })

  it('shows nothing about a copy until one is attempted', () => {
    render(<CopyButton text="x" label="Copy" />)
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('renders the label as text even if it looks like markup, and never renders the copied text at all', () => {
    const { container } = render(<CopyButton text="<img src=x onerror=alert(1)>" label="<b>Copy</b>" />)
    expect(container.querySelector('img, b, script')).toBeNull()
    expect(container.textContent).toBe('<b>Copy</b>')
  })
})
