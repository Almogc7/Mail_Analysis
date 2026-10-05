import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ImagesPanel } from './ImagesPanel'
import { ModuleDetailSection } from './ModuleDetailSection'
import { ResultsView } from './ResultsView'
import { makeAnalysisResult, makeEvidence, makeFinding, makeModuleResult } from '../test/fixtures'
import type { ImageEntry } from '../types'

const HEBREW = 'חשבונית חודשית לתשלום'
const image = (over: Partial<ImageEntry> = {}): ImageEntry => ({ source: 'html', host: 'track.example.org', url_defanged: 'hxxps://track[.]example[.]org/p.gif', filename: null, size_bytes: null, decoded: null, ...over })

describe('Images panel is collapsed by default', () => {
  it('shows a real button header with the count, aria-expanded false, and none of the content', () => {
    render(<ImagesPanel images={[image(), image({ url_defanged: null, filename: 'a.png', source: 'attachment' }), image(), image()]} />)
    const header = screen.getByRole('button', { name: 'Images (4)' })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(header.closest('h2')).not.toBeNull()
    expect(screen.queryByText(/QR codes in images are not decoded yet/)).toBeNull()
    expect(screen.queryByRole('list')).toBeNull()
  })

  it('opens and closes with the button, keeping the count and the aria state in step', () => {
    render(<ImagesPanel images={[image()]} />)
    const header = screen.getByRole('button', { name: 'Images (1)' })
    fireEvent.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('hxxps://track[.]example[.]org/p.gif')).toBeInTheDocument()
    fireEvent.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('hxxps://track[.]example[.]org/p.gif')).toBeNull()
  })

  it('still counts and, once opened, shows a Hebrew file name as text with dir="auto" on the UI-font class', () => {
    render(<ImagesPanel images={[image({ source: 'attachment', url_defanged: null, host: null, filename: `${HEBREW}.png` })]} />)
    expect(screen.queryByText(`${HEBREW}.png`)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Images (1)' }))
    const name = screen.getByText(`${HEBREW}.png`)
    expect(name).toHaveAttribute('dir', 'auto')
    expect(name).toHaveClass('wb-text')
  })
})

describe('Detail by module is collapsed by default', () => {
  const modules = [
    makeModuleResult({ module: 'auth_check', status: 'ok', findings: [makeFinding({ title: 'SPF failed' })] }),
    makeModuleResult({ module: 'enrichment', status: 'ok', findings: [] }),
    makeModuleResult({ module: 'content_analysis', status: 'ok', findings: [] }),
  ]

  it('shows a button header with the module count and no module content until opened', () => {
    render(<ModuleDetailSection modules={modules} />)
    const header = screen.getByRole('button', { name: 'Detail by module (3)' })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('Authentication & Identity')).toBeNull()
    fireEvent.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('Authentication & Identity')).toBeInTheDocument()
    expect(screen.getByText('SPF failed')).toBeInTheDocument()
  })

  it('in the results view the findings stay visible in the family panel while the module detail is closed', () => {
    const f = makeFinding({ title: 'SPF failed', module: 'auth_check' })
    const result = makeAnalysisResult({ findings: [f], module_results: [makeModuleResult({ module: 'auth_check', status: 'ok', findings: [f] })], evidence: makeEvidence(), coverage_report: [] })
    render(<ResultsView result={result} onReset={vi.fn()} />)
    expect(screen.getAllByText('SPF failed')).toHaveLength(1)
    expect(screen.getByRole('button', { name: /^Images \(/ })).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(screen.getByRole('button', { name: /^Detail by module/ }))
    expect(screen.getAllByText('SPF failed')).toHaveLength(2)
  })
})
