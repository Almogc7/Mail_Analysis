import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ModulePanel } from './ModulePanel'
import { makeFinding, makeModuleResult } from '../test/fixtures'

describe('ModulePanel', () => {
  it('renders "No findings" for a clean ok module', () => {
    render(<ModulePanel result={makeModuleResult({ status: 'ok', findings: [] })} />)
    expect(screen.getByText('No findings.')).toBeInTheDocument()
  })

  it('renders findings for an ok module with findings', () => {
    render(<ModulePanel result={makeModuleResult({ status: 'ok', findings: [makeFinding()] })} />)
    expect(screen.getByText('SPF check failed')).toBeInTheDocument()
  })

  it('shows a muted unavailable message for a status=error module instead of hiding it', () => {
    const result = makeModuleResult({
      module: 'enrichment',
      status: 'error',
      findings: [],
      raw_data: { error: 'IOC_ENRICHER_PATH does not exist' },
    })
    render(<ModulePanel result={result} />)

    expect(screen.getByText(/this check could not run/i)).toBeInTheDocument()
    expect(screen.getByText(/IOC_ENRICHER_PATH does not exist/)).toBeInTheDocument()
  })
})
