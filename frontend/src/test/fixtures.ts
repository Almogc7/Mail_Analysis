import type { AnalysisResult, Finding, ModuleResult, ParsedEmail } from '../types'

export function makeParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    source_format: 'eml',
    message_id: '<test@example.com>',
    subject: 'Test subject',
    date: null,
    headers: [],
    from_: { display_name: 'Alice', address: 'alice@example.com', domain: 'example.com' },
    to: [],
    cc: [],
    reply_to: [],
    return_path: null,
    received_chain: [],
    authentication_results_raw: [],
    body_text: 'hello',
    body_html: null,
    urls: [],
    attachments: [],
    parse_warnings: [],
    raw_size_bytes: 100,
    ...overrides,
  }
}

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    module: 'auth_check',
    severity: 'high',
    title: 'SPF check failed',
    description: "SPF authentication result was 'fail'.",
    evidence: { domain: 'evil.example.com' },
    weight: 25,
    ...overrides,
  }
}

export function makeModuleResult(overrides: Partial<ModuleResult> = {}): ModuleResult {
  return {
    module: 'auth_check',
    status: 'ok',
    findings: [],
    raw_data: null,
    ...overrides,
  }
}

export function makeAnalysisResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    parsed_email: makeParsedEmail(),
    module_results: [
      makeModuleResult({ module: 'auth_check' }),
      makeModuleResult({ module: 'enrichment' }),
      makeModuleResult({ module: 'content_analysis' }),
    ],
    findings: [],
    score: 0,
    verdict: 'legit',
    confidence: 1.0,
    scoring: {
      categories: [
        { category: 'auth_check', subscore: 0, weight: 0.35, contribution: 0, coverage: 1, finding_count: 0 },
        { category: 'enrichment', subscore: 0, weight: 0.4, contribution: 0, coverage: 1, finding_count: 0 },
        { category: 'content_analysis', subscore: 0, weight: 0.25, contribution: 0, coverage: 1, finding_count: 0 },
      ],
      weighted_score: 0,
      applied_overrides: [],
    },
    llm_opinion: null,
    ...overrides,
  }
}
