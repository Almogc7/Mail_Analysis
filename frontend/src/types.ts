// Mirrors backend/app/contracts/*.py exactly. Keep in sync by hand -- there is no shared
// schema generation between the two repos (same "no live cross-repo dependency" situation
// as the rest of the frontend, see the plan's note on why frontend reuse can't work like
// the backend's IOC_Enricher import bridge).

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type Verdict = 'malicious' | 'suspicious' | 'legit' | 'needs_review'
export type ModuleStatus = 'ok' | 'error' | 'skipped'
export type LlmStatus = 'ok' | 'unavailable' | 'error'
export type JobStatus = 'pending' | 'running' | 'done' | 'error'

export interface EmailAddress {
  display_name: string | null
  address: string | null
  domain: string | null
}

export interface HeaderField {
  name: string
  value: string
}

export interface ReceivedHop {
  raw: string
  from_host: string | null
  by_host: string | null
  timestamp: string | null
}

export interface ExtractedUrl {
  url: string
  source: 'body_text' | 'body_html' | 'attachment'
  anchor_text: string | null
  is_anchor_mismatch: boolean
}

export interface Attachment {
  filename: string | null
  content_type: string | null
  size_bytes: number
  sha256: string
  sha1: string
  md5: string
  is_inline: boolean
}

export interface ParsedEmail {
  source_format: 'eml' | 'msg'
  message_id: string | null
  subject: string | null
  date: string | null
  headers: HeaderField[]
  from_: EmailAddress
  to: EmailAddress[]
  cc: EmailAddress[]
  reply_to: EmailAddress[]
  return_path: EmailAddress | null
  received_chain: ReceivedHop[]
  authentication_results_raw: string[]
  body_text: string | null
  body_html: string | null
  urls: ExtractedUrl[]
  attachments: Attachment[]
  parse_warnings: string[]
  raw_size_bytes: number
}

export interface Finding {
  module: string
  severity: Severity
  title: string
  description: string
  evidence: Record<string, unknown>
  weight: number
}

export interface ModuleResult {
  module: string
  status: ModuleStatus
  findings: Finding[]
  raw_data: Record<string, unknown> | null
}

export interface CategoryScore {
  category: string
  subscore: number
  weight: number
  contribution: number
  coverage: number
  finding_count: number
}

export interface AppliedOverride {
  rule: string
  effect: string
  reason: string
}

export interface ScoringBreakdown {
  categories: CategoryScore[]
  weighted_score: number
  applied_overrides: AppliedOverride[]
}

export interface LLMOpinion {
  narrative: string
  flags: string[]
  model: string
  status: LlmStatus
  error: string | null
}

export interface AnalysisResult {
  parsed_email: ParsedEmail
  module_results: ModuleResult[]
  findings: Finding[]
  score: number | null
  verdict: Verdict | null
  confidence: number | null
  scoring: ScoringBreakdown | null
  llm_opinion: LLMOpinion | null
}

export interface AnalysisJob {
  job_id: string
  status: JobStatus
  current_step: string | null
  result: AnalysisResult | null
  error: string | null
}
