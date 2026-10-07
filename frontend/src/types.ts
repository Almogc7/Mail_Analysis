// Mirrors backend/app/contracts/*.py exactly. Keep in sync by hand -- there is no shared
// schema generation between the backend and the frontend.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type Verdict = 'malicious' | 'suspicious' | 'benign' | 'inconclusive'
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
  /** A stable, content-free identifier of the KIND of finding (backend app/finding_codes.py). Not shown anywhere yet. */
  code?: string | null
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
  inconclusive_reason?: string | null
  priority?: number
}

export interface LLMOpinion {
  narrative: string
  flags: string[]
  model: string
  status: LlmStatus
  error: string | null
}

export type IndicatorStatus =
  | 'provider_hit'
  | 'unknown'
  | 'shared_platform'
  | 'not_looked_up'
  | 'internal'
  | 'nothing_found'
  | 'n/a'

export interface Pivot {
  name: string
  url: string
}

export interface Indicator {
  kind: 'domain' | 'ip' | 'email' | 'hash'
  value: string
  seen_in: string[]
  count: number
  status: IndicatorStatus
  note: string
  providers: Record<string, string>
  pivots: Pivot[]
  manual_check: boolean
  filename: string | null
  /** The address of a trusted receiver itself ("your gateway"): nothing to check by hand, and not counted as a manual check. */
  gateway?: boolean
}

export interface IndicatorPack {
  indicators: Indicator[]
  counts: Record<string, number>
  manual_check_count: number
  /** Indicators left out of this list because they came only from hops hidden by local config. */
  hidden_by_config_count?: number
}

// ---- workbench blocks (docs/DESIGN_V2.md, phase A). All optional: an older result simply does not have them. ----

export interface HopEntry {
  index: number
  from_host: string | null
  by_host: string | null
  from_ip: string | null
  protocol: string | null
  tls: boolean
  authenticated: boolean
  local_submission: boolean
  timestamp: string | null
  delay_seconds_from_previous: number | null
  clock_skew: boolean
  trusted_receiver: boolean
  is_origin: boolean
  /** Sent from one of the analyst's own systems (INTERNAL_HOP_PATTERNS): the backend blanks its names and address. */
  internal?: boolean
  /** Below the trust boundary (or no trusted hop exists): written by the sender, so every field is a claim. */
  unverified?: boolean
}

export interface AuthRow {
  method: string
  evaluated: boolean
  result: string | null
  receiver: string | null
  reason: string | null
  source: string | null
}

export interface SenderEvidence {
  from_address: EmailAddress | null
  reply_to: EmailAddress | null
  return_path: EmailAddress | null
  auth: AuthRow[]
  alignment: Record<string, boolean | null>
  mismatches: string[]
  trusted_receivers_configured: boolean
}

export type LinkKind = 'direct' | 'tracker' | 'wrapper' | 'shortener' | 'redirector' | 'shared_platform'

export interface LinkEntry {
  url: string
  url_defanged: string
  host: string | null
  registrable_domain: string | null
  display_text: string | null
  kind: LinkKind
  platform: string | null
  anchor_mismatch: boolean
  occurrences: number
  sources: string[]
  status: IndicatorStatus
}

export interface AttachmentEntry {
  filename: string | null
  declared_type: string | null
  detected_type: string | null
  extension: string | null
  size_bytes: number
  sha256: string
  risk_class: string
  active_content: boolean
  double_extension: boolean
  static_analysis: Record<string, unknown> | null
}

export interface BodyInfo {
  language: string | null
  language_status: string | null
  text_chars: number
  html_chars: number
  has_html: boolean
  forms: number
  remote_images: number
  links: number
}

export interface ImageEntry {
  source: 'html' | 'attachment'
  host: string | null
  url_defanged: string | null
  filename: string | null
  size_bytes: number | null
  decoded: Record<string, unknown>[] | null
}

export interface Evidence {
  sender: SenderEvidence
  hop_timeline: HopEntry[]
  links: LinkEntry[]
  attachments: AttachmentEntry[]
  body: BodyInfo
  images: ImageEntry[]
}

export interface CoverageItem {
  area: string
  subject: string | null
  status: 'checked' | 'partly' | 'not_checked'
  reason: string
  detail: string
  by_design: boolean
  blocks_no_indicators: boolean
  how_to_clear: string
}

// Verdict v2 (optional: the page keeps showing the v1 verdict until the UI step; docs/PHASE_B_PREREGISTRATION.md).
export type TierKey = 'confirmed_malicious' | 'suspicious' | 'needs_analyst' | 'no_indicators_found'

export interface V2Reason {
  kind: 'finding' | 'score' | 'evidence_conflict' | 'gap' | 'positive_evidence'
  code: string
  text: string
  evidence_ref?: string | null
}

export interface V2HardEvidence {
  code: 'H1' | 'H2' | 'H3'
  indicator: string
  source: string
}

export interface V2Blocker {
  code: string
  detail?: string | null
  text: string
  how_to_clear: string
}

export interface VerdictV2 {
  tier: TierKey
  label: string
  route: string
  reasons: V2Reason[]
  hard_evidence: V2HardEvidence[]
  blockers: V2Blocker[]
  needs_analyst_reason?: string | null
  priority?: number | null
}

export interface ChecksCompleted {
  completed: number
  total: number
  not_checked: number
  by_design: number
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
  indicators?: IndicatorPack | null
  schema_version?: number
  evidence?: Evidence | null
  coverage_report?: CoverageItem[] | null
  verdict_v2?: VerdictV2 | null
  checks_completed?: ChecksCompleted | null
  verdict_v2_status?: 'ok' | 'unavailable' | null
}

export interface AnalysisJob {
  job_id: string
  status: JobStatus
  current_step: string | null
  result: AnalysisResult | null
  error: string | null
}
