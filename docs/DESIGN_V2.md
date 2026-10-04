# Design v2: an evidence workbench for reported emails

**Status: owner decisions D1 to D12 are recorded in section 10 (2026-10-04); acceptance criteria (D8) are NOT yet approved. Phase A is being
built; nothing from phases B to E is implemented.** Written 2026-10-04. Where section 10 differs from an earlier section, **section 10 wins**.

**Labelling rule.** The hold-out was spent on 2026-10-03 (`backend/tests/HOLDOUT_LOG.md`). Everything in this document that could change a
verdict, a threshold or a signal is **"tuned after viewing hold-out"**: its design was informed by results the project has already seen
(the hold-out, the Kvish mutation analysis, a real analyst's mail). Numbers produced under v2 are labelled that way until a fresh,
never-looked-at sample is drawn after the design freeze (section 6.3).

## 0. Direction and principles

The tool is an **evidence workbench for a reported email**, used by an analyst who decides. It has two jobs:

1. **A verdict the analyst can trust because it never overclaims.** It names the strength of the evidence, never says "safe", and says
   what it could not check.
2. **One page that shows all the evidence**, so the analyst does not open threat-intelligence sites, header viewers and hash tools one by one.

Principles that every change must respect:

* **Never "safe".** The strongest negative statement is "no indicators found", always shown next to what was not checked.
* **Absence of evidence is displayed as absence of evidence.** Unknown, not looked up, disabled, internal-only and unsupported-language
  are separate, visible states, never merged into "clean".
* **Evidence before verdict.** Every tier is explained by the evidence that put it there; the page lists the evidence first.
* **Additive and backward compatible.** Existing API fields keep their meaning; new fields are added beside them.
* **External and sandbox sources are OFF by default** and need explicit configuration (section 5). Nothing leaves the machine unless the
  owner turned a source on.
* **The app never opens, executes, renders or uploads anything from the email.** Parsing only.
* **No content in logs, exports or the feedback log**: hashes, tiers, signal names and labels only.

## 1. Starting point (survey of the current code; counts and file names only)

| Area | Where it lives | Count |
|---|---|---|
| API | `backend/app/api/routes.py` (`POST /analyze`, `GET /analyze/{job_id}`, `POST /analyze/{job_id}/feedback`, `GET /feedback/summary`), `pipeline.py`, `main.py` | 4 endpoints, plus `/health` and the static UI mount |
| Response schema | `backend/app/contracts/{email,findings,scoring,analysis,llm_opinion}.py` | 18 models in `contracts/`, plus `AnalysisJob` in `routes.py`; the job wraps `AnalysisResult` |
| Findings | `contracts/findings.py` (`Finding`, `ModuleResult`); produced by `auth_check/` (incl. `claims.py`), `enrichment/`, `content_analysis/` (incl. `links.py`) | 3 modules |
| Coverage | `scoring/aggregate.py::category_coverage`; surfaced as `scoring.categories[].coverage` and `confidence`; raw detail in `auth_check` raw_data (`auth_headers.<method>.reason`, `header_present`), `content_analysis` raw_data (`script_coverage`, `language`), `enrichment` raw_data (per indicator) | 3 categories |
| Overrides | `scoring/overrides.py` (`apply_overrides`, `benign_evidence_gaps`); thresholds in `scoring/config.py` | 7 named rules plus the category floors (`auth_check_floor`, `enrichment_floor`) |
| Triage aids | `scoring/aggregate.py` (`priority_score`, `inconclusive_reason`), `ScoringBreakdown.priority` | 2 |
| Indicator list | `backend/app/indicators.py`, models `Indicator` / `IndicatorPack` / `Pivot` | 1 module |
| Feedback log | `backend/app/feedback.py` (SQLite table `feedback`), 2 routes, `frontend/src/components/FeedbackBar.tsx`, `api.ts` | 12 columns: `raw_sha256, first_ts, updated_ts, verdict, score, confidence, signals, agree, note, source_format, trusted_receivers_configured, schema_version` |
| Frontend | `frontend/src/`: `App.tsx`, `api.ts`, `types.ts`, `hooks/usePolling.ts`, and 11 components (`UploadView, ProgressView, ErrorView, ResultsView, SummaryCard, ModulePanel, FindingItem, EnrichmentRawData, IndicatorsPanel, LlmOpinionCard, FeedbackBar`) | 7 test files |

What the current verdict does, in one paragraph. Four values (`malicious`, `suspicious`, `inconclusive`, `benign`, shown as "No indicators
found"). `suspicious` comes from a score of at least 35 or from a floor (a trusted-receiver authentication failure, a critical enrichment
score, two high content findings, signals from two different structural families). `malicious` comes only from a weighted score of at
least 70, and **no evaluated message has ever produced it** (0 of 75 tuning, 0 of 75 hold-out, 0 of the fixtures). `benign` needs a verified
aligned authentication pass from a trusted receiver, a known sender, no finding above info, and complete coverage. Those rules are sound
about what they refuse; they are weak about what `malicious` means. v2 fixes that.

## 2. Verdict v2

### 2.1 Tiers, by strength of evidence

| Tier | Label shown | Meaning | Allowed to appear without |
|---|---|---|---|
| T1 | **Confirmed malicious** | Hard evidence (2.2): an independent authority or a deterministic technical fact, not a heuristic | at least one entry in `hard_evidence` |
| T2 | **Suspicious** | Several independent weak signals agree, or one strong signal that is not proof | at least two corroborating reasons, each listed |
| T3 | **Needs analyst** | Not enough evidence either way. Sub-reason `signals_present` or `no_signals_insufficient_evidence`, plus a queue priority | nothing: it is the default |
| T4 | **No indicators found** | Positive evidence (2.3) and nothing unchecked that matters. **Not a safety statement** | an empty `blockers` list |

There is **no "safe", "clean", "legit" or "benign" label anywhere** in the API, the UI, the report draft, the exports or the logs (a lint
test enforces it, criterion V1 in section 6.3). The internal literal `benign` is kept in the v1 field for compatibility only.

Two rules that make the tiers trustworthy:

* **A tier is only ever raised by evidence and only ever lowered by missing evidence.** T4 is lost by an unchecked high-risk surface; T1
  is never reached by accumulating heuristics.
* **T3 is the honest default.** Everything the tool cannot support goes there, with the reason.

### 2.2 Hard evidence (T1)

T1 requires **at least one** of the following. Thresholds are a priori values for the owner to approve (section 8, decision 2); they are not fitted to
any sample.

| # | Hard evidence | Source | Available |
|---|---|---|---|
| H1 | The attachment's SHA-256 is a **known malware sample** (MalwareBazaar `matched`, status ok) | existing | now |
| H2 | An indicator in the message (URL host, domain, IP or hash) **exactly matches ThreatFox with confidence at least 75** | existing | now |
| H3 | **VirusTotal reports at least 10 engines malicious** for the attachment hash, or for a URL or domain taken from the message | existing | now |
| H4 | A **landing page, resolved in a sandbox, contains a credential form** (password field) on a host unrelated to the claimed entity | redirect resolution + landing analysis | phase C, needs sandbox, off by default |
| H5 | An attachment analysed **statically** shows an auto-executing macro that downloads or launches something, or a PDF with a launch/JavaScript action that opens a URL | static attachment analysis | phase C, offline |
| H6 | An HTML attachment with a **password field that posts to a remote host**, or obfuscated script that rebuilds such a form | HTML-attachment analysis | phase C, offline |

Not hard evidence, by definition: any authentication result (attackers authenticate their own domains), a display-name claim, a hosting
sender, a tracker or redirector, hot-linked assets, a young domain, urgency language, a language the tool cannot read, the LLM's opinion.
Those are **signals** and can only support T2.

H1 to H3 already exist as provider answers and map to the existing `enrichment_floor` ("critical" provider score of at least 70). Under v2
that floor is split: a provider score of at least 70 **that rests on H1, H2 or H3** becomes T1; one that does not (for example urlscan hit
counts alone) stays T2. Today every floor yields `suspicious`; the change makes the strongest of them say so.

### 2.3 Positive evidence (T4) and blockers

T4 ("No indicators found") requires **all** of:

1. A **verified, aligned DKIM pass or a DMARC pass written by a trusted receiver** (unchanged).
2. The sender's registrable domain is on the **known-sender list** (unchanged): the only evidence of *legitimacy* as opposed to authenticity.
3. **No finding above info severity** (unchanged).
4. **Complete coverage**: confidence at or above the threshold and complete enrichment (unchanged).
5. **New in v2: no unchecked high-risk surface** (a *blocker*). Any of these, when present and not examined, blocks T4 and is listed:
   an attachment of an active or container type (Office with macros, HTML, script, archive, disk image, PDF) that static analysis did not
   examine; an image attachment or inline image (a QR code could be inside) while QR decoding is off; a link shortener or redirector
   that was not resolved; a link hosted on a shared platform that was not looked at; an internal-looking host; a message in a language
   the tool cannot read; a Received chain with no hop from a trusted receiver.

Item 5 is the answer to the analyst's PNG-and-link mail: it would have been T3 with a visible blocker ("image attachment: not decoded").
Every blocker names the way to clear it (turn a source on, or check by hand).

### 2.4 How today's rules map to the tiers

| Today (v1) | v2 tier | Notes |
|---|---|---|
| weighted score at least 70 (`malicious`) | T1 only if H1 to H3 hold; otherwise T2 | the main behaviour change |
| `enrichment_floor` (provider score at least 70) | T1 if it rests on H1 to H3, else T2 | see 2.2 |
| `auth_check_floor` (trusted-receiver SPF/DKIM/DMARC failure, severity high) | T2 | a real authentication failure is strong, not proof of malice |
| `structural_corroboration_floor` (two families) | T2 | the reasons list names the families and signals |
| `content_analysis_floor` (two high content findings) | T2 | |
| `content_only_ceiling` | caps at T2 | unchanged in spirit |
| weighted score 35 to 69 | T2 | |
| `low_confidence_inconclusive`, `no_positive_evidence_for_benign` | T3 | sub-reason kept; blockers listed |
| `floor_protects_verdict` | keeps T2 or T1 | low coverage never erases a floor |
| `benign` (v1) | T4 if no blocker, else T3 | |

The v1 `verdict` field is unchanged in meaning for the tiers that exist in both models; where v2 demotes a v1 `malicious` to T2 the old field
keeps its old value for compatibility and `verdict_v2` carries the new one (section 4).

## 3. Coverage disclosure: checked, not checked, why

A structured list on every analysis, built **only from data the app already holds**, shown next to the verdict, never collapsed into a single
percentage. Each item is `{area, subject, status, reason, how_to_clear}`.

| Area | `checked` when | `partly` when | `not_checked` reasons (codes) |
|---|---|---|---|
| Authentication (SPF, DKIM, DMARC, one row each) | a trusted receiver evaluated the method | only an untrusted claim exists | `no_trusted_receiver_configured`, `claim_from_untrusted_source`, `receiver_evaluated_spf_only`, `no_trusted_result` (these four reasons already exist in `auth_headers.<method>.reason`) |
| Sender identity | alignment computed | Reply-To or Return-Path missing | `from_header_unparseable` |
| Each lookup provider, per indicator class (domain, IP, URL, hash) | the provider answered | some indicators answered, some not | `no_api_key`, `disabled_by_config`, `rate_limited`, `provider_error`, `never_seen_by_source` (404) |
| Each indicator not looked up | n/a | n/a | `internal_host_not_sent`, `shared_platform`, `limit_reached`, `enrichment_did_not_run` |
| Content heuristics | language supported (English, Hebrew) | language undetermined | `language_unsupported`, `no_readable_text` |
| Links | extracted | n/a | `never_opened` (by design), `redirects_not_resolved` (until phase C source is on) |
| Attachments | hash computed | type identified | `content_never_opened` (by design), `static_analysis_off` |
| Images and QR | listed | n/a | `images_not_examined`, `qr_not_decoded` (until a source is on) |
| HTML body | text extracted | n/a | `not_rendered` (by design) |

Display rules: "Checked (n) / Not checked (m)" next to the verdict; the not-checked items are expanded by default; each item that blocks
T4 is marked as a blocker; `by_design` items are shown too (the analyst should see that the tool never opens attachments), but marked
"by design" rather than "missing".

## 4. Response schema (additive) and the page

### 4.1 Schema changes

`AnalysisResult` keeps every current field. New optional fields, all absent in old results and ignored by old clients:

```text
schema_version: int = 1            # becomes 2 when the new blocks are present
verdict_v2: {
    tier: "confirmed_malicious" | "suspicious" | "needs_analyst" | "no_indicators_found",
    label: str,                    # the exact words shown (never "safe")
    reasons: [{kind: "hard_evidence"|"signal"|"floor"|"score"|"gap", code: str, text: str, evidence_ref: str | null}],
    hard_evidence: [{code: "H1".."H6", indicator: str, source: str}],
    blockers: [{code: str, text: str, how_to_clear: str}],
    needs_analyst_reason: "signals_present" | "no_signals_insufficient_evidence" | null,
    priority: float
}
coverage_report: [{area: str, subject: str | null, status: "checked"|"partly"|"not_checked", reason: str, by_design: bool,
                   blocks_no_indicators: bool, how_to_clear: str}]
evidence: {
    hop_timeline: [{index, from_host, by_host, from_ip, protocol, tls, authenticated, local_submission, timestamp,
                    delay_seconds_from_previous, trusted_receiver: bool, is_origin: bool}],
    links: [{display_text, host, registrable_domain, defanged, kind: "direct"|"tracker"|"wrapper"|"shortener"|"redirector",
             anchor_mismatch: bool, platform: str | null, status: IndicatorStatus}],
    attachments: [{filename, declared_type, detected_type, size, sha256, risk_class, static_analysis: object | null}],
    body: {language, text_excerpt_chars: int, has_html: bool, forms: int, remote_images: int},      # no body text in the API by default
    images: [{host, source: "html"|"attachment", decoded: [{kind: "qr", text_defanged}] | null}]
}
hunting: [{platform: "kql"|"splunk"|"generic", purpose: str, query: str}]                  # text templates, never executed
attack: [{technique_id: str, name: str, because: [signal_code], confidence: "suggested"}]   # suggestions the analyst confirms
report_draft: {markdown: str}                                                                # generated locally from the fields above
decision: {disposition: "confirmed_phish"|"spam"|"benign"|"bec"|"other"|null, decided_at: str | null}
```

New endpoint, beside the existing feedback endpoint (which stays and keeps working):
`POST /analyze/{job_id}/decision` with `{disposition}` (and an optional free-text note that is **stored locally only and never exported**).
Everything else is read through the existing `GET /analyze/{job_id}`.

Backward compatibility rules: no field is renamed or removed; the frontend treats every new field as optional; an old stored job renders
with the old layout; `verdict`, `score`, `confidence`, `scoring`, `findings`, `module_results`, `parsed_email`, `llm_opinion` and `indicators`
are unchanged. `body.text_excerpt_chars` is a count: the body text is not added to the API response by default (it is already inside
`parsed_email.body_text` today; an option to strip it is in section 8, decision 5).

### 4.2 The page (text wireframe)

```text
+----------------------------------------------------------------------------------------------------------+
| VERDICT   [ Needs analyst: signals present ]  priority 26      confidence 0.59                           |
| Why:  - Image attachment and a link on a shared platform                      (signal)                   |
|       - No authentication result from a trusted receiver                      (gap)                      |
| Blocks "No indicators found":  [image attachment not decoded]  [no trusted receiver]   how to clear: ...  |
+--------------------------------------------+-------------------------------------------------------------+
| CHECKED (7)                                | NOT CHECKED (6)                                             |
|  VirusTotal: 3 hosts answered              |  DKIM, DMARC: no trusted receiver configured                |
|  ThreatFox: 3 hosts answered               |  1 attachment hash: never seen by VirusTotal                |
|  Language: Hebrew (supported)              |  QR in image: decoding is off                               |
|                                            |  Links: never opened (by design)                            |
+--------------------------------------------+-------------------------------------------------------------+
| SENDER AND AUTHENTICATION                                                                                |
|   From / Reply-To / Return-Path with registrable domains and mismatches                                  |
|   SPF  DKIM  DMARC  (trusted? by which receiver)      alignment                                          |
|   Received hops (oldest first):                                                                          |
|   #1 origin  host12.example.net  local submission  10:49:28                                              |
|   #2 gateway esa1...             TLS               +1 s     [trusted receiver]                           |
|   #3 ...                                                                                                 |
+----------------------------------------------------------------------------------------------------------+
| LINKS (n)   defanged host | text shown | kind | status | lookup links          [copy] [defanged]          |
| ATTACHMENTS (n)   name | detected type | size | sha256 | risk class | static analysis result              |
| BODY   language, forms, remote images, urgency/brand findings (text not shown unless the analyst opens it)|
| IMAGES AND QR   host, source, decoded QR text (defanged, never a link)                                   |
+----------------------------------------------------------------------------------------------------------+
| IOC TABLE   kind | indicator | seen as | status | lookups       [copy raw] [copy defanged] [CSV defanged]   |
+----------------------------------------------------------------------------------------------------------+
| HUNTING QUERY TEMPLATES   KQL | Splunk | generic     (filled with defanged indicators; copy only)         |
| ATT&CK (suggested)   T1566.002 link / T1566.001 attachment / T1656 impersonation ...  because: <signals>   |
| REPORT DRAFT   [editable markdown]  [copy]                                                               |
| RAW HEADERS   (escaped text, collapsed by default)                                                       |
| ANALYST DECISION   ( ) confirmed phish  ( ) spam  ( ) benign  ( ) BEC  ( ) other   [save]  note (local)  |
+----------------------------------------------------------------------------------------------------------+
```

The order is deliberate: verdict and reasons, then what was and was not checked, then evidence by surface, then outputs, then the decision.

## 5. Evidence sources

Every external or sandbox-dependent source is **OFF by default** and needs explicit configuration. Internal and private hosts are never sent
to any source (section 9). Effort: S under a day, M a few days, L about a week or more.

| Source | Offline / network | Privacy risk | Sandbox | Default | Effort | Notes |
|---|---|---|---|---|---|---|
| **RDAP domain age** | network (public registry servers, hostname only) | low: domain names go to registries, the same class of data as the existing lookups | no | **OFF** | S | shown as "registered N days ago"; adds a signal only after owner approval of the weight (a priori), never hard evidence |
| **Lookalike / homoglyph** | **offline** | none | no | **ON** (no data leaves) | M | compares link and sender domains with the brand map, the known-sender list and the sender's own domain using confusable folding and edit distance; extends `shared/matching.py`; signal family `claim`, never hard evidence |
| **Redirect resolution + landing-page analysis** | network (contacts the attacker's infrastructure) | **high**: reveals analyst interest and IP, can burn per-recipient tracking tokens, can trigger a report to the attacker | **yes** (resolve and fetch inside an isolated environment, never from the analyst's machine) | **OFF**, and needs the security team's approval | L | resolution of shorteners via an allow-listed resolver is a smaller first step; landing analysis (forms, password fields, brand assets) only in the sandbox |
| **Static attachment analysis** | **offline** | low: files are parsed, never run; parser bugs are the risk | no (parse with size, depth and time limits; sandbox optional) | **ON** for type detection and metadata, **OFF** for deep parsing until reviewed | L | magic-number type, Office macro presence and auto-exec markers from the zip structure, PDF actions and URIs, archive entry names (no extraction to disk), URLs embedded in files; no execution, no rendering |
| **QR decoding** | **offline** | low: decodes pixels of an attachment or inline image; one new dependency | no | **OFF** until the dependency is approved, then ON | M | decoded text shown defanged and never as a link; feeds the link pipeline as an indicator; image size and type caps against decompression bombs |
| **HTML-attachment analysis** | **offline** | low: parsed as text, never rendered or run | no | **ON** (no data leaves) | M | forms and password fields, remote form targets, `data:` URIs, meta refresh, base64 blobs, script obfuscation markers (`atob`, `eval`, `unescape`, `document.write`); JavaScript is never executed |
| *(existing)* VirusTotal, urlscan.io (search only), ThreatFox, MalwareBazaar | network, hostname or hash only | low, documented in the README | no | ON when a key is set | done | unchanged |
| *(rejected)* upload of a file or URL to any scanner | network | **high** (public visibility) | n/a | never | n/a | no code path exists and none will be added without a separate decision |

Each new source ships with: an entry in `app/enrichment/policy.py` where it uses the network (so the internal-address guard and the
per-provider off-switch cover it), offline tests with a fake HTTP session or fixtures, a "what leaves the machine" line in the README, a
`coverage_report` row, and an indicator-pack entry.

## 6. Evaluation plan

### 6.1 What the old numbers mean

The 2026-10-03 hold-out (STRICT 6 of 75 flagged, 8.0% [3.7 to 16.4%]; CONFIGURED 20 of 75, 26.7% [18.0 to 37.6%]; 0 missed) **describes the v1
verdict model only**. It does not describe v2: the tiers, the hard-evidence rule and the blockers are new, the hold-out is spent, and "0
missed" was by construction. No v1 number is carried over to v2.

### 6.2 The feedback log gains a final disposition

Additive migration of the `feedback` table (hashes, tiers, signal names and labels only):

| Column | Type | Content |
|---|---|---|
| `disposition` | text, nullable | `confirmed_phish`, `spam`, `benign`, `bec`, `other` (set by the analyst, can be changed) |
| `disposition_ts` | text | UTC time of the last change |
| `verdict_tier` | text | `confirmed_malicious`, `suspicious`, `needs_analyst`, `no_indicators_found` |
| `blocker_codes` | text (JSON list) | codes only, for example `qr_not_decoded` |
| `sources_on` | text (JSON list) | which optional evidence sources were enabled for this analysis |
| `model_version` | text | for example `v2.0`, so numbers are never mixed across versions |

Rules: no subject, address, URL, host or body text is stored; the existing free-text `note` stays **local and is excluded from every
export and summary** (today it is part of the exported columns; changing that is section 8, decision 6). `agree/disagree` keeps working and is
interpreted against the tier. Summaries report counts per tier by disposition with Wilson 95% intervals.

### 6.3 Proposed acceptance criteria (for the owner to approve before any measurement)

Criteria are fixed here, before v2 exists. "Fresh sample" means a public-corpus sample drawn with a **new pre-registered seed from a snapshot
dated after this document**, never looked at, run **once** after the v2 detection design is frozen (frozen by the hash of the commit that
completes phase B). It restores blindness for v2 acceptance only; it does not make v2 design choices blind.

| ID | Criterion | Threshold | Data | Label |
|---|---|---|---|---|
| V1 | **Never "safe"**: no API, UI, report or log string contains safe, clean, legit or benign (except the frozen v1 field name) | 0 occurrences | static lint test | invariant |
| V2 | **T4 never with a blocker** | 0 violations | property test over all fixtures, mutations and the fresh sample | invariant |
| V3 | **T1 never without hard evidence** | 0 violations | same | invariant |
| V4 | **Every analysis has a non-empty coverage report**; every `by_design` or missing item has a reason code | 100% | same | invariant |
| V5 | **Internal addresses never reach a provider** | 0 requests | recording fake HTTP over the internal-address matrix (exists) | invariant |
| V6 | **Phase A and D change no verdict**: per-sample verdict, score and priority identical to the committed baseline | 100% identical | tuning split and fixtures, STRICT and CONFIGURED, both enrichment modes | regression |
| V7 | **T1 precision in the field** (only once enough dispositions exist) | lower Wilson 95% bound of `confirmed_phish + bec` among T1 cases at least 0.90, with at least 30 labelled T1 cases | analyst dispositions | tuned after viewing hold-out |
| V8 | **T4 phish rate in the field** | report the upper Wilson 95% bound; **no pass/fail** below 100 labelled T4 cases | analyst dispositions | tuned after viewing hold-out |
| V9 | **Disagree rate by tier** | report with intervals; no threshold | analyst feedback | descriptive |
| V10 | **Recall on the fresh sample** | report flagged (T1 plus T2) with a Wilson interval, STRICT and CONFIGURED, T3 shown separately; **no target** | fresh sample, once | tuned after viewing hold-out |
| V11 | **Priority sanity** | AUC and share above the benign median reported, labelled sanity only (the benign side is synthetic) | tuning plus fixtures | descriptive |

Real-world precision stays unmeasured until analysts supply dispositions; the tool says so in the README and in the report footer.

## 7. Phased plan

Order: A, then B, then C one source at a time, D (can run alongside C), then E. Every phase ends with the full backend and frontend suites,
both guard scripts, `test_standalone`, and one atomic commit group per source or feature. A commit that touches more than three source files
is announced first.

| Phase | Goal | Files likely touched | Tests | Regression rule |
|---|---|---|---|---|
| **A. UI and schema** | `evidence` (hop timeline, links, attachments, body, images), `coverage_report`, `schema_version`; new page layout; decision endpoint and storage | `contracts/analysis.py`, new `app/evidence.py`, new `app/coverage.py`, `api/pipeline.py`, `api/routes.py`, `feedback.py`; frontend `types.ts`, `ResultsView.tsx`, new `CoveragePanel.tsx`, `EvidencePanel.tsx`, `HopTimeline.tsx`, `DecisionBar.tsx` | schema tests (old JSON still parses, new fields optional), coverage derivation tests for every reason code, frontend tests for old-shape and new-shape results | **must not change any verdict, score or priority** (V6); a committed baseline of per-sample verdicts for the tuning split and fixtures is added first, so the rule is a test |
| **B. Verdict v2** | tiers, hard evidence, blockers, mapping table | `scoring/overrides.py`, `scoring/config.py`, new `scoring/tiers.py`, `contracts/scoring.py` | table-driven tests of the mapping (2.4), property tests V2 and V3, blocker tests per item in 2.3, before/after tier table on tuning and fixtures | **changes verdicts by design**; the only permitted changes are the documented ones (v1 `malicious` without hard evidence becomes T2; T4 with a blocker becomes T3); thresholds are a priori and **not** tuned on any sample; labelled tuned after viewing hold-out |
| **C. Evidence sources** (one per sub-phase: lookalike, HTML attachment, static attachment, QR, RDAP, redirect and landing) | add evidence and signals | per source: a new module, `policy.py` where the network is used, `indicators.py`, `coverage.py`, config and README | offline fakes, privacy tests (what leaves the machine), a benign fixture set per source that must stay below T2, a mutation test where relevant | each source adds signals or hard evidence only through the tier rules in section 2; no weight is fitted; external and sandbox sources stay OFF; each change labelled tuned after viewing hold-out |
| **D. Analyst outputs** | hunting templates, ATT&CK suggestions, report draft, defanged CSV and copy for every table | new `app/outputs.py`, `config` for template names, frontend `OutputsPanel.tsx`, `ReportDraft.tsx` | golden-text tests, defang tests, no-content tests (the report contains only fields already shown) | **must not change any verdict** (V6) |
| **E. Calibration** | review field dispositions, adjust thresholds only by pre-registered rules | `scoring/config.py`, this document's log | the V7 to V11 reports, a versioned `model_version` bump | any change bumps the version and is logged here with its reason and the data that motivated it; a fresh sample is used once per freeze |

Hunting templates, ATT&CK suggestions and the report draft are **text generators**: they cannot run a query, and the ATT&CK list is labelled
"suggested" with the signals it came from.

## 8. Open decisions for the owner

Numbered, each with my recommendation.

| # | Decision | Recommendation |
|---|---|---|
| 1 | **Approve the four tiers and the exact wording**, including "No indicators found" with the blockers beside it | approve |
| 2 | **H1 to H3 thresholds** (MalwareBazaar match; ThreatFox confidence at least 75; VirusTotal at least 10 engines) | approve as a priori values; no tuning |
| 3 | **Demote v1 `malicious` without hard evidence to T2** (the only v1 behaviour that gets weaker) | approve |
| 4 | **Blockers for T4** (2.3 item 5): which surfaces count, and whether an unread shared-platform link or a missing trusted receiver blocks T4 | approve the list in 2.3 |
| 5 | **Keep the body text in the API response?** Today `parsed_email.body_text` is returned. Option: strip it and fetch on demand | strip by default |
| 6 | **Free-text note in the feedback log**: exclude it from exports and summaries | exclude |
| 7 | **Dispositions** (`confirmed_phish`, `spam`, `benign`, `bec`, `other`): the set and who records them | approve the set; the analyst who handled the case records it |
| 8 | **Acceptance criteria V1 to V11** (6.3) and the fresh-sample protocol (new seed, run once after the freeze) | approve before any measurement |
| 9 | **Hunting query platforms and table names** (KQL for Defender or Sentinel, Splunk, generic) | KQL and generic first; your team supplies real table names in untracked config |
| 10 | **Order of the evidence sources** in phase C | lookalike, HTML attachment, static attachment, QR, RDAP, redirect and landing |
| 11 | **QR decoding dependency** (one small package, reads image pixels) | approve a pinned, wheel-only package |
| 12 | **Shared instance** (the earlier Vercel idea) | still later; local first |

**Needs your security team's approval before it can be built or turned on** (it stays OFF and unbuilt until then):

* **Any external URL fetching or scanning**: redirect resolution, landing-page fetch, or any service that visits a link on the analyst's behalf.
  It exposes the organisation's interest in a campaign to the attacker, and a fetch can fire per-recipient tracking.
* **Any sandbox**: where it runs, who owns it, its network egress, how files and results enter and leave, retention.
* **RDAP and any new outbound lookup**: domain names to registries are low risk but are a new outbound data flow.
* **Static analysis of attachments from the organisation's mail on analysts' machines**: parsers handle hostile files; the team may want it
  restricted to the sandbox VM.
* **Hosting a shared instance anywhere outside the organisation**, because mail contains customer and employee data.
* **Storing dispositions** (even hashes plus labels) and where the file lives.
* **Using an LLM at all** (it is OFF by default; titles only, tokenised).

## 9. Privacy and security notes

**Logs.** The console summary and every log line carry counts, provider names and status words only: no host, URL, address, hash, subject or body
text. `LOG_LEVEL` controls verbosity. A test (exists for the enrichment summary) is extended to every new module.

**Internal addresses.** Private, loopback, link-local, multicast, reserved, documentation and CGNAT addresses, IPv6 forms embedding them,
obfuscated spellings, single-label names and internal-looking suffixes are never sent to any provider. The guard sits in `classify_host` and again
inside `GuardedProvider.lookup`; the indicator list offers no lookup links for them. Every new network source goes through the same guard.

**Rendering untrusted content.**
* The email's HTML is **never rendered** by the app. The page shows extracted text and metadata. If an analyst wants a visual preview, it is
  an explicit action that uses an iframe with an empty `sandbox` attribute (no scripts, no forms, no same-origin), a policy of
  `default-src 'none'`, and **no remote images** (a loaded image is a tracking beacon).
* No `dangerouslySetInnerHTML` anywhere (a lint test); everything is rendered as escaped text by React.
* URLs and addresses are shown **defanged** by default; copy and CSV offer raw and defanged; CSV cells that start with `=`, `+`, `-` or `@` are
  neutralised (exists).
* Decoded QR text, macro strings and HTML-attachment findings are text, never links.
* Raw headers are shown as escaped text.
* Attachments are never offered for download and never opened; only metadata and hashes are shown.
* The server sends a restrictive `Content-Security-Policy` for the UI and keeps the static-file mount traversal-safe (tested).
* Parsers of hostile files (Office, PDF, archives, images) run with size, depth and time limits, and a failure is reported as "not checked: parser
  limit", never as clean.

**Data at rest.** The feedback log stays local, git-ignored and content-free; the API has no login and listens on this machine only; keys stay in
the untracked `.env`.

**Honesty of the output.** Every report footer repeats three facts: real-world precision is not established; "no indicators found" is not a safety
verdict; the list of what was not checked is part of the result.

## 10. Decisions (recorded 2026-10-04)

Everything below is "tuned after viewing hold-out" where it touches a verdict, a threshold or a signal. Standing rules: no push, no history
rewrite, no `--final-holdout`, `backend/.env` is the owner's file.

| # | Decision | Status |
|---|---|---|
| D1 | **Four tiers approved.** "No indicators found" is **always shown with its blockers** and with **neutral styling: no green, no check mark, no shield**. It reads as a statement of what was and was not found, not as reassurance. | approved |
| D2 | **H1 to H3 approved, with these precisions** (they replace the wording of 2.2 H3): VirusTotal at least **10 engines malicious** counts for **URLs and file hashes**; for **domains only if the domain is not on the shared-platform list** (a hit on a platform host says nothing about the page); **an IP alone never counts**. **Any later change to a threshold is logged** in this document with its reason and the data behind it. | approved |
| D3 | **A v1 `malicious` without hard evidence is shown as Suspicious (T2).** | approved |
| D4 | **Blockers for "No indicators found" approved (2.3 item 5), with two additions: password-protected archives, and HTML attachments.** A password-protected archive cannot be examined; an HTML attachment is a classic credential-harvesting carrier. Both block until they have been analysed. | approved, extended |
| D5 | **The message body text stays in the live response**, held **in memory only with a short time to live** (the job store expires; default 30 minutes). It is **never logged, persisted, exported, sent to any provider or sent to the LLM**, and is **rendered as plain text only**. In a future **shared-instance mode the body is stripped** from the response. | approved |
| D6 | **The free-text note is excluded from every export and summary**, has a **length cap**, and the UI shows a **warning not to paste email content** into it. | approved |
| D7 | **Dispositions: `confirmed_phish`, `spam`, `benign`, `bec`, `other`, `unsure`.** Recorded by the analyst **after investigation**, **editable once**. Stored fields only: **file hash, verdict (tier), signal names, label, timestamp** (the local note is separate and never exported, D6). | approved |
| D8 | **Acceptance criteria (section 6.3) are NOT yet approved.** The owner is reviewing section 6. Rules that apply regardless, recorded now: criteria are **written and approved before any measurement**; the **fresh sample is drawn once, with a new seed, after the v2 freeze**; precision criteria are judged on **Wilson lower bounds**; the **minimum number of dispositions is fixed in advance** (in the approved criteria); **precision criteria are evaluated only on analyst dispositions**, never on a public corpus or on synthetic mail. | **pending** |
| D9 | **Hunting-query templates: a generic format first**, then KQL or SPL (the owner will say which). **Table and field names live in untracked configuration**; **no organisation names appear in any tracked file.** | approved |
| D10 | **Evidence-source order approved** (lookalike, HTML attachment, static attachment, QR, RDAP, redirect and landing). **Attachment parsers run in a separate subprocess with a timeout, a memory limit and no network.** | approved |
| D11 | **One pinned, wheel-only QR package, with hash pinning** (`pip --require-hashes`). Candidates and notes are below; the choice is the owner's. **Pillow decompression-bomb limits** apply to every image that is decoded. | candidates proposed |
| D12 | **Local first; shared instance later.** | approved |

### Items that stay OFF and unbuilt until the security team approves them

External URL fetching or scanning; any sandbox; RDAP and every other new outbound lookup; any use of an LLM; storing dispositions; hosting a
shared instance. Nothing for these is built in Phase A. When built later, each is OFF by default and needs explicit configuration.

### New proposal H0: a local IOC list as an additional hard-evidence source (documented, NOT built)

**H0 (offline).** An indicator in the message **exactly matches an entry in a local IOC list** kept in untracked configuration. The list is
the owner's SOC blocklist export plus indicators from **confirmed phish** (dispositions `confirmed_phish` or `bec`). A match is hard evidence (T1),
because the organisation itself has already judged that indicator malicious.

Proposed rules, for approval before anything is built:

* **Format:** one file (CSV or JSON), columns `kind` (domain, ip, url-host, hash), `value`, `source`, `added`, optional `expires`. No content.
* **Matching:** lower-case exact match after de-fanging; a domain entry also matches its subdomains; an IP counts only if it is public; a hash
  matches exactly. **An entry for a shared-platform host, for a registrable domain on the known-sender list, or for an internal-looking name is
  rejected at load time** (a poisoned or careless entry must not turn a platform or a supplier into "confirmed malicious").
* **Hygiene:** `expires` is honoured; a stale entry is reported in the coverage report, not silently used; a loader reports counts only.
* **Feedback loop:** adding an indicator from a confirmed phish is an **explicit analyst action**, never automatic, and shows the exact entries
  before they are written.
* **Privacy:** the list never leaves the machine, is git-ignored, is never logged (counts only), and is never sent to a provider.
* **Evaluation:** because the list comes from the same organisation's judgements, an H0 match is a statement about the organisation's own
  history; it is excluded from the precision criteria for T1 (it would make them circular) and reported separately.

### D11: QR package candidates (looked up on PyPI on 2026-10-04; the lookup returned partial data, so confirm every item at selection time)

| Candidate | Licence | Wheels | Maintenance signal | Notes |
|---|---|---|---|---|
| **`zxing-cpp`** (Python bindings of the zxing-cpp C++ library) | Apache-2.0 | prebuilt CPython wheels for Windows amd64, manylinux x86_64 and macOS (universal2); source distribution also published | releases in 2023-07, 2023-12 and 2025-01, and a later 3.1.1; active project on GitHub | no system library needed; decodes QR and other codes from an image buffer; small |
| `pyzbar` | MIT | Windows wheels (win32, amd64) that **bundle the zbar DLLs**; on Linux and macOS the system library `libzbar` must be installed | **last release 2022-03-15**; no source distribution on PyPI | depends on the LGPL zbar library underneath; an extra system step on non-Windows; effectively unmaintained |
| `opencv-python-headless` (`cv2.QRCodeDetector`) | Apache-2.0 | wheels of roughly 31 MB (Windows) and 36 MB (Linux) | actively released | a very large dependency for one function; a large parser surface |
| `Pillow` (not a decoder: it loads the image and enforces the limits) | MIT-CMU | wheels for all platforms | actively released; needs Python 3.10 or newer (matches this project) | required in any case to open the image and to apply `Image.MAX_IMAGE_PIXELS` and the decompression-bomb error; pinned the same way |

**Recommendation: `zxing-cpp` plus `Pillow`**, both wheel-only with pinned hashes. Reasons: no system library, a permissive licence, wheels on every
platform the analysts use, small, and maintained. Limits to adopt with it: only PNG, JPEG, GIF and BMP are decoded; a maximum file size; the
pixel limit set below Pillow's default (a decompression-bomb error is treated as "not checked: image limit", never as clean); decoding happens in the
parser subprocess of D10; the decoded text is shown defanged and is never a link.

### Consequences recorded for the plan

* Phase A (section 7) does not change a verdict, adds no evidence source, adds no outbound lookup and ships the workbench panels and the additive schema.
  Leaving to later phases: the analyst-decision panel, hunting queries, ATT&CK suggestions and the report draft (phase D); tiers and blockers (phase B).
* The job store gets a time to live now (D5), because the body panel is the first place the body text is shown.
* Until verdict v2 is active, the page shows the **v1 verdict** with the new neutral styling, and lists each **unchecked high-risk surface** next to it,
  marked "would block 'No indicators found' once verdict v2 is active".
