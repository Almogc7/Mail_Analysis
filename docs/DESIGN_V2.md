# Design v2: an evidence workbench for reported emails

**Status: owner decisions D1 to D23 are recorded in section 10 (D1 to D12 on 2026-10-04, D13 to D23 on 2026-10-05); acceptance criteria (D8) were approved by the owner on 2026-10-05 with conditions (D8 in section 10); V7 to V9 cannot be measured until the security team approves storing dispositions. Phase A is built;
nothing from phases B to E is implemented. The "Review changes (2026-10-05)" list in section 10 revises sections 2, 3, 4, 6, 7 and 8 ; the owner approved it
with D8 on 2026-10-05, with the conditions recorded there; each edit is also marked in place.** Written 2026-10-04. Where section 10 differs from an earlier section, **section 10 wins**.

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
| T2 | **Suspicious** | **Reached only through a named route** (2.1a, D22): the structural floor, the authentication floor, the score band, the content or enrichment floor with a second independent category, or hard evidence in conflict. Not proof | one named route, with every reason listed |
| T3 | **Needs analyst** | Not enough evidence either way. Sub-reason `signals_present` or `no_signals_insufficient_evidence`, plus a queue priority | nothing: it is the default |
| T4 | **No indicators found** | Positive evidence (2.3) and nothing unchecked that matters. **Not a safety statement** | an empty `blockers` list |

**Labels.** The four labels in this table (Confirmed malicious, Suspicious, Needs analyst, No indicators found) are the **source of truth** for tier wording.
`docs/UI_DESIGN.md` currently says "Malicious" and "Inconclusive: analyst review" for the first and third tier and **must be updated to match** when verdict v2
is built. Only the tier labels change there: internal keys (`malicious`, `suspicious`, `inconclusive`, `benign`) and the colour tokens stay. *(Review change 8.)*

**Wording rule (V1).** The words **safe, clean, legit, benign and harmless are banned as whole words** (case-insensitive, matched at word boundaries, so
"safety" is not "safe") in every **user-visible string**: API labels and reasons, the UI (labels, titles, tooltips, accessible names), the report draft,
the exports (copy and CSV) and log messages. A lint test enforces it. The exemptions are explicit and closed: *(Review change 1.)*

* **The frozen v1 field.** The literal `benign` in the v1 `verdict` value and the internal keys and tokens that carry it (for example the `verdict-benign`
  style hook and `types.ts` unions) are not user-visible and stay.
* **Required negated disclaimers**, an allowlist of exact strings kept in one place (`scripts/wording_allowlist.json`) and pinned by the test. **Today the list is empty**:
  the wording cleanup of 2026-10-05 reworded every disclaimer that carried a banned word (for example "says nothing about what the message contains"), and the ones that
  remain ("This is a statement about what was and was not found, not a safety verdict"; "not evidence of safety") contain no banned word, because "safety" is not "safe". A later
  disclaimer that does contain a banned word inside a negation can be added **only** by exact string, with its reason logged in section 10.
* **Third-party product names, exact string only** *(new category, 2026-10-05)*. A third party's proper noun that contains a banned word may appear in the app's text. The phrase is
  listed in `scripts/wording_allowlist.json` with its reason, matches **exactly** (case-sensitive, whole phrase, a near miss still fails) and is ignored **wherever it appears**
  (a finding sentence, an indicator note, the links panel, the LLM prompt); **any other banned word in the same string is still reported**. Today there is one: **Microsoft Safe
  Links**, the name of Microsoft's link-rewriting service, shown because it is the platform a link is hosted on. Renaming it would misname the product the analyst is looking at.
* **Third-party data shown as data.** Provider raw-data field names (for example the VirusTotal `harmless` count that the client passes through) appear only inside the
  "Raw provider data" block, as the provider's own field names. They never appear in a label, a reason, a finding, the report draft or an export.

**What V1 covers** *(2026-10-05)*. V1 covers **the app's own strings**. **Text generated by the language model** appears only inside the card labelled **"AI opinion, not a verdict"**
and is **exempt**: the model's words are not the app's. **The text sent TO the model is the app's own**, and it **must never contain the raw v1 value**: the verdict reaches the prompt as
"No indicators found" through the one label function (`app/verdict_labels.py`), never as `benign`. That one function is also how every reason, log line and CLI line names a verdict;
a test proves no user-visible string, finding, reason, indicator text, log line or prompt carries the raw value outside the frozen field and its internal keys.

**Existing text broke this rule, and was cleaned up** *(2026-10-05)*. A read-only search of `backend/app` found user-visible finding and indicator text, and one log line, that contain banned
whole words, in six modules (authentication, claims, alignment, indicators, enrichment and content analysis). Examples: "Common in **benign** mail" in the brand-claim finding;
"UNKNOWN, **not clean**" in the enrichment findings, in an indicator note and in a log message; "does not make the content **safe**" in authentication findings. (The frontend was
not searched.) **Phase B therefore starts with a text-only cleanup commit, before the V1 lint is enabled** (**done on 2026-10-05**: four small commits; the report-only lint now finds 0 hits in
the static and the runtime scan; it is not yet a failing test, which is the step that switches V1 on). **How every case was found:** run the V1 lint in **report-only mode** over
all finding templates, indicator notes, labels, tooltips, accessible names and log messages, and list each hit with its file; then reword each (or, for a required negated
disclaimer, pin it in the allowlist by exact string with its reason). The tests that assert the old wording change in the same commit. **The baseline must move 0 rows** (it
records no finding text; the check is run and reported).

Two rules that make the tiers trustworthy:

* **A tier is only ever raised by evidence and only ever lowered by missing evidence.** T4 is lost by an unchecked high-risk surface; T1
  is never reached by accumulating heuristics.
* **T3 is the honest default.** Everything the tool cannot support goes there, with the reason.

### 2.1a T2: named routes only; "two independent reasons" is the standard a route must meet *(Review change 2; D16, D22)*

T2 is reached **only through one of the named routes in D22**. "Two independent reasons" is the **standard that several of those routes must meet**, not a separate generic
route: **no rule of the form "any two independent findings make T2" exists or may be added.** (Measured read-only on 2026-10-05, such a rule would have moved 36 STRICT and 24
CONFIGURED tuning rows to T2; D22.) Every reason a route uses is listed in `reasons`.

* **Independent** is defined exactly in decision D16 (section 10): reasons from different signal families (sender, link, claim) or from different categories
  (authentication, enrichment, content).
  Two findings in the same family are **one** reason.
* **Strong signals** (a closed list; adding one needs an owner decision logged in section 10): **a trusted-receiver authentication failure**, that is an SPF,
  DKIM or DMARC `fail` written by a receiver the owner configured as trusted (today's `auth_check_floor`). That is the only entry.
* **Property test (criterion V12).** For every fixture, every Kvish mutation and every generated set of findings (all combinations of families, categories and severities up
  to a fixed size): a case is T2 if and only if it satisfies one of the named routes of D22; a case that satisfies none is T3 (`signals_present`), never T2, however many
  findings it has.
* **Consequence for the mapping in 2.4** (a behaviour change, to be pre-registered with predicted rows before Phase B runs it): a weighted score of 35 to 69, the
  two-high-content-findings floor (one family) and an enrichment floor that does not rest on H1 to H3 (reputation family only) **no longer give T2 on their own**; each
  gives T2 only with a second independent category (or family), otherwise T3. Today each of them gives `suspicious`.

### 2.2 Hard evidence (T1)

T1 requires **at least one** of the following. Thresholds are a priori values for the owner to approve (section 8, decision 2); they are not fitted to
any sample.

| # | Hard evidence | Source | Available |
|---|---|---|---|
| H1 | The attachment's SHA-256 is a **known malware sample** (MalwareBazaar `matched`, status ok) | existing | now |
| H2 | A **link host, link URL or attachment hash** the recipient interacts with **exactly matches ThreatFox with confidence at least 75**, under the rules below | existing | now |
| H3 | **VirusTotal reports at least 10 engines malicious** for an **attachment hash**, for a **URL taken from a link**, or for a **domain taken from a link** (domain only if it is not on the shared-platform list), under the rules below | existing | now |
| H4 | A **landing page, resolved in a sandbox, contains a credential form** (password field) on a host unrelated to the claimed entity | redirect resolution + landing analysis | phase C, needs sandbox, off by default |
| H5 | An attachment analysed **statically** shows an auto-executing macro that downloads or launches something, or a PDF with a launch/JavaScript action that opens a URL | static attachment analysis | phase C, offline |
| H6 | An HTML attachment with a **password field that posts to a remote host**, or obfuscated script that rebuilds such a form | HTML-attachment analysis | phase C, offline |

**Rules for H1 to H3 (D2 applies to H2 as well as H3; Review change 3).**

1. **Only indicators the recipient interacts with count**: link hosts and link URLs, and attachment hashes. A **Received-hop address, a From or Reply-To domain, an image host
   or any header-derived name never counts**, whatever a provider says about it.
2. **An IP alone never counts**, for H2 and for H3 (including a link whose host is an IP).
3. **A domain on the shared-platform list never counts** (a hit on a platform host says nothing about the page that was linked).
4. **A shared-platform URL counts only on an exact URL match**: the provider matched the full URL, not the host. Lookups are hostname-only by default (a path or query is
   sent only to a provider the owner opted in), so a shared-platform URL can reach T1 **only when that opt-in is on for that provider**; otherwise it cannot.
5. **Evidence conflict.** Hard evidence on a registrable domain that is **on the known-sender list, or is the organisation's own domain**, gives **T2 with a visible
   reason "evidence conflict"** (code `evidence_conflict`; the reasons list names both the evidence and the list), **never T1**. A supplier or the organisation itself
   being flagged is more likely a provider error or a compromised account than a verdict the tool should state alone; the analyst decides. The organisation's own domains
   are listed by the owner in untracked configuration (the known-sender file may carry them), never in a tracked file.
6. **H0 uses the same lists.** H0's load-time rejection (a shared-platform host, a registrable domain on the known-sender list, the organisation's own domain, an
   internal-looking name) is the same rule as items 3 and 5, applied before an entry can match.

Not hard evidence, by definition: any authentication result (attackers authenticate their own domains), a display-name claim, a hosting
sender, a tracker or redirector, hot-linked assets, a young domain, urgency language, a language the tool cannot read, the LLM's opinion.
Those are **signals** and can only support T2.

H1 to H3 already exist as provider answers and map to the existing `enrichment_floor` ("critical" provider score of at least 70). Under v2
that floor is split: a provider score of at least 70 **that rests on H1, H2 or H3** becomes T1; one that does not (for example urlscan hit
counts alone) is **T2 only with a second independent reason, otherwise T3** (2.1a, 2.4, D16, D22). Today every floor yields `suspicious`; the change makes the strongest
of them say so and demotes the weakest.

### 2.3 Positive evidence (T4) and blockers

T4 ("No indicators found") requires **all** of:

1. A **verified, aligned DKIM pass or a DMARC pass written by a trusted receiver** (unchanged).
2. The sender's registrable domain is on the **known-sender list** (unchanged): the only evidence of *legitimacy* as opposed to authenticity.
3. **No finding above info severity** (unchanged).
4. **Complete coverage**: confidence at or above the threshold and complete enrichment (unchanged).
5. **New in v2: no unchecked high-risk surface** (a *blocker*). Any of these, when present and not examined, blocks T4 and is listed:
   an attachment of an active or container type (Office with macros, HTML, script, archive, disk image, PDF) that static analysis did not
   examine; an image attachment, or an inline or embedded image (a `cid:` part or a `data:` image), while QR decoding is off (a remote, hot-linked image is **not** a blocker: see below); a link shortener or redirector
   that was not resolved; a link hosted on a shared platform that was not looked at; an internal-looking host; a message in a language
   the tool cannot read; a Received chain with no hop from a trusted receiver. **Added by D4 and by the 2026-10-05 review (Review change 4):**
   a password-protected archive; an HTML attachment (until analysed); **a parser failure, limit or timeout** on any part of the message (that part is "not checked", never
   clean); a **nested message attachment** (.eml or .msg: the inner message is not analysed until it is examined as a message of its own); a **calendar invite** (.ics:
   the location, description and links inside are not examined); an **encrypted or password-protected Office or PDF file**; and a **malformed or unparseable From header**
   (`from_header_unparseable`: the sender identity cannot be established).

Item 5 is the answer to the analyst's PNG-and-link mail: it would have been T3 with a visible blocker ("image attachment: not decoded").
Every blocker names the way to clear it (turn a source on, or check by hand).

**T4 is not relaxed for SPF-only mail** *(Review change 5)*. Where the trusted receiver evaluates SPF only (for example a gateway that writes only a `Received-SPF`
header), T4 stays unreachable: item 1 needs a verified, aligned DKIM pass or a DMARC pass. SPF alignment is weaker than it looks, because shared ESP includes let one sending
platform authorise many unrelated senders. The missing DKIM and DMARC evaluation is a **deployment issue** (the gateway must be configured to evaluate and write them),
shown as a coverage item with its way to clear, not something the rule bends around.

**A remote image is not a blocker** *(2026-10-05)*. A remote (hot-linked) image is an `<img>` that points at an http or https address: the app never fetches it, so it
has **no pixels to decode** and nothing in it can be checked or missed. It is listed under Images as "not examined (by design)" and as a tracking-beacon note, and it does not
block "No indicators found". **The blocker is a picture the message actually carries**: an **image attachment** or an **inline or embedded image** (a `cid:` part, or a
`data:` URI), because a QR code could be inside it and the tool does not decode it yet.

**How the new blockers are detected: Phase B reads metadata only** *(2026-10-05; encryption moved to Phase C the same day)*. Phase B detects **only** these blockers, from
metadata: the **magic-number type from the first bytes** of an attachment; a **nested `.eml` or `.msg`**; an **`.ics`**; a **malformed From**; the **count of `data:` images**
in the HTML; and **structured, content-free parse-failure flags** (a code, never the text of an error). **Encryption flags** (an encrypted Office package, a PDF `/Encrypt` entry,
a password-protected archive) **move to Phase C**, where they run **in the D10 subprocess** with the other attachment parsing. **No deep parsing in Phase B**: macros, PDF
actions, archive entries and the inside of a nested message stay in Phase C.

**Nothing is lost for T4 by that move.** Any unexamined **active, container, Office, PDF or archive attachment already blocks T4** today (the attachment classes mark Office files,
PDF, archives and disk images as active or container, and the coverage report blocks T4 while static analysis has not examined them), so an encrypted Office file, an encrypted PDF
and a password-protected archive are already stopped by that blocker. Phase B's magic-number type extends it to a file that is **renamed** (a document saved as `.bin`), which a
declared name or type alone would miss. What is derivable today and what Phase B adds:

| Blocker | Derivable today? | What Phase B adds (metadata only) |
|---|---|---|
| Image attachment, including a `cid:` inline part | **yes**: the coverage report already flags `qr_not_decoded` | magic-number confirmation, so a renamed file is caught |
| `data:` image in the HTML | **no**: the parser keeps only http and https image sources | a count of `data:` image sources (no content) |
| Active, container, Office, PDF, HTML attachment, archive or disk image | **yes** (declared name and type; already blocks T4) | magic-number type from the first bytes |
| Nested message attachment (.eml, .msg) | **yes, and it already blocks T4**: `.eml` and `.msg` are classed as active (a message inside a message carries its own links and attachments) | magic-number confirmation |
| Calendar invite (.ics) | **detectable by declared filename and type; not a blocker today** (classed as a calendar, not as active) | blocker plus magic-number confirmation |
| Malformed or unparseable From | **yes** (the parsed From has no address; the parser already records an ambiguity warning); not a blocker today | a structured flag in place of free text |
| Parser failure, limit or timeout | **partly**: failures exist only as free-text `parse_warnings` that can contain names and error text, so they cannot be used as they are | a structured, content-free failure and limit flag per part |
| Password-protected archive; encrypted or password-protected Office or PDF | **no flag today, but covered**: the attachment is already an unexamined active or container type, which blocks T4 | **nothing in Phase B**: the encryption flags are **Phase C**, in the D10 subprocess |
| Unresolved shortener or redirector; shared-platform link not looked at; internal-looking host; unreadable language; no trusted hop | **yes** (existing coverage flags) | none |

**Reachability of "No indicators found" is not a goal** *(2026-10-05)*. While the click-tracker, shared-platform and redirect blockers exist, "No indicators found" is
**expected to be rare for real mail**: legitimate newsletters and transactional mail are full of trackers and shared platforms. That is acceptable. The tool's **useful tiers in
practice are Confirmed malicious, Suspicious and Needs analyst**; the fourth tier is a deliberately hard-to-reach statement, and nothing here is to be loosened to make it more
common.

### 2.4 How today's rules map to the tiers

| Today (v1) | v2 tier | Notes |
|---|---|---|
| weighted score at least 70 (`malicious`) | T1 only if H1 to H3 hold; otherwise T2 | the main behaviour change |
| `enrichment_floor` (provider score at least 70) | T1 if it rests on H1 to H3 (and 2.2 rules 1 to 5 hold), else T2 only with a second independent category or family, else T3 | see 2.2 and 2.1a. **Changed 2026-10-05** |
| `auth_check_floor` (trusted-receiver SPF/DKIM/DMARC failure, severity high) | T2 | the named strong signal (2.1a): one reason is enough |
| `structural_corroboration_floor` (two families) | T2 | two independent reasons by construction; the reasons list names the families and signals |
| `content_analysis_floor` (two high content findings) | T2 **only with a second independent category or family**, else T3 | both findings are in the content family: one reason (2.1a). **Changed 2026-10-05** |
| `content_only_ceiling` | caps at T2 | unchanged in spirit |
| weighted score 35 to 69 | T2 **only with above-info findings in at least two different reason classes**, else T3 | **changed 2026-10-05** (2.1a, D16, D22 route 3) |
| `low_confidence_inconclusive`, `no_positive_evidence_for_benign` | T3 | sub-reason kept; blockers listed |
| `floor_protects_verdict` | keeps T2 or T1 | low coverage never erases a floor |
| `benign` (v1) | T4 if no blocker, else T3 | |

The v1 `verdict` field is unchanged in meaning for the tiers that exist in both models; where v2 demotes a v1 `malicious` to T2 the old field
keeps its old value for compatibility and `verdict_v2` carries the new one (section 4).

**Once `verdict_v2` is active, the UI shows only `verdict_v2`** *(Review change 6)*. A v1 `malicious` that v2 demotes is **never displayed**: not in the verdict card, not in
the report draft, not in an export. The v1 `verdict` field stays in the API response, unchanged, for compatibility only, and is documented as not for display.
**Test requirement (criterion V13), exactly what is tested:** a frontend test and a report test render a result whose v1 `verdict` is `malicious` and whose
`verdict_v2.tier` is `suspicious`. They assert, **by element and by field, not by substring search**, that **the v1 verdict element** (the verdict banner element that is bound to
the v1 `verdict`) **and the v1 `verdict` field value are absent** from the verdict card, from the report draft (its verdict field) and from the CSV (its verdict column), and that
the v2 label and reasons are present in the same places.

**What is displayed instead of "Confidence"** *(Review change 7, D15)*. The 0.6 confidence gate stays an **internal rule** and is never displayed. The only coverage
number on the page is **"Checks completed: N of M, K not checked"**, counted from the coverage report alone: M counts the coverage items that apply to this message and are
not `by_design`, N those with status `checked`, K the rest (`not_checked` and `partly`); `by_design` items are listed separately and counted in none of the three. The exact
counting rule is part of the Phase B pre-registration.

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

The coverage list replaces the percentage as the page's statement of completeness (D15, Review change 7): the page shows "Checks completed: N of M, K not checked"
(counting rule in 2.4) and never the 0.6 confidence figure. Authentication coverage **already counts only results written by a trusted receiver**: `header_present` is true only when SPF,
DKIM and DMARC were all evaluated by a trusted receiver, so today's value is binary (1.0 or 0.4) and an SPF-only gateway leaves it at 0.4 (a comment in the code promises a
finer per-method value with the verdict-model commit). *Corrected 2026-10-05: an earlier revision said today's rule counted any header that is present; it does not.* **Closed
2026-10-05 (D15): no finer per-method value will be built.** Measured read-only for the simplest version (full credit as soon as any one method was evaluated by a trusted receiver),
the confidence of 4 rows per variant changes in CONFIGURED and of none in STRICT; **no row's verdict, score, priority or reason moves**; two samples (the Kvish fixture and one
hand-written SPF-only fixture) cross the 0.6 gate upward, only in the two unknown-enrichment variants, with no tier change. The gate stays internal and binary.

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
decision: {disposition: "confirmed_phish"|"spam"|"benign"|"bec"|"other"|"unsure"|null, decided_at: str | null}   # editable once (D7)
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
| VERDICT   [ Needs analyst: signals present ]  priority 26      Checks completed: 7 of 13, 6 not checked  |
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
| ANALYST DECISION   ( ) confirmed phish ( ) spam ( ) benign ( ) BEC ( ) other ( ) unsure  [save]  note    |
+----------------------------------------------------------------------------------------------------------+
```

The order is deliberate: verdict and reasons, then what was and was not checked, then evidence by surface, then outputs, then the decision.
As decided in D19 the verdict card shows no numeric score; the priority figure in the sketch appears only for Needs analyst, labelled "Queue priority (ordering aid, not a
probability)".

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

**The earlier split was probably optimistic** *(Review change 12)*. The tuning and hold-out sets were a random split **by file**. Near-duplicate siblings of one campaign (the
same template, sender infrastructure and link domains) probably landed in both, so the agreement seen on the hold-out may have measured, in part, how well the rules recognise
siblings of mail already seen. This was not measured; the v1 hold-out numbers are read with that caution, and nothing in v2 relies on them.

### 6.2 The feedback log gains a final disposition

Additive migration of the `feedback` table (hashes, tiers, signal names and labels only):

| Column | Type | Content |
|---|---|---|
| `disposition` | text, nullable | `confirmed_phish`, `spam`, `benign`, `bec`, `other`, `unsure` (set by the analyst after investigation, **editable once**: D7) |
| `disposition_ts` | text | UTC time of the latest write (at most two writes ever) |
| `verdict_tier` | text | `confirmed_malicious`, `suspicious`, `needs_analyst`, `no_indicators_found` |
| `blocker_codes` | text (JSON list) | codes only, for example `qr_not_decoded` |
| `sources_on` | text (JSON list) | which optional evidence sources were enabled for this analysis |
| `model_version` | text | for example `v2.0`, so numbers are never mixed across versions |

Rules: no subject, address, URL, host or body text is stored; the existing free-text `note` stays **local and is excluded from every
export and summary** (today it is part of the exported columns; changing that is section 8, decision 6). `agree/disagree` keeps working and is
interpreted against the tier. Summaries report counts per tier by disposition with Wilson 95% intervals.

**Approved in principle on 2026-10-05: an optional `basis` field on a disposition** *(Review change 10)*. Why: an analyst who sees "Confirmed malicious" may label a case
`confirmed_phish` because the tool said so, which would make the tool's own precision circular (automation bias). `basis` records what the label rested on, one of:
`independent_source` (for example a report from a mail provider or the recipient), `gateway_verdict` (the organisation's gateway or mail-security service), `analyst_analysis`
(the analyst's own investigation), `tool_tier_only` (nothing but the tool's tier). V7 is then reported **twice: with all cases and without the `tool_tier_only` cases.**
**It is a fixed-choice label with no content**: one of the four values above, nothing typed by the analyst. **D7's stored-field list gains it only when the security team approves storing dispositions at all**, and nothing is built.

### 6.3 Proposed acceptance criteria (for the owner to approve before any measurement)

Criteria are fixed here, before v2 exists. "Fresh sample" means a public-corpus sample drawn with a **new pre-registered seed from a snapshot
dated after this document**, never looked at, run **once** after the v2 detection design is frozen (frozen by the hash of the commit that
completes phase B). It restores blindness for v2 acceptance only; it does not make v2 design choices blind.

**How a fresh sample is drawn** *(Review change 12)*. Before the draw: **de-duplicate by a normalised content hash** (body text with whitespace and case normalised, plus
the attachment hashes), **cluster by sender registrable domain and by link registrable domains**, and **exclude every cluster in which any message was seen in tuning or in
the hold-out**. The size left after exclusion is reported with the result, and **the fresh sample must have at least 100 messages after the exclusion step; below that it is not run.**

**Freeze scope** *(Review change 13)*. **One fresh sample per freeze.** **Each seed is pre-registered in this document, with its date, before it is used to draw.** Phase B
is one freeze. **Every Phase C source changes detection and is its own freeze** with its own fresh sample; **each source writes its benign fixtures first**, and they must stay
below T2, before any detection is added. A sample is never reused across freezes.

*Edits of 2026-10-05 to this table (V1, V7, V8) and the new V12 to V17 are part of decision D8, approved by the owner on 2026-10-05 with conditions (V18 and the follow-up items included).*

| ID | Criterion | Threshold | Data | Label |
|---|---|---|---|---|
| V1 | **Never a positive-claim word**: no user-visible string (API labels and reasons, UI, report draft, exports, log messages) contains safe, clean, legit, benign or harmless as a whole word, except the allowlisted negated disclaimers, the frozen v1 field and its internal keys, third-party product names by exact string, and provider raw-data field names (2.1) | 0 occurrences outside the allowlist | static lint test over every such string | invariant |
| V2 | **T4 never with a blocker** | 0 violations | property test over all fixtures, mutations and the fresh sample | invariant |
| V3 | **T1 never without hard evidence** | 0 violations | same | invariant |
| V4 | **Every analysis has a non-empty coverage report**; every `by_design` or missing item has a reason code | 100% | same | invariant |
| V5 | **Internal addresses never reach a provider** | 0 requests | recording fake HTTP over the internal-address matrix (exists) | invariant |
| V6 | **Phase A and D change no verdict**: per-sample verdict, score and priority identical to the committed baseline. **The baseline file keeps its v1 columns (verdict, score, priority, reason, signals) unchanged and gets the v2 tier columns beside them** (tier, reason codes, blocker codes), so the v1 comparison stays a test | 100% identical | tuning split and fixtures, STRICT and CONFIGURED, both enrichment modes | regression |
| V7 | **T1 precision in the field** (only once enough dispositions exist). Positives: `confirmed_phish` and `bec`. `spam` is **not** a positive. See the rules below the table | lower Wilson 95% bound of positives among labelled T1 cases **at least 0.90, with at least 50 labelled T1 cases** | analyst dispositions | tuned after viewing hold-out |
| V8 | **T4 phish rate in the field**: descriptive, with a sentinel rule below the table | report the upper Wilson 95% bound of `confirmed_phish + bec` among labelled T4 cases; **no pass/fail at any count** | analyst dispositions | tuned after viewing hold-out |
| V9 | **Disagree rate by tier** | report with intervals; no threshold | analyst feedback | descriptive |
| V10 | **Recall on the fresh sample** | report flagged (T1 plus T2) with a Wilson interval, STRICT and CONFIGURED, T3 shown separately; **no target** | fresh sample, once | tuned after viewing hold-out |
| V11 | **Priority sanity** | AUC and share above the benign median reported, labelled sanity only (the benign side is synthetic) | tuning plus fixtures | descriptive |
| V12 | **T2 only through a named route**: T2 if and only if the case satisfies one of the routes of D22; there is no generic "two independent findings" route (2.1a) | 0 violations | property test over generated finding sets, all fixtures and all mutations | invariant |
| V13 | **v2-only display**: with `verdict_v2` active, a v1 `malicious` that v2 demotes is never displayed (2.4) | the v1 verdict element and the v1 `verdict` field value are absent from the verdict card, the report draft and the CSV: 0 occurrences, checked by element and field, not by substring | frontend and report tests with a demoted-case fixture | invariant |
| V14 | **Every tier has a non-empty `reasons` list** (T4: the positive evidence, T3: at least a `gap` reason) | 0 violations | property test, same data as V2 | invariant |
| V15 | **T1 carries `hard_evidence` entries, each with an `indicator` and a `source`** (extends V3) | 0 violations | same | invariant |
| V16 | **A parser failure, limit or timeout never yields T4** (it is a blocker, 2.3) | 0 violations | fault-injection tests over every parser plus the property test | invariant |
| V17 | **Logs, exports and the feedback log stay content-free, and the rendering rules are unchanged**: the existing tests (no markup rendering, no remote images, links defanged and not clickable, no content in logs or exports) stay green | 0 failures | the existing frontend rendering-rules test, the job-store and log tests, the feedback tests | invariant |
| V18 | **Word-ban mutation test** (D18): inserting a banned word into a label, a reason text or a finding title makes V1 fail; the same word as a provider field name inside the raw-data block does not | 0 undetected mutations | mutation test over the V1 lint | invariant |

**V7 rules** *(Review change 9; part of D8, approved 2026-10-05)*. **V7 to V9 cannot be measured until the security team approves storing dispositions.** A 0.90 lower Wilson 95% bound needs **at least 35, 53, 69 and 84 labelled T1 cases for 0, 1, 2 and 3 errors**
(an error is a T1 case labelled `spam`, `benign` or any non-positive; the figures are computed, not fitted). 30 cases with no error give only 0.8865, which is why 30 is not
enough. With the 50-case minimum the cases needed are therefore **50 (0 errors), 53 (1), 69 (2), 84 (3)**.

| Errors among labelled T1 cases | Cases needed for a lower bound of at least 0.90 | Lower bound at exactly 50 cases |
|---|---|---|
| 0 | 35 (the minimum of 50 applies) | 0.9286 |
| 1 | 53 | 0.8950 (not met) |
| 2 | 69 | 0.8654 (not met) |
| 3 | 84 | 0.8378 (not met) |

* **Positives are `confirmed_phish` and `bec`.** `spam` is **not** a positive: a T1 case labelled `spam` is an error (a spam message is not "confirmed malicious"), and so is
  `benign`. Both stay in the denominator.
* **`unsure` and `other` are excluded from the denominator.** Their counts are reported next to the result so the exclusion cannot hide a trend.
* **H0 matches are reported separately** and are not in V7 (they are the organisation's own judgements: circular, as H0 says).
* **If the bound is not met, keep collecting.** The thresholds, the hard-evidence rules and the 0.90 are **not changed afterwards** to make the bound pass.
* If the `basis` proposal (6.2) is approved, V7 is reported with and without the `tool_tier_only` cases.

**V8 sentinel rule.** Any T4 case later labelled `confirmed_phish` or `bec` is **reviewed immediately** (which blocker or evidence was missing), **logged in this document**
with its reason, and **bumps `model_version`**. The upper Wilson 95% bound with **zero** phish among labelled T4 cases is **11.4% at 30 cases, 3.7% at 100 and 1.3% at 300**;
the number is reported at whatever count exists, never as a pass.

Real-world precision stays unmeasured until analysts supply dispositions; the tool says so in the README and in the report footer.

## 7. Phased plan

Order: A, then B, then C one source at a time, D (can run alongside C), then E. Every phase ends with the full backend and frontend suites,
both guard scripts, `test_standalone`, and one atomic commit group per source or feature. A commit that touches more than three source files
is announced first.

| Phase | Goal | Files likely touched | Tests | Regression rule |
|---|---|---|---|---|
| **A. UI and schema** | `evidence` (hop timeline, links, attachments, body, images), `coverage_report`, `schema_version`; new page layout; decision endpoint and storage | `contracts/analysis.py`, new `app/evidence.py`, new `app/coverage.py`, `api/pipeline.py`, `api/routes.py`, `feedback.py`; frontend `types.ts`, `ResultsView.tsx`, new `CoveragePanel.tsx`, `EvidencePanel.tsx`, `HopTimeline.tsx`, `DecisionBar.tsx` | schema tests (old JSON still parses, new fields optional), coverage derivation tests for every reason code, frontend tests for old-shape and new-shape results | **must not change any verdict, score or priority** (V6); a committed baseline of per-sample verdicts for the tuning split and fixtures is added first, so the rule is a test |
| **B. Verdict v2** | **first a text-only wording cleanup (V1; done 2026-10-05), then a pre-registration commit (D20) and the synthetic cases (D23)**, then tiers, hard evidence, blockers (**metadata-level detection only**: magic-number type, nested .eml and .msg, .ics, malformed From, count of `data:` images, structured parse-failure flags), mapping table | `scoring/overrides.py`, `scoring/config.py`, new `scoring/tiers.py`, `contracts/scoring.py` | table-driven tests of the mapping (2.4), **the reason-class test (every finding code has exactly one class, D22)**, property tests V2 and V3, blocker tests per blocker that Phase B detects (2.3; the encryption blockers are tested in Phase C), before/after tier table on tuning and fixtures | **changes verdicts by design**; the only permitted changes are the documented ones (v1 `malicious` without hard evidence becomes T2; T4 with a blocker becomes T3, including the blockers added on 2026-10-05; **a v1 `suspicious` without two independent reasons or a named strong signal becomes T3**, 2.1a); thresholds are a priori and **not** tuned on any sample; the predicted row movements are written down before the run (D20); labelled tuned after viewing hold-out |
| **C. Evidence sources** (one per sub-phase: lookalike, HTML attachment, static attachment, QR, RDAP, redirect and landing) | add evidence and signals (including the **encryption flags** for Office, PDF and archives, run in the D10 subprocess) | per source: a new module, `policy.py` where the network is used, `indicators.py`, `coverage.py`, config and README | offline fakes, privacy tests (what leaves the machine), **a benign fixture set per source, written first**, that must stay below T2, a mutation test where relevant | each source adds signals or hard evidence only through the tier rules in section 2; no weight is fitted; external and sandbox sources stay OFF; each change labelled tuned after viewing hold-out |
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
| 4 | **Blockers for T4** (2.3 item 5): which surfaces count, and whether an unread shared-platform link or a missing trusted receiver blocks T4 | approve the list in 2.3 as extended on 2026-10-05 |
| 5 | **Keep the body text in the API response?** Today `parsed_email.body_text` is returned. Option: strip it and fetch on demand | strip by default |
| 6 | **Free-text note in the feedback log**: exclude it from exports and summaries | exclude |
| 7 | **Dispositions** (`confirmed_phish`, `spam`, `benign`, `bec`, `other`, `unsure`; editable once): the set and who records them | approved as D7; the optional `basis` field (6.2) is a separate proposal |
| 8 | **Acceptance criteria V1 to V18** (6.3) and the fresh-sample protocol (new seed, de-duplicated and clustered, one sample per freeze) | approved 2026-10-05 with conditions (D8) |
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
| D7 | **Dispositions: `confirmed_phish`, `spam`, `benign`, `bec`, `other`, `unsure`.** Recorded by the analyst **after investigation**, **editable once**. Stored fields only: **file hash, verdict (tier), signal names, label, timestamp** (plus the optional fixed-choice `basis` label with no content, approved in principle on 2026-10-05, 6.2; it is stored only once the security team approves storing dispositions) (the local note is separate and never exported, D6). | approved |
| D8 | **Acceptance criteria (section 6.3): approved by the owner on 2026-10-05 with these conditions.** (1) The criteria are **V1 to V18 as written in section 6.3**, **plus** these follow-up items of 2026-10-05: (a) a provider score of 70 or more that does not rest on H1 to H3 is T2 only with a second independent reason, otherwise T3 (2.2); (b) a **text-only cleanup commit** of existing finding text that contains banned words, **before the V1 lint is enabled**, with the baseline moving 0 rows (2.1); (c) in route 3 of D22 "contributing" means above-info findings in at least two different reason classes; (d) **Phase B detects only metadata-level blockers**, and the encryption flags move to Phase C, in the D10 subprocess (2.3); (e) **V13 is tested by element and field**, not by substring; (f) the **baseline keeps its v1 columns unchanged and gains tier columns beside them, and the fresh sample needs at least 100 messages after the exclusion step** (6.3). (2) The **`basis` field is approved in principle** as a **fixed-choice label with no content** (6.2). (3) **V7 to V9 cannot be measured until the security team approves storing dispositions.** Rules that apply regardless, recorded earlier: criteria are **written and approved before any measurement**; the **fresh sample is drawn once, with a new seed, after the v2 freeze**; precision criteria are judged on **Wilson lower bounds**; the **minimum number of dispositions is fixed in advance** (in the approved criteria); **precision criteria are evaluated only on analyst dispositions**, never on a public corpus or on synthetic mail. The review of 2026-10-05 (below) edited V1, V6, V7, V8 and V13 and added V12 and V14 to V18; they are part of what was approved. | **approved 2026-10-05, with conditions** |
| D9 | **Hunting-query templates: a generic format first**, then KQL or SPL (the owner will say which). **Table and field names live in untracked configuration**; **no organisation names appear in any tracked file.** | approved |
| D10 | **Evidence-source order approved** (lookalike, HTML attachment, static attachment, QR, RDAP, redirect and landing). **Attachment parsers run in a separate subprocess with a timeout, a memory limit and no network.** | approved |
| D11 | **One pinned, wheel-only QR package, with hash pinning** (`pip --require-hashes`). Candidates and notes are below; the choice is the owner's. **Pillow decompression-bomb limits** apply to every image that is decoded. | candidates proposed |
| D12 | **Local first; shared instance later.** | approved |
| D13 | **The single-sample Hebrew urgency phrase is removed from the shipped lexicon** ("valid for one month only", taken from the Kvish sample; removed 2026-10-05). **Logged as "tuned after viewing hold-out".** Reason: one sample's wording is not a lexicon entry, and the phrase also fired on a legitimate hand-written Hebrew newsletter (fixture 06). Measured effect, exactly **8 of 856 baseline rows**, all in the two as-is variants (the ablated variants already lacked it): Kvish score 20 to 18 and priority 48.5 to 45.3, **still suspicious**, signals unchanged; fixture 06 STRICT score 4 to 3 (still inconclusive); fixture 06 CONFIGURED with clean enrichment **inconclusive to benign** (it meets every benign condition: trusted, aligned DKIM and DMARC passes, its sender domain on the eval's known-sender list, no finding above info severity, confidence 1.0 with full enrichment coverage); with unknown enrichment it stays inconclusive and only the reason changes. No tuning-corpus row moved: tuning flagged 6/75 STRICT and 22/75 CONFIGURED, unchanged. The CONFIGURED eval trusts every hop by default and lists synthetic known senders, so fixture 06 becoming benign is a regression guard, not evidence about real mail. | applied |
| D14 | **Lookup boundary: enrichment covers only link hosts and attachment hashes, by design.** The **sender domain and image hosts are never looked up automatically.** They are manual: every indicator already carries "Look up" links, and an **optional per-indicator lookup button** may be added later, **OFF by default**, with a visible warning that it **sends the hostname to a third-party provider** (named on the button). **The button is not built yet.** Reasons, so the boundary is a decision and not an accident of how the first version was scoped: a lookup tells the provider that this organisation received mail from that domain at that time, which reveals suppliers and correspondents; for a spoof of the organisation's own public domain it reveals that the organisation is being impersonated; tracker hostnames can carry per-recipient tokens; and the extra lookups would hit provider rate limits and the per-email cap. Any future change is logged here. | decision recorded, button not built |
| D15 | **"Confidence: NN%" measures data coverage, not correctness.** It is the sum over the three modules of weight times coverage (authentication 0.35, enrichment 0.40, content 0.25) and is used only as a gate (below 0.6 a would-be benign or suspicious verdict becomes inconclusive). **Phase B replaces it with "Checks completed: N of M, K not checked"**, built from the coverage report. **Authentication coverage already counts only results written by a trusted receiver** (**corrected 2026-10-05**: `header_present` is true only when SPF, DKIM and DMARC were all evaluated by a trusted receiver, so today's value is 1.0 or 0.4, and an SPF-only gateway leaves it at 0.4; an earlier version of this row said it counted any header that is present, which was wrong). **Closed 2026-10-05: there will be no finer per-method coverage value.** Measured read-only, the simplest version moves 0 rows and nudges only 2 samples across the gate (no tier change), so it is not worth a behaviour change. **The 0.6 gate stays internal and binary; the page shows only "Checks completed: N of M, K not checked"**, counted from the coverage report. Review change 7's pre-registered authentication-coverage change is **withdrawn**, because trusted-only coverage already exists. | **closed 2026-10-05** |
| D16 | **"Independent reasons" (decided 2026-10-05).** Two reasons are independent when they come from **different signal families (sender, link, claim)** or from **different categories (authentication, enrichment, content)**. A finding that carries a structural family tag counts under that family; any other finding counts under its category; info findings are never reasons. **Consequences:** two high content findings are **one** reason (one category); a **weighted score of 35 to 69 is T2 only with above-info findings in at least two different reason classes** (route 3 of D22), otherwise T3; an **enrichment floor that does not rest on H1 to H3 is one reason** (it needs a second independent reason to be T2). **The strong-signal list is unchanged** (a trusted-receiver authentication failure). This is a **deliberate demotion of three v1 `suspicious` routes** (the content floor, a non-hard enrichment floor, and the score band) and **must be pre-registered with predicted rows** (D20). **Measured read-only on 2026-10-05, aggregates only:** of the 856 baseline rows, the rows that are suspicious today (9 per variant in STRICT, 25 in CONFIGURED) are produced **only** by the structural corroboration floor (64 rows over all variants and modes) and the authentication floor (72 rows); **none by the content floor, the enrichment floor, the score band or a score of 70 or more**. So the three demoted routes move **no baseline row**, the new rule and the old agree on every row, and those three routes can be exercised only by new synthetic cases, written first. | decided 2026-10-05 |
| D17 | **Shared-platform URLs can reach T1 only when the path-and-query opt-in is on for that provider** (default off), because only then is the full URL, not the host, what the provider matched (decided 2026-10-05; applies to H2 and H3, 2.2 rule 4). | decided 2026-10-05 |
| D18 | **The `harmless` exemption is scoped to provider field names inside the raw-data block only** (decided 2026-10-05). A **mutation test is required** (criterion V18): the same word placed in a label, a reason text or a finding title must still fail V1, and only the provider field name inside the raw-data block may carry it. | decided 2026-10-05 |
| D19 | **The numeric score is dropped from the verdict card** (decided 2026-10-05). `score` and `priority` **stay in the API**. **Priority is shown only for Needs analyst, labelled "Queue priority (ordering aid, not a probability)"**. Per-category contributions stay in the detail section. | decided 2026-10-05 |
| D20 | **Phase B starts with a pre-registration commit** (decided 2026-10-05) holding **the tier rules, the thresholds and the predicted row movements, computed by a read-only script before any scoring code changes**. The **"benign fixtures first"** rule applies (and, for the three demoted routes, the demotion cases are written first because the baseline never exercises them). | decided 2026-10-05 |
| D21 | **`docs/UI_DESIGN.md` tier labels are updated as the first step of the verdict-card work** (decided 2026-10-05): Confirmed malicious, Suspicious, Needs analyst, No indicators found; internal keys and tokens stay. | decided 2026-10-05 |
| D22 | **Reason counting and the named routes (decided 2026-10-05).** **Only findings above info severity count as reasons**; **gaps and info findings never do.** Reasons count **only inside the named routes**, which are the complete list of ways to reach T2: (1) the **structural corroboration floor** (signals from at least two different families, sender, link, claim); (2) the **authentication floor** (a trusted-receiver authentication failure, the strong signal); (3) the **score band**: a weighted score of 35 to 69 **and above-info findings in at least two different reason classes** ("contributing" means exactly this, **not** "categories that add points to the score"); (4) the **content floor plus a second independent category or family** (the content floor's own key is content, so the second reason must come from authentication, enrichment, or a structural family); (5) the **enrichment floor not resting on H1 to H3, plus a second independent category or family** (its own key is enrichment); (6) **hard evidence in conflict** with the known-sender list or the organisation's own domain (T2 with the conflict reason; hard evidence otherwise is T1). **"Two independent reasons" is the standard that routes 4 and 5 (and, through categories, route 3) must meet; it is not a separate generic route, and none may be built by accident.** For information only, measured read-only on 2026-10-05: a generic rule would have turned 36 STRICT and 24 CONFIGURED tuning rows (of 69 and 53 not suspicious today) into T2, taking flagged from 6 to 42 of 75 and from 22 to 46 of 75 (the pairs are authentication with claim, link or sender), and no fixture or spoof; that is why it is not adopted. **Reason classes (requirement added 2026-10-05).** Every finding maps to **exactly one reason class: auth, enrichment, content, sender, link or claim.** The class is **keyed by the family tag the finding already carries** (the `evidence.family` tags the structural floor reads: sender, link, claim), **not by the module that produced it** (for example a display-name finding produced by the authentication module is a claim; a click-tracker finding produced by the content module is a link). A finding that carries no family tag takes the class the mapping table assigns it explicitly (auth, enrichment or content). **The mapping table is part of the Phase B pre-registration commit (D20), and a test fails unless every finding code in the code base has exactly one class.** Findings have **no stable code today** (only a title, which can contain an indicator), so the pre-registration commit also introduces one: an additive, content-free identifier per finding kind. Independence in this decision means different reason classes. | decided 2026-10-05 |
| D23 | **Phase B writes synthetic cases first (decided 2026-10-05), before any scoring code changes**, because the baseline cannot exercise the new rules. **Measured read-only on 2026-10-05:** none of the 856 rows is produced by the content floor, the enrichment floor or the score band; none is v1 malicious (so a v1 malicious without hard evidence has no baseline case); and the 7 fixtures that are benign today (CONFIGURED, clean enrichment) carry **no blocker** (no attachment, shortener, shared-platform link or unreadable language; one has a remote image, which is not a blocker today), so all 7 would stay T4 and say nothing about the blockers. The cases, each with its expected tier written into it: **for each demoted route** (content floor, enrichment floor not on H1 to H3, score band) **one case with a single category (expected T3) and one with a second independent category (expected T2)**; **H1, H2 and H3 positives (T1)**; **a shared-platform URL without the path-and-query opt-in (not T1)**; **a conflict case** (hard evidence on a known-sender or own-organisation domain: T2 with the conflict reason); **one case per blocker that Phase B detects** (2.3; each must stop T4; the encryption cases are written first in Phase C); and **a parser failure (never T4)**. | decided 2026-10-05 |

### Review changes (2026-10-05)

A review of this document, made before any Phase B work, revised the sections below. **Nothing here is implemented. The owner approved the acceptance criteria (D8) on
2026-10-05 with the conditions recorded there.** Each entry says what changed and why.

| # | Where | What changed | Why |
|---|---|---|---|
| 1 | 2.1, V1 | Positive-claim words (safe, clean, legit, benign, harmless) are banned as whole words in every user-visible string, with a closed allowlist of exact negated disclaimers and exemptions for the frozen v1 field, its internal keys and provider raw-data field names | the old rule named four words and no scope; "harmless" is the same kind of claim; a disclaimer such as "not a safety verdict" must stay possible; the VirusTotal field is literally called `harmless` |
| 2 | 2.1, new 2.1a, 2.4, V12 | T2 means two independent reasons or one named strong signal (a trusted-receiver authentication failure); a property test pins it; the 2.4 rows for the score band, the content floor and a non-hard enrichment floor become "T2 only with a second independent reason, else T3" | "several weak signals" was undefined, and one family repeating itself is one cause, not two; this **weakens three v1 `suspicious` routes** and is therefore a behaviour change to pre-register |
| 3 | 2.2 | H2 and H3 follow D2: only link hosts, link URLs and attachment hashes count (never a Received-hop address, a header domain or an image host); an IP alone never counts; shared-platform domains never count; a shared-platform URL counts only on an exact URL match (possible only with the path and query opt-in); hard evidence on a known-sender or own domain gives T2 with an "evidence conflict" reason, never T1; H0's load-time rules use the same lists | H2 accepted any IP and any header-derived name; a flagged supplier or own domain is more often a provider error or a compromise than a verdict to state alone |
| 4 | 2.3 | Blockers added: parser failure, limit or timeout; nested message attachments (.eml, .msg); calendar invites (.ics); encrypted or password-protected Office and PDF files; a malformed From header (and the D4 items are written into 2.3) | each is a surface the tool cannot read; calling it "no indicators found" would overclaim |
| 5 | 2.3 | T4 is not relaxed for SPF-only mail; missing DKIM and DMARC evaluation is a deployment issue | shared ESP includes make SPF alignment weaker than it looks |
| 6 | 2.4, V13 | With `verdict_v2` active the UI, report draft and exports show only v2; a demoted v1 `malicious` is never displayed; test required | a displayed v1 "Malicious" next to a v2 "Suspicious" would be two verdicts |
| 7 | 2.4, 3, 4.2 | The page shows "Checks completed: N of M, K not checked" and never the 0.6 confidence figure (the gate stays internal); **the second half of this entry, a pre-registered authentication-coverage change, is WITHDRAWN (2026-10-05, D15 closed)**: trusted-only coverage already exists and a finer value moves no row | D15: confidence measures data coverage, not correctness. The "Checks completed" display stands |
| 8 | 2.1 | The four tier labels are the source of truth; `docs/UI_DESIGN.md` must be updated to match (tier labels only; internal keys and tokens stay) | UI_DESIGN.md still says "Malicious" and "Inconclusive: analyst review" |
| 9 | 6.3, V7 | At least 50 labelled T1 cases (cases needed for a 0.90 lower bound: 35, 53, 69, 84 for 0 to 3 errors; 30 of 30 gives 0.8865); positives are `confirmed_phish` and `bec`; `spam` is not a positive; `unsure` and `other` leave the denominator with their counts reported; H0 matches are separate; if the bound is not met, keep collecting and never change the thresholds | 30 cases cannot support 0.90 even with no error |
| 10 | 6.2 | **Proposal only:** an optional `basis` field on dispositions, with V7 reported with and without `tool_tier_only` cases. D7's stored-field list is unchanged until approved | automation bias: a label that rests only on the tool's tier makes its precision circular |
| 11 | 6.3, V8 | V8 stays descriptive, with a sentinel rule (a T4 later labelled `confirmed_phish` or `bec` is reviewed at once, logged here and bumps `model_version`) and the zero-phish upper bounds (11.4% at 30, 3.7% at 100, 1.3% at 300) | the old text implied a pass or fail above 100 cases; the rare miss matters more than the rate |
| 12 | 6.1, 6.3 | The earlier random split by file probably put near-duplicate campaign siblings in both tuning and hold-out, so the hold-out agreement may have been optimistic; a fresh sample is de-duplicated by a normalised content hash, clustered by sender and link registrable domains, and excludes every cluster seen in tuning or hold-out | siblings of one campaign are not independent samples |
| 13 | 6.3, 7 | One fresh sample per freeze; each seed pre-registered before drawing; every Phase C source is its own freeze and writes its benign fixtures first | a sample reused across freezes stops being blind |
| 14 | 6.3, V14 to V17 | New invariants: every tier has a non-empty `reasons` list; T1 has `hard_evidence` entries each with an `indicator` and a `source`; a parser failure never yields T4; logs, exports and the feedback log stay content-free and the rendering rules are unchanged (existing tests stay green) | each is a way the verdict could silently overclaim or leak |
| 15 | 4.1, 6.2, 8 | Dispositions are editable **once** (D7), and `unsure` is in the set everywhere | 6.2 said "can be changed" and listed five values; D7 (section 10) says six and once |
| 16 | 10 (D22), 7 | Reason classes: every finding maps to exactly one class (auth, enrichment, content, sender, link, claim), keyed by the family tag it carries and not by its module; the mapping table is part of the Phase B pre-registration commit with a test that every finding code has exactly one class; findings get a stable, content-free code for it | "independent" needs a definition that cannot depend on which module happened to emit a finding; findings have no stable code today |
| 17 | 2.3 | A remote (hot-linked) image is not a blocker (no pixels to decode); the blocker is an image attachment or an inline or embedded (`cid:` or `data:`) image; the new blockers are detected in Phase B from metadata only, deep parsing stays in Phase C (**the list of Phase B blockers and the move of the encryption flags to Phase C are superseded by entry 22**); a table says which are derivable today | the earlier text said "inline image", which a reader could take to include remote images; the parser drops `cid:` and `data:` sources, so the detection level had to be stated |
| 18 | 2.3 | "No indicators found" is expected to be rare for real mail while the tracker, shared-platform and redirect blockers exist; reaching it is not a goal | so no one loosens a blocker to make the fourth tier more common |
| 19 | 2.2 | The closing paragraph no longer says a provider score of 70 or more that does not rest on H1 to H3 "stays T2": it is T2 only with a second independent reason, otherwise T3 | it contradicted 2.1a, 2.4, D16 and D22 |
| 20 | 2.1, 7 | The record that existing finding, indicator and log text contains banned whole words; Phase B starts with a text-only cleanup commit before the V1 lint is enabled, found by running the lint in report-only mode, with the baseline moving 0 rows | the lint would fail on day one; the examples are real ("benign mail", "not clean", "content is safe") |
| 21 | 10 (D22 route 3), 2.4, D16 | "Contributing" means above-info findings in at least two different reason classes, not categories that add points | the earlier wording could be read as a score-contribution test, which is not independent evidence |
| 22 | 2.3, 7, D23 | Phase B detects only metadata-level blockers: magic-number type from the first bytes, nested .eml and .msg, .ics, malformed From, the count of `data:` images, structured content-free parse-failure flags; the encryption flags (encrypted Office, PDF `/Encrypt`, password-protected archives) move to Phase C in the D10 subprocess; nothing is lost for T4 because an unexamined active, container, Office, PDF or archive attachment already blocks T4. **Correction:** an earlier table said a nested message was not yet a blocker; `.eml` and `.msg` are classed as active and already block T4 | reading encryption flags is parsing hostile files, which belongs in the subprocess of D10 |
| 23 | 2.4, V13 | V13 is tested by element and field (the v1 verdict element and the v1 `verdict` field value absent from the card, the report draft and the CSV), not by substring | a substring search cannot tell a label from a word in a reason |
| 24 | 6.3, V6 | The baseline keeps its v1 columns unchanged and gets tier columns beside them; a fresh sample needs at least 100 messages after the exclusion step, and below that it is not run | V6 must stay a test; a sample that small cannot support the intervals |
| 25 | 10 (D8), status line, 6.2 | D8 is approved by the owner on 2026-10-05 with conditions (V1 to V18 as written plus items 19 to 24); the `basis` field is approved in principle as a fixed-choice label with no content; V7 to V9 cannot be measured until the security team approves storing dispositions | owner decision |
| 26 | 2.1, V1 | A new exemption category, **third-party product names, exact string only** (one entry today: Microsoft Safe Links, with its reason in `wording_allowlist.json`); V1 covers the app's own strings; LLM-generated text appears only inside the card labelled "AI opinion, not a verdict" and is exempt | a product's own name is not the app's wording and renaming it would misname the product; the model's words are not the app's |
| 27 | 2.1, V1 | The LLM prompt must never contain the raw v1 value; one label function (`app/verdict_labels.py`) turns a verdict into words for every reason, log line, CLI line and the prompt; the prompt has no exemption in the lint | the first line of the prompt sent the raw literal `benign` to the model, and an override reason built from the verdict could print it |
| 28 | 2.1, 7 | The wording cleanup is done (four small commits; 0 hits in the report-only lint); the maintainers' comment field in `shared_platforms.json` is not scanned, only the display fields of its entries | the lint would otherwise fail on documentation that the app never shows |

**Conflicts between these instructions and the earlier text, resolved as written above** (the owner may reverse any of them): the 2.4 mapping gave T2 to the score band, the content
floor and a non-hard enrichment floor (now T3 without a second independent reason, entry 2); Phase B's "only permitted changes" listed two (now three, plus the extended blockers);
D2's URL rule meets the hostname-only lookup policy (entry 3, rule 4); the VirusTotal `harmless` field meets the word ban (entry 1); V7's 30-case minimum, V8's "no pass/fail below
100" and 6.2's five dispositions all differed from the new text; the wireframe showed a confidence figure (entry 7); and `docs/UI_DESIGN.md` uses different tier labels
(entry 8). **Resolved 2026-10-05 (D19):** the numeric score is dropped from the verdict card.

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
