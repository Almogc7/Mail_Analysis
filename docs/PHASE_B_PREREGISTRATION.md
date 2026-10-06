# Phase B pre-registration (verdict v2)

**Status: frozen when this file is committed, before any tier code exists.** Written 2026-10-06. It fixes the tier rules, the thresholds, the interface and the predicted row movements, so that
Phase B can be judged against what was written first. The design it freezes is `docs/DESIGN_V2.md` (sections 2, 3, 6.3 and decisions D1 to D23, review entries 1 to 32); where this
file and that one disagree, **this file is the frozen text** and the disagreement is a deviation to be logged (section 6). Nothing here is code: no scoring, verdict, threshold, contract,
API or UI change is made by the commit that adds this file, and nothing under `scoring/` is created or changed by it.

**Fixed inputs, by hash.** Hashes are SHA-256 of the file's bytes after replacing CRLF with LF (so a checkout with either line ending gives the same value).

| Input | File | sha256 |
|---|---|---|
| Finding-code registry, frozen snapshot (47 kinds) | `backend/tests/fixtures/finding_codes_frozen.json` | `a75deafeb1f2e217f087beac181035047e102ef2eba5613af5fe0a6d7348cbb6` |
| Reason classes and eligibility, frozen snapshot (47 entries) | `backend/tests/fixtures/reason_classes_frozen.json` | `09ca84841f4bdbcc92fa191915dff7adafb24a9bbb1b2325998f779b6fc357cf` |
| Predicted tiers for the 856 baseline rows | `backend/tests/fixtures/predicted_tiers.json` | `edd260d46fbc56bf816e139986e20ebb707de1f6bdd9a000e98bfe916e6d7c23` |
| The read-only predictor | `scripts/predict_tiers.py` | `035257a2eea3586b8c470260bf85fbd642ff0530c3fc22c340fe9ac52db6a6cb` |

The specification cases (`backend/tests/fixtures/v2_cases.json`, D23) are added by the next commit; its hash is entered in section 7 with a dated line, which is a record and not a rule change.

---

## 1. Frozen rules

### 1.1 The four tiers and their labels

| Tier | Label shown | Internal key (frozen v1 key, unchanged) | Meaning |
|---|---|---|---|
| T1 | **Confirmed malicious** | `malicious` | at least one entry in `hard_evidence` (1.5) |
| T2 | **Suspicious** | `suspicious` | reached only through one named route (1.2); every reason is listed |
| T3 | **Needs analyst** | `inconclusive` | the default: not enough evidence either way; sub-reason `signals_present` or `no_signals_insufficient_evidence`, plus a queue priority |
| T4 | **No indicators found** | `benign` | positive evidence and no blocker (1.6). Not a safety statement; neutral styling, always shown with its blockers (D1) |

The label map is the only place a tier becomes words (`app/verdict_labels.py` is the one function). The raw `benign` key never reaches a user-visible string (V1).

**A tier is only raised by evidence and only lowered by missing evidence. T3 is the default.**

### 1.2 The order of evaluation and the T2 routes

Evaluation order, first match wins:

1. **Hard evidence (1.5).** If at least one hard-evidence entry survives the rules of 1.5 and is not in conflict, the tier is **T1**. A hard-evidence entry in conflict (1.5 rule 5) is not T1: it is route R6.
2. **T2 routes**, any one is enough; the first that holds names the route id (the `reasons` list names every route that holds):

| Route | Condition (exact) | Severity rule |
|---|---|---|
| **R1** structural corroboration floor | eligible findings that carry a family tag (sender, link, claim) from **at least two different families** | none (unchanged from v1) |
| **R2** authentication floor, the strong signal | a **trusted-receiver** SPF, DKIM or DMARC `fail`: a finding with code `AUTH_SPF_CHECK_FAILED`, `AUTH_DKIM_CHECK_FAILED` or `AUTH_DMARC_CHECK_FAILED` and produced severity `high` (high or higher: clarification C2) | none (one reason is enough) |
| **R3** score band | a weighted score of **35 to 69** (below 70) **and** eligible findings of **medium or higher** produced severity in **at least two different reason classes** | **medium or higher** for every counted reason |
| **R3B** score of 70 or more | a weighted score of **70 or more** and no hard evidence. **No class condition** (the weights make it arithmetically impossible for one module to reach 70: largest single-module contribution 0.40 x 100 = 40; stated limitation in `DESIGN_V2.md` 2.1a) | none |
| **R4** content floor | the v1 content floor (**two or more content findings at severity high**) **and** a second reason in a class other than content (auth, enrichment, sender, link or claim) | the second reason must be **medium or higher** |
| **R5** enrichment floor, not resting on H1 to H3 | the v1 enrichment floor (an enrichment finding at severity **critical**, a provider score of 70 or more) with no hard-evidence entry for it, **and** a second reason in a class other than enrichment | the second reason must be **medium or higher** |
| **R6** evidence conflict | hard evidence (1.5) on a registrable domain that is on the known-sender list or is the organisation's own domain: **T2 with the visible reason `evidence_conflict`** (the reasons list names the evidence and the list) | none |

There is **no generic "any two independent findings" route** (D22). A case that satisfies no route is T3 or T4, never T2.

**Reasons.** A finding is a *reason* only if (a) its kind has `counts_as_reason` true in the table (1.4) and (b) its **produced** severity is above info. In routes R3, R4 and R5 a reason
must also have produced severity **medium or higher**; a low-severity finding stays in the reasons list for the analyst and cannot be the second reason there. "Independent" means **different
reason classes**: auth, enrichment, content, sender, link, claim. **It means different classes of evidence, not statistical independence**; two classes can be correlated and the rule does not claim otherwise.

**Strong-signal list (closed; an addition needs an owner decision logged in section 6):** a trusted-receiver authentication failure (R2). That is the only entry.

**The internal 0.6 coverage gate (unchanged from v1, never displayed).** If confidence is below 0.6 and the weighted score is 10 or more, a case that reached T2 **only through R3** becomes
T3 (v1 `low_confidence_inconclusive`). The gate does **not** apply to R1, R2, R4, R5, R6 or R3B, and **it does not apply when a v1 floor condition holds** (the trusted failure, two high
content findings, a critical enrichment finding, or two structural families): low coverage of other evidence never erases a floor (v1 `floor_protects_verdict`). The gate also applies to T4 (1.6, condition 4).

**T3 sub-reason (unchanged from v1):** `signals_present` if any finding above info exists (eligible or not), otherwise `no_signals_insufficient_evidence`. `needs_analyst_reason` also carries
`low_confidence` when the gate demoted a case.

### 1.3 The tier-3 queue priority

`priority` is unchanged (v1 rule: weighted score plus 5 per different structural family plus 2 per finding above info, at most 10 counted, capped at 100). **It is displayed only for Needs
analyst, labelled "Queue priority (ordering aid, not a probability)"** (D19). It stays in the API for every tier. The numeric score is not shown on the verdict card (D19).

### 1.4 Eligibility and classes (the table)

Every finding code has exactly one class and a `counts_as_reason` flag, in `backend/app/reason_classes.py`, pinned by the two hashes above. **47 kinds; 26 never count**: the 20
info-default kinds, plus `AUTH_FROM_HEADER_AMBIGUOUS` (parse note), `ENRICH_SKIPPED_PER_EMAIL_LIMIT` (gap), `AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED`, `AUTH_DKIM_FAILURE_CLAIMED_UNTRUSTED`,
`AUTH_DMARC_FAILURE_CLAIMED_UNTRUSTED` (results written below the trust boundary) and `AUTH_ALIGN_NONE_ALIGNED_FALLBACK` (the compared domain came from a header the sender writes). The rule: a kind
counts only if its severity can be above info **and** it is a real signal about the message, not a gap, a parse note or an untrusted claim. The class follows the family tag when the
kind has one, whichever module produces it; an untagged kind takes auth, enrichment or content, explicitly. Known limitation: a display-name spoof (claim) and its fuzzy twin (auth,
deliberately untagged) would count as two classes on one message.

### 1.5 Hard evidence (T1)

| # | Hard evidence | Threshold (a priori, D2) | Phase |
|---|---|---|---|
| H1 | the attachment's SHA-256 is **MalwareBazaar `matched`** (status ok) | matched | B |
| H2 | a **link host, link URL or attachment hash** the recipient interacts with **exactly matches ThreatFox with confidence at least 75** | `confidence_level >= 75` (74 does not count) | B |
| H3 | **VirusTotal reports at least 10 engines malicious** for an attachment hash, a URL taken from a link, or a domain taken from a link | `malicious >= 10` (9 does not count) | B |
| H4 to H6 | credential form on a resolved landing page; auto-executing macro or PDF action; HTML attachment with a password field posting to a remote host | not built | C |

**The six rules (DESIGN_V2.md 2.2).**

1. Only indicators the recipient interacts with count: link hosts, link URLs and attachment hashes. A Received-hop address, a From or Reply-To domain, an image host or any header-derived name never counts, whatever a provider says.
2. An IP alone never counts, for H2 and H3, including a link whose host is an IP.
3. A domain on the shared-platform list never counts.
4. A shared-platform URL counts only on an exact URL match, and lookups are hostname-only by default, so it can reach T1 only when the path-and-query opt-in is on for that provider (D17).
5. **Evidence conflict:** hard evidence on a registrable domain that is on the known-sender list or is the organisation's own domain is **T2 with the reason `evidence_conflict`, never T1** (route R6). The organisation's own domains live in untracked configuration.
6. H0 (a local IOC list; documented, not built) uses the same lists: a shared-platform host, a known-sender or own domain, or an internal-looking name is rejected before an entry can match.

Not hard evidence: any authentication result, a display-name claim, a hosting sender, a tracker or redirector, hot-linked assets, a young domain, urgency language, an unreadable language, the LLM's opinion.

### 1.6 T4 and the blockers

T4 requires **all** of: (1) a verified, **aligned DKIM pass or a DMARC pass written by a trusted receiver**; (2) the sender's registrable domain is **on the known-sender list**; (3) **no finding
above info severity**; (4) **complete coverage**: confidence at or above 0.6 and complete enrichment; (5) **no blocker**. T4 is not relaxed for SPF-only mail. A case with the positive evidence and a blocker is T3 with the blocker listed.

**The full blocker list (DESIGN_V2.md 2.3), and when each is derived.**

| Blocker | Derived in Phase B from metadata? | Waits for Phase C? |
|---|---|---|
| image attachment, or an inline or embedded image (`cid:` part, `data:` image) while QR decoding is off | **yes**: coverage flag `qr_not_decoded` today, plus magic-number confirmation and a count of `data:` images | the QR decode itself |
| active or container attachment (Office with macros, HTML, script, archive, disk image, PDF) not examined | **yes**: declared type today, plus magic-number type from the first bytes (catches a renamed file) | static analysis |
| link shortener or redirector not resolved | **yes** (existing coverage flag `redirects_not_resolved`) | resolution |
| link hosted on a shared platform, not looked at | **yes** (existing flag `shared_platform`) | none |
| internal-looking host | **yes** (existing flag `internal_host_not_sent`) | none |
| message in a language the tool cannot read, or with no readable text | **yes** (existing flags `language_unsupported`, `no_readable_text`) | none |
| Received chain with no hop from a trusted receiver | **yes** (existing flag `no_trusted_receiver_hop`) | none |
| HTML attachment, until analysed | **yes** (type) | HTML analysis |
| nested message attachment (`.eml`, `.msg`) | **yes** (already classed active; magic-number confirmation added) | analysis of the inner message |
| calendar invite (`.ics`) | **yes** (declared name and type, plus magic-number confirmation; a blocker from Phase B) | examining its content |
| malformed or unparseable From (`from_header_unparseable`) | **yes** (a structured flag replaces free text) | none |
| parser failure, limit or timeout on any part | **yes**: a structured, content-free flag (a code, never an error text) per part | none |
| password-protected archive; encrypted or password-protected Office or PDF | **no new flag**: already covered because the file is an unexamined active or container type | the encryption flags, in the D10 subprocess |

**A remote, hot-linked image is not a blocker** (an `<img>` pointing at an http or https address is never fetched, so there is nothing to decode or miss). **A parser failure is never T4.**

### 1.7 "Checks completed: N of M, K not checked"

Counted from the coverage report alone (D15). **M** = the number of coverage items that apply to this message and are **not** `by_design`. **N** = the number of those with status `checked`.
**K** = M minus N (status `not_checked` or `partly`). **`by_design` items are listed separately and counted in none of N, M or K.** The 0.6 figure is never displayed. Worked examples are in section 4.

### 1.8 The v1 field

The v1 `verdict`, `score`, `confidence` and `priority` fields stay in the response, unchanged in meaning, for compatibility; `verdict_v2` carries the tier. With `verdict_v2` active the UI shows only `verdict_v2` (V13).

---

## 2. The interface contract (names only, no code)

The tier function is `compute_tier` in the module `app.scoring.tiers` (not created by this commit). It is a pure function of the following inputs.

**Inputs**

| Name | Contents |
|---|---|
| `findings` | list of: `code`, produced `severity`, and, looked up by code in the table, `class` and `counts_as_reason` |
| `score` | the v1 weighted score (a number) |
| `contributions` | the per-category contributions to that score (auth_check, enrichment, content_analysis) |
| `trusted_auth_failures` | list of: `method` (spf, dkim, dmarc), `result`, written by a trusted receiver |
| `hard_evidence_candidates` | list of: `indicator_type` (link host, link URL, attachment hash, other), `source` (malwarebazaar, threatfox, virustotal), `engine_count` or `confidence`, `is_ip`, `is_shared_platform`, `path_optin_on`, `exact_url_match`, `is_known_sender_or_own_domain` |
| `blockers` | list of blocker codes (1.6) derived in Phase B |
| `t4_positive_flags` | `trusted_aligned_dkim_or_dmarc_pass`, `sender_on_known_list` |
| `coverage_gate` | `confidence`, `confidence_threshold` (0.6), `enrichment_complete` |

**Outputs**

| Name | Contents |
|---|---|
| `tier` | T1, T2, T3 or T4 |
| `route_id` | R1, R2, R3, R3B, R4, R5 or R6 for T2; `HARD_EVIDENCE` for T1; `T4_POSITIVE_EVIDENCE` for T4; `DEFAULT` for T3 |
| `reasons` | list of: `code`, `class`, produced `severity`, and the route(s) it supports |
| `hard_evidence` | list of: `indicator`, `source`, `rule` (H1, H2 or H3); non-empty exactly for T1 |
| `blockers` | the blockers that apply (always listed, whatever the tier) |
| `needs_analyst_reason` | for T3: `signals_present` or `no_signals_insufficient_evidence`, plus `low_confidence` when the gate demoted a case; otherwise empty |

---

## 3. Predicted row movements

### 3.1 The prediction, in words, written before the predictor was run

*Written on 2026-10-06 from the design and from the v1 verdict counts already recorded in the baseline file; the predictor script did not exist and had not been run.*

The 856 baseline rows are 4 variants (clean or unknown enrichment, seeds as-is or ablated) x 2 modes x 107 samples. Their v1 verdicts are 136 suspicious, 706 inconclusive (524
`signals_present`, 182 `no_signals_insufficient_evidence`), 14 benign and **0 malicious**. The enrichment stubs answer "nothing found" or "disabled", so no row has hard evidence.

* **Every v1 suspicious row becomes T2, through R1 or R2.** DESIGN_V2.md D16 measured that these rows are produced only by the structural corroboration floor (64 rows) and the authentication floor (72 rows), and by nothing else (no content floor, no enrichment floor, no score band, no score of 70). R1 is the same condition as the v1 structural floor and R2 the same as the v1 authentication floor, neither changes, so I expect **136 rows at T2**, 64 through R1 and 72 through R2, with a row that has both counted under R1 first.
* **Every v1 inconclusive row becomes T3, keeping its v1 sub-reason:** 524 `signals_present` and 182 `no_signals_insufficient_evidence`. No such row satisfies a T2 route, because the v1 floors would have made it suspicious already.
* **Every v1 benign row becomes T4:** 14 rows (the 7 synthetic fixtures that are benign in CONFIGURED mode with clean enrichment, in two seed variants). D23 measured that none carries a blocker.
* **No row is T1.**

So I expect **0 of 856 rows to change tier** relative to the v1 mapping (suspicious to T2, inconclusive to T3, benign to T4), and the routes R3, R3B, R4, R5 and R6 and the severity rule to move nothing in the baseline; they can be exercised only by the specification cases.

### 3.2 What the predictor produced

`python scripts/predict_tiers.py --write` reran the 856 rows (about two minutes). Its recomputed v1 verdicts equal the recorded baseline on all 856 rows. The v1 verdict to predicted tier:

| v1 verdict | Rows | Predicted tier |
|---|---|---|
| suspicious | 136 | T2: 136 (route R1: 72, route R2: 64) |
| inconclusive | 706 | T3: 706 (sub-reason `signals_present` 524, `no_signals_insufficient_evidence` 182, each equal to the v1 reason) |
| benign | 14 | T4: 14 |
| malicious | 0 | none |

Per variant and mode: STRICT has 9 T2 and 98 T3 in every variant; CONFIGURED has 25 T2 in every variant, plus 75 T3 and 7 T4 in the two clean variants, and 82 T3 and no T4 in the two unknown variants. **No row is T1, and no row is reached through R3, R3B, R4, R5 or R6.**

**Rows that differ from the written prediction in 3.1: 0 at the level of the tier, the route family (R1 or R2 for every suspicious row) and the kept sub-reason: 0 of 856 rows change tier.**

**One figure in the written prediction was wrong, and it is left as written.** 3.1 said 64 rows through R1 and 72 through R2. The predictor gives **R1: 72 and R2: 64**. The cause, checked read-only: R1 holds in 72 rows and R2 holds in 72 rows, **8 rows satisfy both**, 64 satisfy R1 only and 64 satisfy R2 only. The 64 and 72 of D16 were counted in v1's override order (the authentication floor first), so the 8 rows with both were credited to authentication; this file's evaluation order puts R1 first, so they are credited to R1. The sentence in 3.1 combined the D16 numbers with "R1 first", which cannot both hold. It is a difference in attribution between two routes for 8 rows, not a difference in any tier, and it is reported here rather than corrected in 3.1.

---

## 4. Worked "Checks completed" examples (computed read-only)

Computed read-only from the coverage report, CONFIGURED mode, clean enrichment, seeds as-is. M counts the items that are not `by_design`; N those with status `checked`; `by_design` items are listed and counted in none.

| Fixture | v1 | Predicted | Checks completed | By design (not counted) | Items that block T4 |
|---|---|---|---|---|---|
| `malicious/kvish6_invoice_phish.eml` | suspicious | T2 via R1 | **7 of 10, 3 not checked** (DKIM and DMARC: the receiver evaluated SPF only; hosts on shared platforms not looked up) | 3 (links never opened, images not examined, HTML body not rendered) | `shared_platform` |
| `benign/synthetic/06_hebrew_newsletter_esp.eml` | benign | T4 | **9 of 9, 0 not checked** | 2 (links never opened, HTML body not rendered) | none |
| `benign/synthetic/02_safelinks_wrapped_internal.eml` | inconclusive | T3 (`no_signals_insufficient_evidence`) | **1 of 7, 6 not checked** (SPF, DKIM, DMARC: no trusted result; no trusted receiver hop; hosts on shared platforms not looked up; language undetermined, status `partly`) | 2 (links never opened, HTML body not rendered) | `no_trusted_receiver_hop`, `shared_platform` |

The counting rule gives the same N, M and K whatever the tier: a `partly` item is in K, a `by_design` item is in none, and the display never shows the 0.6 figure.

---

## 5. How the predictor works (so it can be audited)

`scripts/predict_tiers.py` is read-only and is not imported by the application. It reruns the same pipeline as the regression baseline over the same 856 rows (same variants, modes, samples and row
keys), builds for every row only the inputs of section 2 from data the pipeline already produces (findings with codes, the weighted score, the coverage report, the provider answers), applies
sections 1.2 to 1.6 exactly as written, and writes `backend/tests/fixtures/predicted_tiers.json` (per row: the v1 verdict, the predicted tier, the route, and for T3 the sub-reason; plus counts
per group). A test recomputes the as-is clean variant and compares it with the file. The hold-out is never read.

## 6. Deviation protocol

After this commit, **any change to a rule, a threshold, the table or the interface** needs a **dated entry in this section** giving: the change, the reason, **the data that motivated it** (aggregates only, codes only) and the **iteration count**. **The cap for Phase B is 3 iterations**; after the third, the rules stay as they are and the result is reported as it is. A change made without an entry here is a violation, whatever its effect.
An entry may not be made to improve a number that was measured on the fresh sample, which is drawn once, after the freeze (DESIGN_V2.md 6.3).

**Iteration count: 0 of 3.**

| Date | Iteration | Change | Reason | Data |
|---|---|---|---|---|
| 2026-10-06 | **C1, a clarification; not counted toward the cap** | The content floor (two content findings at severity high) is counted **by reason class** (class `content`, produced severity high or critical), not by the module that produced the finding; the enrichment floor likewise by class `enrichment` (severity critical). No rule changes. | The interface passes no module field, and D16 and D22 key reasons by class, not by module. The frozen predictor counts by module, as v1 does; the two differ only for a link-class finding (built by the content module) at severity high, which no producer emits. | A class-based recompute equals `scripts/predict_tiers.py` on all 856 rows (a test: in-process on the as-is clean variant, and on all 856 rows in a subprocess); **no row and no case changes**, so the iteration count stays 0 of 3. |
| 2026-10-06 | **C2, a clarification; not counted toward the cap** | Route R2 (the strong signal) holds for a trusted-receiver failure finding at produced severity **high or higher**, not only the literal `high`, exactly as v1's authentication floor (`auth_check` at least high). No rule changes. | Found by the V12 property test: the first oracle read "severity high" literally and disagreed with the v1-compatible implementation on severity `critical`, which no producer emits for these kinds (their severities are medium or high). The oracle and the implementation now agree; the frozen predictor still reads `high` literally and differs from them only at severity `critical`. | All 246,753 generated (set, score) pairs agree after the change; **no row and no case changes** (no baseline row has a trusted failure above high), so the iteration count stays 0 of 3. |

## 7. Register of fixed files

| Date | File | sha256 | Note |
|---|---|---|---|
| 2026-10-06 | see the table at the top | | frozen with this commit |
| 2026-10-06 | `backend/tests/fixtures/v2_cases.json` | `35840091d75595bb47d95d15d63bdfa2ef46fcf2ccbac9da384285442dc39356` | the 97 specification cases (D23), added after the pre-registration commit as the next commit; a record, not a rule change |
| 2026-10-06 | `backend/tests/fixtures/v2_cases.json` (supersedes the line above) | `ecdedf282f1b15fd6ba5fe59653d34e649f2919630c035ec7889a65a507a1241` | 100 cases: three conflict cases added, the blocker code `nested_message_unanalysed` renamed `nested_message_unexamined`, and `conflict_plus_live_evidence` now lists `evidence_conflict` (the reason is listed whatever the route); a record of the owner's step-8 instructions, not a rule change |
| 2026-10-06 | `backend/tests/fixtures/blocker_codes_frozen.json` | `390bd81bf477b23dd98e3c955eb611f076a5cf3c44476ab72ee3fc4b428b788f` | the frozen blocker codes (19) with source and Phase B detector status |
