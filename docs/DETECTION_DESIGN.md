# Detection design (pre-registered)

**Status: pre-registered 2026-10-03, BEFORE any tuning run of the structural signals.** This file is committed
before the signals are implemented. It fixes the signal families, the weights, the floor rule and the reason for
each, so they cannot be quietly bent to fit the tuning set. Every later change is logged in the iteration log at
the bottom, with a reason, and counts against a cap.

Scope: the structural detections added after the first real false negative (the "Kvish 6" invoice lure): sender
infrastructure, link infrastructure, and claim/brand signals, plus the corroboration rule that turns them into a
floor. The authentication, enrichment and verdict model already exist (README, `scoring/overrides.py`).

## Rules of engagement

1. **Tuning set only.** The 75-sample tuning split of the public corpus may be looked at (aggregates and per-sample
   signal counts). The hold-out split is not touched until after the verdict model is finished, and then only via
   `python -m tests.eval --final-holdout`, which reports BOTH trust modes (pre-registered in `backend/tests/HOLDOUT_LOG.md`).
2. **Iteration cap: 5** for the structural work combined. An *iteration* is any change to a signal rule, weight,
   family assignment or threshold made after looking at tuning results. Running the design below unchanged is
   iteration 0 and is free. If the cap is reached, work stops and the owner is told.
3. **No signal is added or loosened to raise tuning recall.** The corroboration rule (>= 2 different families) is
   not loosened. A new signal needs (a) a rationale that does not depend on the corpus -- a documented phishing
   technique -- and (b) benign fixtures that exercise it and must stay below SUSPICIOUS.
4. **Synthetic benign results are a regression guard only**, never an accuracy claim. Real-world precision is not
   established and every report says so.
5. **Weights are set a priori** (below), by relative strength of evidence, not fitted.

## Verdict model recap

* flagged = `suspicious` or `malicious`; `needs_review` = inconclusive; `legit` = benign (the literal rename is last;
  the user-visible label for that state becomes "no indicators found", never a guarantee).
* **Benign requires positive evidence of legitimacy, not only authentication** (iteration 1, below): a verified aligned
  DKIM pass or a DMARC pass from a TRUSTED receiver AND the sender's registrable domain on the KNOWN-SENDER list
  (untracked config, empty by default) AND no finding above info severity AND adequate coverage (confidence at or above
  the threshold and complete enrichment: an unknown or uninformative indicator counts as inadequate). Authentication
  proves who sent a message, not that the sender is legitimate; attackers authenticate their own domains.
* Everything else that is not flagged is inconclusive, with a sub-reason: `signals_present` (something fired, not enough
  to call) or `no_signals_insufficient_evidence`, and a numeric queue `priority`.
* A floor is never undone by low coverage.
* **Priority** (a priori, not fitted): weighted score + 5 per DIFFERENT structural family + 2 per finding above info
  (at most 10 counted), capped at 100. It orders a review queue; it is not a probability.

## Families

A *family* is a class of evidence about one aspect of the message. Several signals in the same family count ONCE
toward the floor, because they tend to share a cause (one hosting box produces both a server-style sender and a local
submission hop; one cloned template produces both hot-linked images and tracker links).

| Family | What it describes |
|---|---|
| `sender` | how the message entered the mail system: hosting-style identity, local submission, freemail |
| `link` | the infrastructure behind the links and assets: click trackers, hot-linked assets, redirectors |
| `claim` | what the message presents itself as: a brand/display-name claim, a claimed entity, decoy links to it |

## Floor rule

A **structural floor to SUSPICIOUS** fires when findings from **>= 2 different families** are present. Findings
count only if they carry `evidence.structural = true` and an `evidence.family`. Signals in one family count once.
Weak signals never floor on their own; they only add to the category score through their weight. The floor is
recorded as the override `structural_corroboration_floor`, listing the families and signals.

Existing hard floors are unchanged: a high-severity finding from a TRUSTED receiver's SPF/DKIM/DMARC failure, or a
critical enrichment finding, still floors alone.

## Signals

Severity is the finding severity; weight is the additive contribution to its module's category subscore (sender
signals live in `auth_check`; link and claim signals in `content_analysis`). "Near-miss exemptions" are the
legitimate patterns the rule is written NOT to fire on; each has a benign fixture.

### Family `sender`

| ID | Rule | Sev / weight | Documented technique | Near-miss exemptions |
|---|---|---|---|---|
| `S1` machine-provisioned sender claiming a brand | From domain is a server-style hostname and/or the mailbox is auto-generated, AND the display name or subject carries a brand the sender domain does not belong to (EXISTING finding, unchanged, now tagged `sender`) | medium / 15 | Phishing sent from compromised or throwaway shared-hosting accounts shows the hosting box as the sender | machine-looking sender WITHOUT a brand claim (contact forms, cron mail) never fires |
| `S2` local-submission first hop | The first hop is a local submission (Exim `with local`, Postfix `from userid`) and not authenticated SMTP | low / 6 | Mail injected by a script or compromised account on a host, bypassing authenticated submission | a legitimate site's contact-form or order mail from its own shared host: alone it is one family and cannot floor |
| `S3` freemail with a brand display name | Sender domain is a freemail provider (config file) AND the display name carries a known brand | medium / 10 | Display-name impersonation from free accounts | freemail without a brand claim never fires; a freemail user named like a brand is a known limitation |

### Family `link`

| ID | Rule | Sev / weight | Documented technique | Near-miss exemptions |
|---|---|---|---|---|
| `L1` platform-mismatched click tracker | A clickable link targets an ESP click tracker (shared-platforms kind `esp_tracker`, which only says what IS a tracker) AND the OBSERVED SENDING PATH shows no trace of that platform: its name or registrable domain appears in none of the Received hop hosts, DKIM `d=`, envelope domains (Return-Path, Received-SPF, hop envelope-from), List-Unsubscribe hosts or the Message-ID domain. **Carve-out (D5):** not judged when the path is aligned with the From domain (DKIM d= or envelope on it) AND the message came in over the network, which is the standard branded-ESP setup. A local-submission origin is never carved out. No sending path at all = no judgement | medium / 8 | A tracked link borrows a reputable platform's domain while the mail was not sent through it | mail really sent through the ESP (any trace) never fires; branded-ESP sends over the network never fire; Safe Links/Proofpoint wrappers are `link_wrapper`, not `esp_tracker`; own-domain tracking hosts are not platform hosts |
| `L2` hot-linked third-party assets | >= 2 images and >= 50% of image hosts are one non-platform registrable domain X that is not the sender's AND X ALSO hosts some of the message's links (or its label is a token of the display name/subject) | low / 5 | Cloned newsletters keep the original vendor's assets and tracking links while only the visible sender changes | images from an unrelated CDN or stock site that the links do not use never fire; images on the sender's own domain or a shared platform never fire |
| `L3` redirector chain | A link is a known URL shortener, or carries another full URL in its query that points at a different registrable domain, excluding `link_wrapper`/`esp_tracker` hosts | low / 5 | Open redirects and shorteners hide the real destination and borrow reputation | gateway wrappers (Safe Links, Proofpoint, Mimecast) and ESP trackers are excluded; links back to the sender's own domain are excluded |

### Family `claim`

| ID | Rule | Sev / weight | Documented technique | Near-miss exemptions |
|---|---|---|---|---|
| `C1` brand/display-name claim | An exact whole-token brand (map + aliases, incl. Hebrew/transliteration) in the display name or subject, sender registrable domain not the brand's. Replaces today's display-name finding. **MEDIUM and no floor on its own** | medium / 12 | Display-name spoofing | sender on the brand's domain never fires; fuzzy-only stays a separate medium/10 finding; a business literally named like a brand ("Apple Valley Dental") is MEDIUM only |
| `C1b` brand mention in the body | An exact brand token in the body text of a message from a non-brand sender. **Additive only, not a family signal** | info-low / 3 | Body-only brand mentions are common in benign mail (a friend writing about an order) | never counts toward the floor |
| `C2` claimed-entity mismatch | One non-platform registrable domain D dominates the message's links+images (>= 50% of non-platform hosts, >= 2 occurrences), D is unrelated to the sender's registrable domain, AND the message has NO `DKIM-Signature` header at all. Does NOT depend on trust: an absent header is an observable fact; a present one is only a claim. When a trusted receiver verified an ALIGNED DKIM/DMARC pass, the signal is suppressed | low / 8 | A lure built from an entity's links/assets but sent from an unrelated, unsigned origin | mail whose links are on the sender's domain or on shared platforms never fires; any DKIM-Signature header present (even unverified) suppresses it |
| `C3` decoy links to the claimed entity | A token of the display name or subject (digits stripped, whole token, >= 4 letters) equals the label of a linked registrable domain that is not the sender's (e.g. display `kvish6`, link `kvish6.co.il`); OR a link points at a known brand's real domain from a non-brand sender. Brand-map independent in the first form | medium / 10 | Decoy links to the real service make a lure look genuine while the call-to-action goes elsewhere | the sender's own domain, shared platforms and generic words (< 4 letters, or in a small stop list) never match |

## Additive weights, in order of evidential strength (a priori)

`trusted SPF/DKIM/DMARC fail 25` > `S1 15` > `C1 12` > `S3 10` = `C3 10` > `L1 8` = `C2 8` > `S2 6` > `L2 5` = `L3 5` >
`C1b 3`. Rationale: a verified authentication failure is a hard fact; a brand claim combined with a machine-provisioned
origin is a combination; a bare brand claim is common in benign mail; local submission, hot-linked assets and
redirectors are individually common and benign, so they are weak. These weights only shape the score within
SUSPICIOUS/inconclusive; flagging is decided by the floor rule.

## Changes to existing signals

* The display-name spoofing finding drops from HIGH/25 (which floored alone) to `C1` MEDIUM/12 with no floor.
  **Predicted consequence:** the four synthetic display-name-only positives (`s01`, `s02`, `s04`, `s05`) stop being
  flagged and become inconclusive (one family); `s03` (freemail + brand = `sender` + `claim`) stays flagged. They are
  re-labelled as single-family "must not floor alone" cases and corroborated variants are added.
* The brand map gains aliases (display/subject/body matching across scripts); the `kvish6` brand and its aliases are
  labelled seeds and are removed by `--ablate-seeds`.

## Not included, and why

* **Domain age (RDAP) and hosting-ASN reputation:** need live network lookups with an offline fallback that cannot be
  exercised on the offline eval; no signal is added that the eval cannot test.
* **Form/credential-harvest markers, attachment content, OCR, NLP for text-only lures:** out of scope for this
  iteration (README "What the detectors can and cannot see").
* **Resolving redirect chains:** off by default and not part of this design.

## Fixtures

Benign (must stay below SUSPICIOUS in BOTH trust modes; synthetic, regression guards only): ESP mail with and without
a `DKIM-Signature`; a Mailchimp-style newsletter; a small business on shared hosting sending its own newsletter
(local submission), one variant that also uses a click tracker and one that also hot-links images from an unrelated
host; an order confirmation from shared hosting with local submission; a Safe Links-wrapped external mail; mail with
click-tracking redirectors on the sender's own platform; personal freemail mail that mentions a brand in the body.
Positive controls: single-family claims that must NOT floor, and two-family combinations that must.

## Pre-registered predictions

1. Kvish 6 with seeds ablated reaches >= SUSPICIOUS from structural signals alone (`sender` S2, `link` L1/L2, `claim`
   C2/C3), in both modes.
2. Every benign fixture stays below SUSPICIOUS in both modes.
3. `s01`, `s02`, `s04`, `s05` become inconclusive; `s03` stays flagged.
4. Tuning recall rises by an amount I will not predict numerically. No recall target is set.

## Reporting

After each commit group: files touched, tests added, STRICT vs CONFIGURED tables with benign / inconclusive /
suspicious / malicious counts, the inconclusive rate on the synthetic benign set (the triage-queue cost), and
per-family signal counts on the tuning set and on the fixtures.

## Iteration log

Tuning iterations used: **1 / 5** (D5 below was made before L1 fired on any tuning sample and is not counted).

| # | Date | Change | Reason | Tuning effect (aggregate) |
|---|---|---|---|---|
| 0 | 2026-10-03 | Design registered; floor rule + C1 demotion + S1/S2/S3 implemented as written | pre-registration | STRICT flagged 9 -> 0; CONFIGURED 25 -> 18 (see deviation D2) |
| 1 | 2026-10-03 | Benign rule: add known-sender list (untracked, empty by default) and complete-enrichment requirement; inconclusive sub-reason; queue priority; ranking sanity metric | benign rule treated authentication as legitimacy; 11/75 tuning phish reached benign in CONFIGURED | CONFIGURED missed 11 -> 0 (all 11 inconclusive); synthetic benign CONFIGURED benign 8 -> 6, inconclusive 9/15 |

Iteration 1 is a verdict-model change, not a detection signal, but it is logged here because it was made after looking
at tuning results.

## Predictions vs results so far (2026-10-03)

| # | Pre-registered prediction | Result so far | Status |
|---|---|---|---|
| 1 | Kvish with seeds ablated reaches >= SUSPICIOUS from structural signals alone, both modes | **Met** after the link family: ablated Kvish is `suspicious` in STRICT and CONFIGURED via `structural_corroboration_floor` from S2 (sender) + L1 + L2 (link); no claim-family signal and no brand list contributed. No weight was changed to get there | **MET** |
| 2 | Every benign fixture stays below SUSPICIOUS in both modes | Holds: 0 of 21 flagged in STRICT and CONFIGURED (15 original + 6 link-family guards) | holds |
| 3 | s01, s02, s04, s05 become inconclusive; s03 stays flagged | Holds exactly after S3 landed. Between the floor commit and the sender-family commit s03 was also inconclusive, because S3 did not exist yet | holds (see D1) |
| 4 | "Tuning recall rises by an amount I will not predict" | **Wrong in direction.** Tuning flagged fell: STRICT 9 -> 0, CONFIGURED 25 -> 18 | **DEVIATION D2** |

Deviations, each with its reason:

* **D1 -- timing of s03.** The design describes s03 as claim + sender, but S3 (the sender-family half) was implemented one
  commit after the floor. For that one commit s03 was inconclusive. Reason: the floor mechanism and the signals were
  committed separately to stay within the 3-source-file limit. No behavior difference in the final state.
* **D2 -- tuning recall fell instead of rising.** All nine STRICT detections and seven of the 25 CONFIGURED ones were
  bare display-name claims (one family). Demoting C1 to MEDIUM with no floor was the design's own decision; the design
  predicted the effect on the synthetic positives but wrongly implied a net recall gain overall. The drop is the price of
  not flagging a business named like a brand; the link and claim signals are meant to win it back through corroboration.
  Nothing was tuned to recover it.
* **D3 -- the benign rule was not part of this design's scope and was wrong.** Iteration 1 above. Reason: authenticated
  mail on an attacker's own domain reached benign (11/75 in CONFIGURED). The design's recap of the verdict model was
  updated; the weights and the floor rule were not touched.
* **D4 -- reporting additions.** The inconclusive sub-reason, the queue priority and a ranking sanity check (AUC and
  fraction above the synthetic-benign median) are added to the eval tables. They were not in the original reporting
  section. The ranking check is a sanity check only: the benign side is synthetic.
* **D5 -- L1 carve-out for branded ESP sending.** The registered L1 rule exempted a "branded bounce subdomain"; the first
  implementation (following the instruction to judge against the observed sending path) dropped it and fired on the
  hand-written ESP fixtures `03` and `04`, whose path is on the sender's own domain (CNAME'd return-path, branded relay).
  Vendors document that setup as the default, so the platform's name being absent from the path is expected, not
  evidence. The carve-out is: path aligned with the From domain AND network origin. A local-submission origin is never
  carved out. Made before L1 fired on any tuning sample (it fires on 0 of 75), so it is not a tuning iteration.
  Known leftover: fixture `04` (no DKIM, no return-path, relay not on the sender's domain) still fires L1 alone: one
  family, inconclusive, never flagged. Known blind spot: an attacker on their own VPS with a branded-looking path who
  copied a template's ESP links is not caught by L1.

## Link-family results (2026-10-03, tuning set, aggregates)

* Samples in which each signal fired (tuning, n=75): S2 5, L1 0, L2 4, L3 10, C1 9. Samples with signals from >= 2 families: **1**.
* So the sender and link families add almost nothing to recall on the public corpus: STRICT flagged is 1/75, CONFIGURED
  18/75 (the 18 come from trusted gateway authentication failures, not from structure). The structural families
  separate the Kvish-type lure (shared-hosting origin + borrowed tracker + cloned assets) and little else in this sample.
* Synthetic benign (n=21): S2 fires in 4, L1 in 1; none carries two families.
