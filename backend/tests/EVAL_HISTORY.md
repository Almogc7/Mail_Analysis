# Eval history

**Benign evidence is synthetic only; real-world precision is NOT established.** Output of `python -m tests.eval` (enrichment=clean: providers stubbed to "no detections").
Two rows per commit: **as-is**, and **ablated** (`--ablate-seeds`: the "kvish6" brand token and
the Hebrew urgency phrase taken from that one sample removed). The ablated row is the honest
one. Synthetic benign results are regression guards, not an accuracy claim; there is 1
malicious fixture, so read verdicts, not percentages. Strict = `needs_review` is not flagged.

| After commit | Mode | Malicious fixtures flagged | Benign flagged (FP) | Benign reaching MALICIOUS | Notes |
|---|---|---|---|---|---|
| HEAD `38043c1` (baseline) | as-is | 1/1 (suspicious, via auth floor only; score 10) | 3/10 | 0 | all 3 FPs are the same bug: fuzzy display-name match flags "Example *" as brand `apple` |
| HEAD `38043c1` (baseline) | ablated | **0/1** (legit, score 0, no non-info findings) | 3/10 | 0 | the true "before" |
| matcher fix, **before** (old code, 21 fixtures) | as-is | kvish 1/1, synthetic-spoof 5/5 | **8/15** | 0 | every benign flag is a substring/fuzzy brand hit (apple, discount bank); strict P=0.43 R=1.00 |
| matcher fix, **before** (old code, 21 fixtures) | ablated | kvish **0/1**, synthetic-spoof 5/5 | **8/15** | 0 | strict P=0.38 R=0.83 |
| matcher fix (token-based) | as-is | kvish 1/1, synthetic-spoof 5/5 | **0/15** | 0 | strict P=1.00 R=1.00 (synthetic-inflated) |
| matcher fix (token-based) | ablated | kvish **0/1**, synthetic-spoof 5/5 | **0/15** | 0 | strict P=1.00 R=0.83; Kvish still needs the structural signals (later commits) |
| b1 parser: Received-SPF + structured hops | as-is | kvish 1/1, synthetic-spoof 5/5 | 0/15 | 0 | no verdict change expected (parser-only); confirmed |
| b1 parser: Received-SPF + structured hops | ablated | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | unchanged; hops/SPF are parsed but nothing consumes them yet |
| b2 parser: img src, anchor/href normalization, raw sha256 | as-is | kvish 1/1, synthetic-spoof 5/5 | 0/15 | 0 | no verdict change (images are a separate field, not in urls) |
| b2 parser: img src, anchor/href normalization, raw sha256 | ablated | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | unchanged; images/anchors normalized but not yet consumed |
| b3 parser: banner/subject-tag stripping | as-is | kvish 1/1, synthetic-spoof 5/5 | 0/15 | 0 | no verdict change on current fixtures (banner words were not in any lexicon); test proves they no longer could be |
| b3 parser: banner/subject-tag stripping | ablated | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | unchanged |
| c1 auth: trusted receivers / not_evaluated (eval trusts fixture gateway hosts) | as-is | kvish 1/1, synthetic-spoof 5/5 | 0/15 | 0 | no verdict change; Kvish auth coverage stays 0.40 (SPF-only gateway) |
| c1 auth: trusted receivers / not_evaluated (eval trusts fixture gateway hosts) | ablated | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | unchanged; an intermediate version let SPF-only evaluation set coverage 1.0 (caught here, fixed + tested) |
| c1 auth (`--trusted-receivers none`, the out-of-box default) | as-is / ablated | 1/1 / **0/1**, spoof 5/5 | 0/15 | 0 | identical verdicts; every method not_evaluated |
| c2 auth: alignment findings | as-is (trust fixtures / none) | kvish 1/1, synthetic-spoof 5/5 | 0/15 | 0 | no verdict change: alignment findings are weight 0 except "no aligned authentication" (needs SPF+DKIM both trusted-evaluated) |
| c2 auth: alignment findings | ablated (trust fixtures / none) | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | unchanged. Kvish: trusted SPF pass is aligned (From == envelope == sweb.ru) -- correctly worth nothing |
| c3 auth: machine-provisioned sender + brand claim; registrable-domain mismatch | as-is (trust fixtures / none) | kvish 1/1 (score 10 -> 15), synthetic-spoof 5/5 | 0/15 | 0 | new medium finding fires on Kvish (server-style FQDN `vh319`, auto-generated mailbox, display-name brand) |
| c3 auth: machine-provisioned sender + brand claim; registrable-domain mismatch | ablated (trust fixtures / none) | kvish **0/1**, synthetic-spoof 5/5 | 0/15 | 0 | expected: the finding needs a brand claim and the seed is gone; the structural indicators are recorded but unscored until the sender-infra detections (f) |
| c4 auth: untrusted FAIL = low weight (4); positional-header signal; README trust model | all four modes | unchanged (kvish 1/1 score 15 as-is, **0/1** ablated; spoof 5/5) | 0/15 | 0 | no fixture carries an untrusted fail, so no verdict change |
| c5 eval: hold-out protection (`--final-holdout` + tracked log), per-source reporting (no pooled P/R) | all modes | unchanged: kvish 1/1 (score 15) as-is, **0/1** ablated | benign flagged: synthetic 0/15, real-user 0/0 (none yet) | 0 | report format change only; the tuning corpus does not exist yet |
| d1 enrichment policy: hostname-only lookups, opt-in path/query, provider guard + off-switch, any non-ok status = unknown | as-is / ablated | kvish 1/1 / **0/1**; spoof 5/5; tuning recall 5/75 | synthetic 0/15 (real-world precision NOT established) | 0 | unchanged: the eval stubs providers as clean, so this commit changes what leaves the machine, not verdicts |
| d2a shared platforms (config file) -> `uninformative`, no lookup | as-is / ablated | kvish 1/1 / **0/1**; spoof 5/5; **tuning recall strict 3/75 (was 5/75), lenient 5/75** | synthetic 0/15 (real-world precision NOT established) | 0 | 2 flagged tuning samples have links only on shared platforms: coverage now (correctly) drops and the known needs_review-over-floor defect (strict xfail in test_verdict_floors) downgrades them. Fixed in (g), not here. |
| d2b risk-ordered cap; dropped IOCs listed with rank+reasons; coverage counts dropped | as-is / ablated | unchanged (kvish 1/1 / **0/1**; spoof 5/5; tuning strict 3/75, lenient 5/75) | synthetic 0/15 (real-world precision NOT established) | 0 | the eval's tuning samples rarely exceed the cap on unique hosts, so recall is unchanged; the cap now drops the LEAST risky links |
| d3 LLM off by default; tokenized, titles-only prompt | as-is / ablated | unchanged (kvish 1/1 / **0/1**; spoof 5/5; tuning strict 3/75, lenient 5/75) | synthetic 0/15 (real-world precision NOT established) | 0 | the eval never calls the LLM. Measured after d2b: 0/75 tuning samples hit the per-email cap (was 15/75), 11 have a shared-platform link, 1 an internal-looking host. |
| (0a) tolerant From/Reply-To extraction + informational "From header parse ambiguity" finding (weight 0) | as-is / ablated | kvish 1/1 / **0/1**; spoof 5/5; **tuning strict 3 -> 6 /75, lenient 5 -> 9 /75** | synthetic 0/15 (real-world precision NOT established) | 0 | "no usable From" bucket 16 -> 1; misses with no non-info finding 31 -> 15. Effect of (0) alone (trusted-receivers=fixtures; the CONFIGURED mode arrives with the eval-modes commit). |
| (g1) floor protection: low coverage / needs_review never downgrades a floor-based verdict (strict xfails removed) | as-is / ablated | kvish 1/1 / **0/1**; spoof 5/5; **tuning strict 6 -> 9 /75, lenient 9 /75 (unchanged)** | synthetic 0/15 (real-world precision NOT established) | 0 | the 3 needs_review samples that carried a floor trigger are SUSPICIOUS again. Effect of (g1) alone. |

**From here on every row reports BOTH modes.** STRICT = nothing trusted (default deployment). CONFIGURED = the corpus collector's gateway headers trusted (default patterns: any header naming a hop in the chain; override with the untracked env var EVAL_CONFIGURED_TRUSTED_RECEIVERS). Corpus failure-header frequency is NOT representative of mail that passed a gateway, so CONFIGURED shows what trusting a gateway adds, not real-world recall. "inconclusive" = needs_review; "benign" = legit.

| After commit | Kvish (S / C) | Kvish seeds ablated (S / C) | Tuning flagged (S / C) | Tuning inconclusive (S / C) | Tuning benign (S / C) | Synthetic benign flagged / inconclusive (S / C) |
|---|---|---|---|---|---|---|
| eval modes (after (0), (g1)) | 1/1 / 1/1 | see note | 9/75 / **25/75** | 0 / 0 | 66 / 50 | 0/15, 0 inc. / 0/15, 0 inc. |
| language-aware content coverage (en/he only; other languages and empty bodies reduce coverage) | 1/1 / 1/1 | **0/1 / 0/1** | 9/75 / 25/75 | 0 / 0 | 66 / 50 | 0/15, 0 inc. / 0/15, 0 inc. |

(The eval-modes row above lists Kvish seeds-ablated as "see note": it is 0/1 in both modes. Language coverage changes confidence, not verdicts, until the verdict-model commit makes "benign" require sufficient coverage.)

**Verdict model update: benign now REQUIRES positive evidence.** Columns below are counts of verdicts (malicious / suspicious / inconclusive / missed-or-benign) per mode. "missed" = a confident benign verdict on a malicious set. STRICT trusts nothing, so benign is mostly unreachable by design there.

| After commit | Kvish (S / C) | Kvish seeds ablated (S / C) | Tuning mal/susp/inconc/missed STRICT | Tuning mal/susp/inconc/missed CONFIGURED | Synthetic benign: benign/inconc/susp/mal STRICT | Synthetic benign CONFIGURED |
|---|---|---|---|---|---|---|
| benign-needs-positive-evidence | susp / susp | **inconclusive / inconclusive** | 0 / 9 / 66 / 0 | 0 / 25 / 39 / **11** | 0 / **15** / 0 / 0 (rate 15/15) | 8 / **7** / 0 / 0 (rate 7/15) |

The 11 CONFIGURED "missed" are phishing samples whose OWN domain passes aligned DKIM/DMARC with nothing else flagged: authentication proves who controls a domain, not that the message is safe.

**Structural work (docs/DETECTION_DESIGN.md), iteration 0 = the pre-registered design unchanged.** Verdict counts per set as mal/susp/inconclusive/missed.

| After commit | Kvish S / C | Kvish ablated S / C | Synthetic spoofs S / C | Tuning STRICT | Tuning CONFIGURED | Synthetic benign STRICT (benign/inc/susp) | Synthetic benign CONFIGURED |
|---|---|---|---|---|---|---|---|
| e1: family floor + C1 demoted to MEDIUM | susp / susp | inconclusive / inconclusive | 0 flagged, 5 inconclusive / same | 0 / 0 / **75** / 0 | 0 / 18 / 46 / 11 | 0 / 15 / 0 | 8 / 7 / 0 |

e1 cost: tuning STRICT flagged 9 -> 0 (all nine were bare display-name claims: one family, now inconclusive and still visible to the analyst). Predicted in the design doc.
| e2: sender family S2 (local submission) + S3 (brand on freemail) | susp / susp | inconclusive / inconclusive | 1 flagged (s03), 4 inconclusive / same | 0 / 0 / 75 / 0 | 0 / 18 / 46 / 11 | 0 / 15 / 0 | 8 / 7 / 0 |

e2: iteration 0 (design unchanged). S2/S3 do not move the tuning counts: on their own they are one family. Ablated Kvish still needs a second family (link/claim) to flag. Tuning iterations used: 0 / 5.
| iteration 1: benign needs a known sender + complete enrichment | susp / susp | inconclusive / inconclusive | 1 flagged, 4 inconclusive (signals present) / same | 0 flagged / 75 inconclusive (60 signals, 15 none) / 0 missed | 18 flagged / 57 inconclusive (41 signals, 16 none) / **0 missed** | 0 / 15 / 0 | 6 / 9 / 0 |

Iteration 1 ranking sanity check (tuning phish vs SYNTHETIC benign priority; a sanity check only): STRICT AUC 0.845, 0.80 of phish above the benign median; CONFIGURED AUC 0.852, 0.79. Tuning iterations used: 1 / 5.
| e3: link family L1-L3 (+6 benign link guards, n=21) | susp / susp | **susp / susp (S2+L1+L2: sender+link)** | 1 flagged, 4 inconclusive / same | 1 flagged / 74 inconclusive / 0 missed | 18 flagged / 57 inconclusive / 0 missed | 0 / 21 / 0 | 6 / 15 / 0 |

e3 per-family signal counts (tuning, n=75): S2 5, L2 4, L3 10, C1 9, L1 0; >= 2 families: 1. Synthetic benign (n=21): S2 4, L1 1, no sample with 2 families. Ranking sanity (synthetic benign n=21): STRICT AUC 0.799, CONFIGURED 0.831. Iterations used: 1 / 5 (D5 not counted).
| e4: claim family C1b/C2/C3 + aliases (benign n=26) | susp / susp | susp / susp (S2+L1+L2+C3) | 1 flagged, 4 inconclusive / same | 6 flagged / 69 inconclusive / 0 missed | 22 flagged / 53 inconclusive / 0 missed | 0 / 25 / **1 (fixture 22, known FP)** | 6 / 19 / **1** |

e4: first run before iteration 2 was STRICT 9 / CONFIGURED 25 tuning flagged and fixture 20 flagged. Enrichment-UNKNOWN variant: synthetic benign CONFIGURED 6 -> 0; phishing sets unchanged. Per-family counts (tuning n=75): S2 5, L2 4, L3 10, C1 9, C2 29, C3 2, L1 0; >= 2 families: 6. Ranking sanity (benign n=26): STRICT AUC 0.771, CONFIGURED 0.820. Iterations used: 2 / 5.

**Comparability note.** The ranking AUC and 'fraction above the benign median' are NOT comparable across rows where the synthetic benign set changed size: n=15 (to e1/e2), n=21 (e3, after the six link-family guards), n=26 (e4, after the five claim-family guards). Each added fixture changes the benign side of the comparison itself, so a falling AUC across those rows (0.852 -> 0.842 -> 0.831 -> 0.820 in CONFIGURED) mostly reflects a harder, larger benign set, not a worse ranking. Compare AUCs only within one benign-set size.

**Verdict rename (2026-10-03).** From this point the literals are `benign` (was `legit`; label "No indicators found") and `inconclusive` (was `needs_review`). Rows above keep the old words as they were written. Eval tables now also print Wilson 95% intervals for every rate; a rate is `k/n = p% [95% CI lo-hi%]`.

**Reading this table (added 2026-10-03, after the hold-out).**
(a) A "missed" count of 0 is by construction while the known-sender list is empty for the phishing sets: the benign rule needs a
known sender, so it cannot fire. It is not a miss rate.
(b) Recall means **flagged** only (suspicious or malicious). Inconclusive is not a catch.
(c) The Kvish mutation finding: the local-submission origin hop is load-bearing, and an authenticated-mailbox phish with a clean display
name, a direct link and its own images is invisible to the current families (`KVISH_MUTATIONS.md`).
(d) Still unproven: real-world precision; Hebrew and Israeli-brand phishing beyond one sample; text-only BEC; image-only mail; attachment
content; authenticated or compromised-mailbox lures; the D5 carve-out on real ESP headers; compromised vendor/partner accounts.
The hold-out (n=75, once, 2026-10-03): STRICT flagged 6/75 [3.7-16.4%], CONFIGURED flagged 20/75 [18.0-37.6%], missed 0/75 in both; see HOLDOUT_LOG.md.

**Synthetic corpus = two groups (2026-10-04).** The hand-written files are reported as two separate groups and are never pooled: **26 benign fixtures** (benign/synthetic) and **5 synthetic spoofs** (malicious/synthetic), 31 files in all. Neither is an accuracy claim. Current numbers (enrichment clean, no verdict logic changed): synthetic spoofs flagged 1/5, inconclusive 4/5, missed 0/5 in STRICT and CONFIGURED; benign fixtures, STRICT benign 0 / inconclusive 25 / flagged 1 of 26, CONFIGURED benign 6 / inconclusive 19 / flagged 1 of 26; none reach malicious. Ranking sanity (tuning phish vs the 26 benign fixtures): STRICT AUC 0.771, CONFIGURED 0.820. Eval output now prints these under their own names ("synthetic spoofs", "benign fixtures") and a corpus line with both counts; only printed labels changed, the baseline keys did not (856/856 rows unchanged).
