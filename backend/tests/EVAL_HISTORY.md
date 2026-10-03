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
