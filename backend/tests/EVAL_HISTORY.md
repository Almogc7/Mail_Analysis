# Eval history

Output of `python -m tests.eval` (enrichment=clean: providers stubbed to "no detections").
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
