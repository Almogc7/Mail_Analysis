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
