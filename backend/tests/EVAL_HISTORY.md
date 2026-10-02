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
