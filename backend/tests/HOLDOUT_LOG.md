# Hold-out evaluation log

Every `python -m tests.eval --final-holdout` run appends a timestamped line BEFORE it evaluates anything (so even a crashed run is on record) and an aggregate-only result line after. No file names, per-sample verdicts or content are ever written here. The hold-out set exists to be evaluated once, after tuning is finished.

PRE-REGISTRATION (written 2026-10-03, before any hold-out evaluation): the final hold-out run reports BOTH modes -- STRICT (nothing trusted) and CONFIGURED (the corpus collector's gateway headers trusted) -- each with flagged and inconclusive counts. It is never reported in only the more flattering mode. Corpus failure-header frequency is not representative of mail that passed a gateway, so CONFIGURED shows what trusting a gateway's results adds, not an estimate of real-world recall.


## PRE-REGISTRATION OF THE FINAL HOLD-OUT RUN (written 2026-10-03, BEFORE the hold-out was evaluated)

**Code under test:** commit `0f20c4be5a80872262b3be46c96caea8d8b7499f` ("Verdict rename (benign / inconclusive), Wilson intervals,
README and design-doc final state"), working tree clean. The run will be made at the commit that adds this section; that commit
changes only this file, which will be verified with `git diff 0f20c4b HEAD --stat` before the run and printed in the report.

**Command, run exactly once:** `python -m tests.eval --final-holdout` (no `--ablate-seeds`, enrichment = the offline clean stub,
no `EVAL_*` overrides, so CONFIGURED trusts every header naming a hop and STRICT trusts nothing). The set is the 75 hold-out
samples of the seed-20261003 split recorded in `CORPUS_MANIFEST.md`. If it crashes, the crash is reported and the owner is asked;
it is not re-run.

**Local configuration present at run time (counts only):** an untracked brand file with one entry beyond the generic and seed
brands, no known-sender list (the eval's CONFIGURED mode lists only the reserved example domains), no gateway-banner or
subject-tag patterns, no extra shared platforms. The tuning numbers below were produced in the same environment.

**What is reported:** both trust modes, never one. For each: flagged (malicious / suspicious), inconclusive (signals present / no
signals), and missed (a confident "no indicators found" on a phishing sample), each as k/n with a Wilson 95% interval, plus
aggregate structural-signal counts by signal id and the number of samples carrying two or more families. Aggregates only: no file
names, subjects, addresses, URLs or per-sample verdicts.

**Tuning results the prediction is derived from** (75 samples, same code, Wilson 95% intervals):

| Mode | flagged | inconclusive | missed |
|---|---|---|---|
| STRICT | 6/75 = 8.0% [3.7-16.4%] | 69/75 = 92.0% [83.6-96.3%] | 0/75 = 0.0% [0.0-4.9%] |
| CONFIGURED | 22/75 = 29.3% [20.2-40.4%] | 53/75 = 70.7% [59.6-79.8%] | 0/75 = 0.0% [0.0-4.9%] |

**Predicted ranges for the hold-out (n=75), taken from those intervals, not from a target:**

| Mode | flagged | inconclusive | missed |
|---|---|---|---|
| STRICT | 4-16% (3-12 of 75) | 84-96% (63-72 of 75) | 0 (at most 2) |
| CONFIGURED | 20-40% (15-30 of 75) | 60-80% (45-60 of 75) | 0 (at most 2) |

These are coarse. The hold-out count has its own sampling noise on top of the tuning interval, so a result a little outside a range
is not evidence of anything by itself, and a result inside one is not evidence of real-world performance. The public corpus
carries the collector's authentication failures far more often than mail that reached a protected inbox, so CONFIGURED flags are
mostly gateway failures and say little about real mail. Real-world precision is not measured by this run at all (there is no
benign mail in the hold-out).

**Rules:**
1. The results are published as they come, in both modes, in this file and in the report to the owner, whether or not they fall in the
   predicted ranges.
2. Nothing in the detectors, weights, rules, thresholds or fixtures is changed in response to the hold-out result. If anything is
   changed after the hold-out has been viewed, every later hold-out run is labelled "tuned after viewing hold-out" and its numbers are
   not comparable to this one.
3. The run is made once. A second run, for any reason, is logged as such and does not replace the first.
- 2026-10-03 10:45:52 UTC | HEAD 40a4fc0 | FINAL HOLD-OUT run started | n=75 | enrichment=clean ablate_seeds=False modes=strict,configured
- 2026-10-03 10:45:56 UTC | result | mode=strict | n=75 | flagged=6 inconclusive=69 missed=0 | inconclusive=69, suspicious=6
- 2026-10-03 10:45:58 UTC | result | mode=configured | n=75 | flagged=20 inconclusive=55 missed=0 | inconclusive=55, suspicious=20

### Published result (2026-10-03), as run, both modes, once

Run at commit `40a4fc0` (differs from the code commit `0f20c4b` only in this file), exit 0, no crash, no sample errors.

| Mode | flagged | inconclusive | missed | structural signals (samples) |
|---|---|---|---|---|
| STRICT | 6/75 = 8.0% [3.7-16.4%] (malicious 0, suspicious 6) | 69/75 = 92.0% [83.6-96.3%] (signals present 57, no signals 12) | 0/75 = 0.0% [0.0-4.9%] | S2 8, L2 1, L3 11, C1 9, C2 23, C3 1; >= 2 families: 6 |
| CONFIGURED | 20/75 = 26.7% [18.0-37.6%] (malicious 0, suspicious 20) | 55/75 = 73.3% [62.4-82.0%] (signals present 41, no signals 14) | 0/75 = 0.0% [0.0-4.9%] | S2 8, L2 1, L3 11, C1 9, C2 22, C3 1; >= 2 families: 6 |

Against the pre-registered ranges: STRICT flagged 6 (range 3-12), inconclusive 69 (63-72), missed 0; CONFIGURED flagged 20 (15-30),
inconclusive 55 (45-60), missed 0. **Every figure fell inside its predicted range.** That is a statement about this corpus's
phishing recall at these settings, not about real-world precision, which this run cannot measure. No code, weight, rule or fixture
was changed after viewing this result; any later change makes later hold-out runs "tuned after viewing hold-out".
