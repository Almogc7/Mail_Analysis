# Hold-out evaluation log

Every `python -m tests.eval --final-holdout` run appends a timestamped line BEFORE it evaluates anything (so even a crashed run is on record) and an aggregate-only result line after. No file names, per-sample verdicts or content are ever written here. The hold-out set exists to be evaluated once, after tuning is finished.

PRE-REGISTRATION (written 2026-10-03, before any hold-out evaluation): the final hold-out run reports BOTH modes -- STRICT (nothing trusted) and CONFIGURED (the corpus collector's gateway headers trusted) -- each with flagged and inconclusive counts. It is never reported in only the more flattering mode. Corpus failure-header frequency is not representative of mail that passed a gateway, so CONFIGURED shows what trusting a gateway's results adds, not an estimate of real-world recall.

