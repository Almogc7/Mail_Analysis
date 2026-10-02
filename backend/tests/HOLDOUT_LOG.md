# Hold-out evaluation log

Every `python -m tests.eval --final-holdout` run appends a timestamped line BEFORE it evaluates anything (so even a crashed run is on record) and an aggregate-only result line after. No file names, per-sample verdicts or content are ever written here. The hold-out set exists to be evaluated once, after tuning is finished.

