# History cleanup plan (prepared 2026-10-03; NOT executed on the working copy; nothing pushed)

**Status: rehearsed on a throwaway clone only.** The working copy, its history and the remote are untouched. Executing this on the
real repository, and pushing, each need the owner's separate explicit approval. No matched string appears in this file or in
any report: counts only.

## What is in the pushed history (counts only)

Scan of every commit on all refs (70 commits, 14 pushed to `origin/main`) with the same rules as `scripts/check_fixtures.py`
(denylist from the untracked `.denylist.local`, RFC1918 addresses, non-allowlisted public IPs, non-reserved email addresses, plus the
commit messages and author fields):

| Category | Commits with at least one hit | Hits |
|---|---|---|
| denylist (the tenant gateway hostname and the employer brand entry, among the 14 patterns) | 2 | 5 |
| RFC1918 address literal | 1 (the **root** commit) | 1 |
| public IP, non-reserved email, commit message / author | 0 | 0 |

All three commits are already pushed. The 56 unpushed commits are clean (a separate scan of `origin/main..HEAD` found 0 in every
category), and the tree at HEAD is clean: the rewrite does not change it (identical tree hash before and after).

**Consequence of the root commit leaking: every commit hash changes**, pushed or not, so publishing the rewrite means replacing the
whole of `main` on the remote with a force push.

## Backup (done)

`git bundle create ... --all` to `C:\Users\almog\Desktop\projects\_Mail_Analysis_backups\Mail_Analysis-2026-10-03-all-refs.bundle`,
outside any repository, verified with `git bundle verify`. **The bundle contains the original history, leaks included**: keep it private
and delete it when you no longer need the way back.

## Rehearsal (done, on a fresh clone in a temp directory)

1. `git clone --no-local <working copy> <temp>/clone` (no link to GitHub; the clone's only remote is the local path, and filter-repo removes it).
2. Rules: `python scripts/history_cleanup_rules.py <temp>/rules.txt` builds `regex:(?i)<pattern>==>REDACTED-<n>` for each denylist pattern
   and one literal-to-`192.0.2.x` rule per RFC1918 address found in the guard-scoped files of the history (the guard's own scope; an
   unscoped first attempt also matched the CIDR constants in `scripts/check_fixtures.py`, which is why the rule builder is scoped).
   The rules file lives outside the repository because it contains the strings to redact. 15 rules: 14 denylist, 1 address.
3. `git-filter-repo --replace-text rules.txt --replace-message rules.txt` (git-filter-repo installed in a throwaway venv, not a project
   dependency).
4. Full-history scan of the rewritten clone with the same rules and the original `.denylist.local`.
5. Guards and the full backend test suite on the rewritten clone (untracked local files copied in only as needed for the guards).

**Rehearsal results (counts only):**

| Check | Result |
|---|---|
| Commits rewritten | 70 of 70 (all hashes change; root commit is affected) |
| Scan of rewritten history: denylist / RFC1918 / public IP / email / message-author | 0 / 0 / 0 / 0 / 0 commits with hits |
| Tree at HEAD, original vs rewritten | identical |
| `check_fixtures.py`, `check_control_chars.py` on the clone | OK, OK |
| Backend tests on the clone | 979 passed, 2 expected failures (same as the working copy) |
| Remotes on the rewritten clone | 0 |

## Execution, when (and only when) approved

1. Re-verify the bundle; re-run the rehearsal against the then-current HEAD and confirm the counts above (the rules builder is
   deterministic: it reproduced the rehearsal's rules byte for byte).
2. Make the rewritten clone the new working repository: add the GitHub remote to it, **leave the old working copy intact until the push is
   verified**, copy the untracked local files (`.env`, `brands.local.json`, `.denylist.local`, the corpora) into the new one.
3. `git push --force-with-lease origin main` from the rewritten clone, naming the expected remote value. No other refs, no tags.
4. Re-clone from GitHub into a scratch directory; scan and test it; compare the tree to the pre-rewrite HEAD.
5. Retire the old working copy; delete the bundle when you no longer need the way back.

## Costs and caveats you should weigh before approving

* **The hold-out pre-registration is anchored by commit hashes** (`HOLDOUT_LOG.md` names `0f20c4b...` as the code under test, and 5
  references to commit hashes sit in that file and 2 in `EVAL_HISTORY.md`). After a rewrite those hashes no longer exist in the history.
  filter-repo writes an old-to-new map (`.git/filter-repo/commit-map`); the plan is to commit a short mapping note for the two
  pre-registration commits. The order of commits is preserved, so "pre-registered before the run" still holds, but the cryptographic
  anchor changes. The original, with its original hashes, is in the bundle.
* **GitHub keeps old objects reachable by hash** (cached views, forks, anyone who cloned) until it garbage-collects them; a force push
  does not guarantee removal. Treat what was pushed as disclosed. The leaked items are an internal gateway hostname and an employer
  name, not credentials, so no rotation is implied; GitHub support can purge cached objects on request if that matters to you.
* **Anyone with a clone** has to re-clone. This is a personal portfolio repository, so that is probably only you.
* **Not covered:** content that is not in the denylist and not an RFC1918 address. The scan uses the same rules as the guard; it cannot
  find a leak the rules do not describe. A manual read of the first pushed commits (the 14 on `origin/main`) is the remaining check.
