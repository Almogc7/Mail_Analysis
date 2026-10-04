# Quick start for a Windows analyst machine

Mail Analysis reads a reported mail (`.eml` or `.msg`), collects every indicator in it (domains, IPs, addresses, file hashes), checks
what it can automatically, and gives you copy-ready lists and one-click lookup links. **It is an analyst aid, not a filter: a verdict
is a sorting hint, never a reason to close, release or delete a mail.** It never opens links or attachments.

Two ways to run it. Pick one.

| | Python install | Docker |
|---|---|---|
| Needs | Python 3.10+ (Node.js 20+ to build the web UI) | Docker Desktop |
| Start | `setup.ps1` once, then `run.ps1` | `docker compose up --build` |
| Good for | analysts who already have Python | a clean, isolated, same-everywhere install |

Both listen on **this machine only** (`http://localhost:8000`). The app has **no login**; do not expose it on a network.

## Before you start: the IOC_Enricher dependency

The provider clients and the risk scorer live in a second repository, `IOC_Enricher`. The setup script fetches it for you (next to this
folder). **It must be a version that contains `MalwareBazaarClient`.** If setup stops with "IOC_Enricher ... is too old", ask the
maintainer for the right ref and put it in `deploy\IOC_ENRICHER_REF` (or update the folder `..\IOC_Enricher`).

## Option 1: Python

```powershell
# once, in the Mail_Analysis folder
powershell -ExecutionPolicy Bypass -File .\setup.ps1

# every time
powershell -ExecutionPolicy Bypass -File .\run.ps1        # opens http://localhost:8000
```

`setup.ps1` checks Python, creates `backend\.venv`, installs the dependencies, makes sure `IOC_Enricher` is next to this folder, creates
`backend\.env` from an example (no keys filled in), builds the web UI if Node.js is installed, and runs the test suite. Without Node.js it
still works but only the API is served (`http://localhost:8000/docs`). Stop with Ctrl+C.

## Option 2: Docker

```powershell
copy-item -Recurse deploy\team-config.example team-config      # then edit it, see "Configuration"
docker compose up --build                                       # open http://localhost:8000
```

Nothing organisation-specific is inside the image: the keys, trusted receivers, brands and known senders are mounted from `team-config\`
(git-ignored). The feedback log lives on a Docker volume and survives restarts. Build against a specific IOC_Enricher version with
`$env:IOC_ENRICHER_REF="<commit>"; docker compose up --build`. *Status: this path was written and reviewed but not yet run end to end by
the maintainer; the Python path was.*

## Configuration (all optional, all local)

| What | Where (Python / Docker) | Without it |
|---|---|---|
| Your own API keys (VirusTotal, urlscan.io, ThreatFox, MalwareBazaar) | `backend\.env` / `team-config\.env` | that source shows "disabled" and its indicators are "check by hand" |
| Trusted receivers: your mail gateway, so its pass/fail results count | `TRUSTED_RECEIVER_PATTERNS` in the same file | authentication shows "not evaluated" |
| Known senders: domains you positively recognise | `backend\known_senders.local.json` / `team-config\known_senders.local.json` | nothing can be "No indicators found" |
| Your organisation's brands and aliases | `backend\brands.local.json` / `team-config\brands.local.json` | only the generic brand list |

* **Use your own VirusTotal key.** A free key allows 4 lookups a minute and 500 a day: too little to share between analysts.
* **Trusted receivers need no access to your organisation.** Take a mail that came through your gateway (a reported one is fine) and run
  `python scripts\suggest_trusted_receivers.py mail.eml`. It prints the gateway host that wrote the authentication results and a
  ready-made, already-escaped line for the `.env` file. Trust **only your own gateway**, and only if it overwrites authentication headers
  that arrive from outside.
* **In JSON values every backslash is written twice** (`\\.`), or the app will not start.
* Copy the examples from `deploy\team-config.example\`. Keep real values out of the repository.

## Using it

1. Open `http://localhost:8000`, drop the `.eml` or `.msg` in.
2. Read the verdict as a sorting hint: **Inconclusive with signals present** is the normal result and means "look at this one".
3. Work through **Indicators to check**: anything marked "check by hand" was not judged (shared platforms such as Power BI or SharePoint,
   unknown lookups, files no source has seen). Use the lookup links, or open the link in your sandbox. The links only go anywhere when you
   click them, and they carry a host, IP or hash, never the full URL.
4. Copy the list (raw or defanged) or download the CSV for your ticket.
5. Use **agree / disagree** at the bottom. The local feedback log is what lets the team see where the tool is wrong.

## Keeping a team on the same setup

* Share the **non-secret** configuration (known senders, brands, shared platforms, the trusted-receiver line) through a private repository or
  a shared folder; never the API keys.
* Update with `git pull` and run `setup.ps1` again (it keeps your `.env`). The tests run at the end of setup: do not use an install whose
  tests fail.
* Once a month, export the feedback log (`python -m app.feedback export` in `backend`) and review the "disagree" cases together.
* A shared web instance (with a login or an IP allowlist) is a later step. Mail contains customer and employee data, so check with the
  organisation before hosting it anywhere outside it.

## If something goes wrong

| Message | Meaning |
|---|---|
| `Python 3.10 or newer was not found` | install Python from python.org and tick "Add python.exe to PATH" |
| `IOC_Enricher ... is too old` | see "Before you start" |
| `port 8000 is already in use` | it is already running, or use `run.ps1 -Port 9000` |
| UI missing, only `/docs` works | Node.js was not installed; install Node 20+ and run `setup.ps1` again |
| `TRUSTED_RECEIVER_PATTERNS must be a JSON array` | a single backslash in the value; write each backslash twice |
| a source shows `disabled` | no API key for it in `.env`; the indicator is "check by hand", not clean |
| VirusTotal "never seen by this source" for a file | not an error: VirusTotal has no record of that hash; inspect the file in your sandbox |
