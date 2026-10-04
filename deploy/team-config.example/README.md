# Team configuration (copy this folder to `team-config/` next to docker-compose.yml)

Everything organisation-specific lives here, never in the repository or in an image. `team-config/` is git-ignored.

| File to create | What it is | Needed? |
|---|---|---|
| `.env` | copy of `env.example`: your own API keys, `TRUSTED_RECEIVER_PATTERNS` | keys optional; without them each lookup source shows "disabled" |
| `known_senders.local.json` | `{"domains": ["supplier.example.com"]}`: senders you positively recognise | optional; without it nothing can be "No indicators found" |
| `brands.local.json` | your organisation's brands and aliases (Hebrew names, transliterations) | optional |

Each analyst should use their own free VirusTotal key (a free key allows 4 lookups a minute and 500 a day, too little to share).
JSON values in `.env` need every backslash written twice. Get a ready-made `TRUSTED_RECEIVER_PATTERNS` line from your own mail with
`python scripts/suggest_trusted_receivers.py mail.eml`.
