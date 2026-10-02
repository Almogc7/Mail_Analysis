# Fixture manifest

Every fixture used by `python -m tests.eval`, with its type, source and hashes. Update this
file in the same commit as any fixture change. `python scripts/check_fixtures.py` (run by the
pre-commit hook) must pass before committing.

## Eval fixtures

| Fixture | Type | Source / provenance | SHA256 of fixture | SHA256 of original |
|---|---|---|---|---|
| `malicious/kvish6_invoice_phish.eml` | malicious | Real user-reported phishing email received 2026-09-26 (Hebrew; impersonates an Israeli toll-road operator; sent from a Russian shared-hosting box). Sanitized. | `3cb6a2ff2e35ae25e0e22763da714b4e7191d91d9301d824e0b64a274a4a573d` | `f03d04544d6e2b9793f7dd78ee3a57f9444ab851ef514d7f54d87c891c9dd160` |
| `benign/synthetic/01_newsletter_esp_click_tracking.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `4fba3ee0b295ef548c28429e076fbe23137a3dde1fde4347975ce35f2e9fc6a7` | n/a (hand-written) |
| `benign/synthetic/02_safelinks_wrapped_internal.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `daeba851b26903d659a59c4ee869b5fe8118a18dc4db32cb01936b4ba063613b` | n/a (hand-written) |
| `benign/synthetic/03_transactional_sendgrid_receipt.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `cb84b97265eb4b07efe2f700d8bdaa112d372c8c7213ff0436a64bf3d80c9f77` | n/a (hand-written) |
| `benign/synthetic/04_transactional_mandrill_invoice.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `3a9e54f44412a2acb33fa2a4641d4174137e64babed48c4419cac4ea8f573069` | n/a (hand-written) |
| `benign/synthetic/05_spf_only_small_business.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `0d651b57379d16fa7fe4fce3166f038dcffcf480dff5667324d16f3b50b2d7c4` | n/a (hand-written) |
| `benign/synthetic/06_hebrew_newsletter_esp.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `6ed1a34dd6a72555eff9122d318bc4ebd08e55c0e80b4f4879307f883250630e` | n/a (hand-written) |
| `benign/synthetic/07_account_verification_legit.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `02d984ef3b34a970270946460802956e8970aa492884c3fd18d76702775f2c32` | n/a (hand-written) |
| `benign/synthetic/08_shared_hosting_local_submission.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `305f6a0bb4671379155a798443ab8244a04acfd9e9bce973df7d2c57292d04ff` | n/a (hand-written) |
| `benign/synthetic/09_internal_no_auth_headers.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `81f4714d14d30eb7a88f2b77314687239ddf95404e47fe4ac7faeaf564e9f235` | n/a (hand-written) |
| `benign/synthetic/10_legit_brand_domain_esign.eml` | benign (synthetic) | Hand-written for this repo. Not real mail. | `94eabcec39513a77527611deacfccf15a18313873bc04b70a4a857c24ab374e5` | n/a (hand-written) |

### Sanitization of `kvish6_invoice_phish.eml`

Done with a local-only script (it contains the original internal strings, so it is not in the
repo). Replaced: recipient address/name, internal and gateway hostnames, tenant-specific
cloud-gateway hostnames, all RFC1918 and gateway IPs (-> `192.0.2.x` / `198.51.100.x`),
per-message GUIDs/queue ids, and the *values* of per-recipient tracking tokens in URL query
strings (same length; host, path and parameter names kept). **Kept intact**: sender domain,
sender IP, hop structure and order, all other headers, link hosts/paths, HTML structure.
Verified equivalent to the original on: hop count, URL (source, host, path) list, From,
subject, HTML length, header-name list, and the auth_check and content_analysis findings.

### Reading eval results

* `benign/synthetic/*` are regression guards against over-flagging. They are **not** an
  accuracy claim and must not be reported as precision.
* `benign/_from_user/` is the slot for sanitized *real* benign mail (currently empty).
* There is exactly one malicious fixture until the local corpus exists, so recall is 0/1 or
  1/1 -- read the per-fixture table, not the percentages.

## Local corpus (not committed)

`backend/tests/fixtures/_local_corpus/` is gitignored. Planned layout:
`tuning/*.eml` and `holdout/*.eml`, chosen from a local clone of phishing_pot by a **seeded**
random pick and split 50/50 with the same seed. Raw files never enter the repo; only this
manifest does. Attachments are parsed and hashed, never opened. `holdout/` is never
evaluated unless `EVAL_UNBLIND_HOLDOUT=1` (reserved for after the tuning work is finished).

| Item | Value |
|---|---|
| Source | phishing_pot (local clone, path supplied by the repo owner) |
| Selection seed | _not selected yet_ |
| Tuning / hold-out sizes | _not selected yet_ |

## Pre-existing unit-test inputs

`tests/fixtures/samples/*` are small hand-written inputs for the unit tests, not eval
fixtures. `hebrew_invoice_phish.eml` there is a heavily reduced reconstruction of the same
incident as the Kvish 6 fixture.
