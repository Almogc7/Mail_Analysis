# Fixture manifest

Every fixture used by `python -m tests.eval`, with its type, source and hashes. Update this
file in the same commit as any fixture change. `python scripts/check_fixtures.py` (run by the
pre-commit hook) must pass before committing.

## Eval fixtures

| Fixture | Type | Source / provenance | SHA256 of fixture | SHA256 of original |
|---|---|---|---|---|
| `malicious/kvish6_invoice_phish.eml` | malicious (real) | Real user-reported phishing email received 2026-09-26 (Hebrew; impersonates an Israeli toll-road operator; sent from a Russian shared-hosting box). Sanitized. | `3cb6a2ff2e35ae25e0e22763da714b4e7191d91d9301d824e0b64a274a4a573d` | `f03d04544d6e2b9793f7dd78ee3a57f9444ab851ef514d7f54d87c891c9dd160` |
| `malicious/synthetic/s01_exact_brand_nonbrand_domain.eml` | malicious (synthetic) | Hand-written display-name-spoof positive (matcher test); display-name signal only. Not real phish. | `9f47e9559dd24152e7300693998838b567067ab017e78a74e817fe6667e1b55a` | n/a (hand-written) |
| `malicious/synthetic/s02_homoglyph_cyrillic.eml` | malicious (synthetic) | Hand-written display-name-spoof positive (matcher test); display-name signal only. Not real phish. | `844eb2d829dc990ab3e2b431cc782c14b2ef42cad3be2a7d76918bea51ddff37` | n/a (hand-written) |
| `malicious/synthetic/s03_freemail_sender.eml` | malicious (synthetic) | Hand-written display-name-spoof positive (matcher test); display-name signal only. Not real phish. | `96d339d4bf877a18829da8732d0292d26d7546d8d510cef694bc1c0b72a72307` | n/a (hand-written) |
| `malicious/synthetic/s04_leet_variant.eml` | malicious (synthetic) | Hand-written display-name-spoof positive (matcher test); display-name signal only. Not real phish. | `33398ccedc10768f3e7c3a7238a205723e7aae4332ed3437d69dea82b548bb4a` | n/a (hand-written) |
| `malicious/synthetic/s05_multiword_brand.eml` | malicious (synthetic) | Hand-written display-name-spoof positive (matcher test); display-name signal only. Not real phish. | `f2ea2104b0a059f39e1794b0f4b99e34638b4623460410695833b045dcb1298d` | n/a (hand-written) |
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
| `benign/synthetic/11_nearmiss_pineapple_weekly.eml` | benign (synthetic, near-miss name) | Hand-written for this repo. Not real mail. | `30194b7e4b0cce7a6f96f5549e59944a9e4598844faa06d013025a0a2d1afbeb` | n/a (hand-written) |
| `benign/synthetic/12_nearmiss_maple_leaf_dental.eml` | benign (synthetic, near-miss name) | Hand-written for this repo. Not real mail. | `e463bfe975c46f6f01dbe3f48686a565a5490cdac6a9d3f116ff27dee2259900` | n/a (hand-written) |
| `benign/synthetic/13_nearmiss_fibonacci_books.eml` | benign (synthetic, near-miss name) | Hand-written for this repo. Not real mail. | `0516852bda4d705f35922a7148f157e51cbd77148c0a53e409a21a7e2a63eed8` | n/a (hand-written) |
| `benign/synthetic/14_nearmiss_grapple_fitness.eml` | benign (synthetic, near-miss name) | Hand-written for this repo. Not real mail. | `de36f630ecf2de9fc04a76552136869f50b78d9d9c746babbf824d3a990d98a2` | n/a (hand-written) |
| `benign/synthetic/15_nearmiss_discount_tires.eml` | benign (synthetic, near-miss name) | Hand-written for this repo. Not real mail. | `6249f6b340bcc8bc00c10cd8207d33874335c19696d9b7152a594b44e4737f10` | n/a (hand-written) |

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
* There is exactly ONE real malicious fixture (`malicious/kvish6_*`) until the local corpus exists.
  `malicious/synthetic/*` are hand-written spoof positives for the matcher: they inflate recall
  and are not an accuracy claim. Read the per-fixture table, not the percentages.

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
