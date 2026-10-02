Drop SANITIZED real benign mail here (.eml/.msg). These are the only benign fixtures that
count as real data in eval reports. Sanitize first (recipients, internal hosts/IPs, names ->
RFC-reserved placeholders), record the original's SHA256 in ../../MANIFEST.md, and run
`python scripts/check_fixtures.py` before committing.
