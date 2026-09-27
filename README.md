# Mail Analysis

Suspicious-email analysis and triage tool for SOC analysts. Parses `.eml`/`.msg` files,
runs them through multiple analysis modules (header/auth checks, URL and attachment-hash
enrichment, content analysis, LLM second opinion), and produces a scored verdict with a
full evidence trail.

Reuses provider integrations (VirusTotal, URLScan, ThreatFox, MalwareBazaar) and scoring
logic from the sibling [IOC_Enricher](../IOC_Enricher) repo via a `sys.path` bridge
(`backend/app/enrichment/ioc_bridge.py`) rather than duplicating that code.

## Status

Milestone 1: `.eml`/`.msg` parser (Module 1) + header/auth-check module (Module 2).
See `backend/app/parser/` and `backend/app/auth_check/`.

## Setup

```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # then fill in IOC_ENRICHER_PATH and provider API keys
pytest
```
