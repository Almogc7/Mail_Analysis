from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring
from app.scoring.overrides import apply_overrides
from app.scoring.config import ScoringConfig


def _auth_result(findings=None, header_present=True, status="ok") -> ModuleResult:
    return ModuleResult(
        module="auth_check",
        status=status,
        findings=findings or [],
        raw_data={"auth_headers": {"header_present": header_present}, "identity": {}},
    )


def _enrichment_result(findings=None, enriched_iocs=None, status="ok") -> ModuleResult:
    return ModuleResult(
        module="enrichment",
        status=status,
        findings=findings or [],
        raw_data={ioc: {} for ioc in (enriched_iocs or [])},
    )


def _content_result(findings=None, status="ok", script_coverage=1.0) -> ModuleResult:
    return ModuleResult(
        module="content_analysis",
        status=status,
        findings=findings or [],
        raw_data={"script_coverage": script_coverage},
    )


def test_clean_auth_plus_malicious_enrichment_triggers_floor_override():
    auth = _auth_result()
    enrichment = _enrichment_result(
        findings=[
            Finding(
                module="enrichment",
                severity="critical",
                title="Suspicious URL: http://evil.example.com",
                description="VT malicious detections",
                evidence={},
                weight=85.0,
            )
        ],
        enriched_iocs=["http://evil.example.com"],
    )
    content = _content_result()

    outcome = run_scoring([auth, enrichment, content])

    # 0.40 * 85 = 34, below the 35 suspicious threshold -- verdict only reaches
    # "suspicious" because the enrichment floor override fires, not the raw score.
    assert outcome.breakdown.weighted_score < 35
    assert outcome.verdict == "suspicious"
    assert outcome.confidence == 1.0
    assert any(o.rule == "enrichment_floor" for o in outcome.breakdown.applied_overrides)


def test_spf_fail_alone_triggers_auth_floor_override():
    auth = _auth_result(
        findings=[
            Finding(
                module="auth_check",
                severity="high",
                title="SPF check failed",
                description="SPF authentication result was 'fail'.",
                evidence={},
                weight=25.0,
            )
        ]
    )
    enrichment = _enrichment_result()
    content = _content_result()

    outcome = run_scoring([auth, enrichment, content])

    assert outcome.breakdown.weighted_score < 35
    assert outcome.verdict == "suspicious"
    assert any(o.rule == "auth_check_floor" for o in outcome.breakdown.applied_overrides)


def test_strong_content_only_signals_reach_suspicious_via_floor_override():
    """Given the confirmed category weight (0.25) and subscore cap (100), content_analysis's
    own weighted contribution can never exceed 25 -- structurally below the 35-point
    suspicious threshold, so this verdict is only reachable via the content-only floor
    override (2+ independently-firing high-severity findings), not the weighted score."""
    auth = _auth_result(findings=[])
    enrichment = _enrichment_result(findings=[])
    content = _content_result(
        findings=[
            Finding(module="content_analysis", severity="high", title="Urgency/pressure language detected", description="", evidence={}, weight=25.0),
            Finding(module="content_analysis", severity="high", title="Body content claims to be 'paypal'...", description="", evidence={}, weight=25.0),
        ]
    )

    outcome = run_scoring([auth, enrichment, content])

    assert outcome.breakdown.weighted_score == 12.5  # weighted score alone never crosses 35
    assert outcome.verdict == "suspicious"
    assert any(o.rule == "content_analysis_floor" for o in outcome.breakdown.applied_overrides)


def test_single_content_finding_alone_does_not_trigger_floor():
    """One high-severity content finding on its own is deliberately not enough --
    corroboration requires 2+ independently-firing heuristics agreeing within the category."""
    auth = _auth_result(findings=[])
    enrichment = _enrichment_result(findings=[])
    content = _content_result(
        findings=[
            Finding(module="content_analysis", severity="high", title="Body content claims to be 'paypal'...", description="", evidence={}, weight=25.0),
        ]
    )

    outcome = run_scoring([auth, enrichment, content])

    assert outcome.verdict == "legit"
    assert outcome.breakdown.applied_overrides == []


def test_ceiling_override_caps_content_only_malicious_bucket():
    """Direct unit test of the override logic in isolation. Even with the content-only
    floor override in place, the floor only ever raises the bucket to "suspicious" (never
    higher) -- so in real run_scoring, base_bucket can still never reach "malicious" from
    content_analysis alone (weighted contribution capped at 25). The ceiling therefore
    remains a defensive guard exercisable only via this direct call, not through
    run_scoring -- together, the floor and ceiling pin a strong content-only signal to
    exactly "suspicious": at least that (floor), never more (ceiling)."""
    config = ScoringConfig()
    bucket, applied = apply_overrides(
        base_bucket="malicious",
        module_results={"auth_check": _auth_result(), "enrichment": _enrichment_result(), "content_analysis": _content_result()},
        category_subscores={"auth_check": 0.0, "enrichment": 0.0, "content_analysis": 80.0},
        confidence=1.0,
        weighted_score=70.0,
        config=config,
    )

    assert bucket == "suspicious"
    assert any(o.rule == "content_only_ceiling" for o in applied)


def test_all_modules_clean_verdicts_legit_with_high_confidence():
    outcome = run_scoring([_auth_result(), _enrichment_result(), _content_result()])

    assert outcome.verdict == "legit"
    assert outcome.confidence == 1.0
    assert outcome.breakdown.weighted_score == 0
    assert outcome.breakdown.applied_overrides == []


def test_conflicting_signals_trigger_needs_review():
    # Auth headers missing entirely (coverage 0.4, not 1.0 -- we genuinely can't assess
    # auth), enrichment attempted but every IOC came back incomplete (subscore 0, coverage
    # 0.0 -- "couldn't check" is distinct from "checked, clean"), content has a moderate
    # signal. A pure score-band design would just call this a low-scoring "legit" email;
    # the confidence-based trigger correctly flags it as needing a human instead.
    auth = _auth_result(findings=[], header_present=False)
    enrichment = _enrichment_result(
        findings=[
            Finding(
                module="enrichment",
                severity="info",
                title="Enrichment incomplete for http://unknown.example.com",
                description="virustotal did not return a usable result (status: rate_limited).",
                evidence={"ioc_value": "http://unknown.example.com", "provider": "virustotal"},
                weight=0.0,
            )
        ],
        enriched_iocs=["http://unknown.example.com"],
    )
    content = _content_result(
        findings=[
            Finding(module="content_analysis", severity="high", title="Urgency/pressure language detected", description="", evidence={}, weight=25.0),
            Finding(module="content_analysis", severity="medium", title="Generic greeting combined with personalized account claim", description="", evidence={}, weight=15.0),
        ]
    )

    outcome = run_scoring([auth, enrichment, content])

    assert outcome.breakdown.weighted_score == 10.0
    assert outcome.confidence < 0.6
    assert outcome.verdict == "needs_review"
    assert any(o.rule == "low_confidence_needs_review" for o in outcome.breakdown.applied_overrides)


def test_reduced_content_script_coverage_can_trigger_needs_review():
    # Regression test for a real false negative: a Hebrew phishing email scored "legit"
    # because content_analysis's coverage was unconditionally 1.0 regardless of whether its
    # (English-only, at the time) phrase lists could actually read the content. This proves
    # the fix's other half -- with enrichment ALSO incomplete (a plausible combination for
    # an email whose links a provider couldn't evaluate) and content flagged as
    # low-script-coverage, confidence correctly drops enough for needs_review, even though
    # auth_check itself is clean/fully covered.
    auth = _auth_result(findings=[], header_present=True)
    enrichment = _enrichment_result(
        findings=[
            Finding(
                module="enrichment",
                severity="info",
                title="Enrichment incomplete for http://unknown.example.com",
                description="virustotal did not return a usable result (status: rate_limited).",
                evidence={"ioc_value": "http://unknown.example.com", "provider": "virustotal"},
                weight=0.0,
            )
        ],
        enriched_iocs=["http://unknown.example.com"],
    )
    content = _content_result(
        findings=[
            Finding(module="content_analysis", severity="high", title="Urgency/pressure language detected", description="", evidence={}, weight=25.0),
            Finding(module="content_analysis", severity="medium", title="Generic greeting combined with personalized account claim", description="", evidence={}, weight=15.0),
        ],
        script_coverage=0.5,
    )

    outcome = run_scoring([auth, enrichment, content])

    assert outcome.breakdown.weighted_score == 10.0
    assert outcome.confidence < 0.6
    assert outcome.verdict == "needs_review"
    assert any(o.rule == "low_confidence_needs_review" for o in outcome.breakdown.applied_overrides)


def test_missing_module_treated_as_zero_subscore_and_coverage():
    outcome = run_scoring([_auth_result(), _enrichment_result()])  # content_analysis absent

    content_score = next(c for c in outcome.breakdown.categories if c.category == "content_analysis")
    assert content_score.subscore == 0
    assert content_score.coverage == 0.0
    assert outcome.verdict == "legit"


def test_errored_module_ignores_stray_findings_and_has_zero_coverage():
    content = _content_result(
        findings=[Finding(module="content_analysis", severity="critical", title="should be ignored", description="", evidence={}, weight=999.0)],
        status="error",
    )

    outcome = run_scoring([_auth_result(), _enrichment_result(), content])

    content_score = next(c for c in outcome.breakdown.categories if c.category == "content_analysis")
    assert content_score.subscore == 0
    assert content_score.coverage == 0.0
