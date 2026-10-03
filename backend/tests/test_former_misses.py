from tests.former_misses import _signal_name, profile


def _row(cov=(1.0, 1.0, 1.0), states=("looked up, nothing found",), signals=(), new="inconclusive"):
    return {"coverage": dict(zip(("auth_check", "enrichment", "content_analysis"), cov)), "enrichment_states": list(states),
            "auth_basis": ["dkim pass via authentication-results / authserv-less header (opt-in placeholder)"],
            "signals": list(signals), "new_verdict": new, "new_overrides": ["no_positive_evidence_for_benign"]}


def test_signal_names_drop_the_variable_part_of_a_title():
    assert _signal_name("Suspicious host: bad.example") == "Suspicious host"
    assert _signal_name("Possible display-name spoofing of 'x'") == "Possible display-name spoofing"
    assert _signal_name("Enrichment incomplete for http://a.example") == "Enrichment incomplete"
    assert _signal_name("Plain title") == "Plain title"


def test_profile_is_aggregate_only_and_counts_samples():
    text = "\n".join(profile([_row(), _row(cov=(1.0, 1.0, 0.25), signals=["Urgency language"]), _row(states=())]))
    assert "former misses (CONFIGURED, old rule called them benign): 3" in text
    assert "1.00 / 1.00 / 0.25  ->  1" in text and "1.00 / 1.00 / 1.00  ->  2" in text
    assert "Urgency language 1" in text and "samples with no non-info finding at all: 2" in text
    assert "samples with NO indicator at all: 1" in text
    assert "inconclusive 3" in text and "no_positive_evidence_for_benign 3" in text


def test_an_empty_profile_is_reported_plainly():
    assert profile([]) == ["former misses (CONFIGURED, old rule called them benign): 0"]
