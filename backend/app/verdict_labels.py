"""The ONE place that turns a v1 verdict value into words for use inside a sentence.

The v1 `verdict` field is frozen: its values (`malicious`, `suspicious`, `inconclusive`, `benign`) are internal literals that clients and the feedback log depend on. They are not wording.
In particular the literal `benign` must never appear in a reason, a finding, an indicator note, a log line, the CLI output or the text sent to the language model: the user-visible name of
that outcome is "No indicators found" (docs/DESIGN_V2.md 2.1, the V1 word ban). Every f-string that interpolates a verdict goes through `verdict_label`.

Only `benign` changes: the other three read the same in a sentence as the literal does, so their text stays as it was. The verdict card has its own labels in the frontend; when verdict v2 renames
the tiers, this table is the single backend place to change.
"""

VERDICT_LABELS: dict[str, str] = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "inconclusive": "inconclusive",
    "benign": "No indicators found",
}


def verdict_label(value: str) -> str:
    """The wording for a v1 verdict value; an unknown value is returned unchanged."""
    return VERDICT_LABELS.get(value, value)
