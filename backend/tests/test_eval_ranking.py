from tests.eval import _reason_split, Row, auc, frac_above_median


def test_auc_is_the_probability_a_positive_outranks_a_negative_ties_half():
    assert auc([3, 4], [1, 2]) == 1.0
    assert auc([1, 2], [3, 4]) == 0.0
    assert auc([1], [1]) == 0.5
    assert auc([2, 0], [1]) == 0.5
    assert auc([], [1]) is None and auc([1], []) is None


def test_fraction_above_the_median_uses_strictly_greater():
    assert frac_above_median([5, 5, 1], [1, 2, 3]) == 2 / 3  # median 2
    assert frac_above_median([2], [1, 3]) == 0.0  # median 2, tie is not above
    assert frac_above_median([], [1]) is None


def test_reason_split_counts_only_inconclusive_rows():
    rows = [Row("m", "s", "a", verdict="inconclusive", reason="signals_present"),
            Row("m", "s", "b", verdict="inconclusive", reason="no_signals_insufficient_evidence"),
            Row("m", "s", "c", verdict="inconclusive", reason="no_signals_insufficient_evidence"),
            Row("m", "s", "d", verdict="suspicious")]
    assert _reason_split(rows) == "[inconclusive: signals present 1 / no signals 2]"
    assert _reason_split([rows[3]]) == ""
