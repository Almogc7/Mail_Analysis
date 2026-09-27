from app.enrichment.rate_limit import VTRateLimiter


def _clock():
    """Returns a callable time_fn and a way to advance it, for deterministic tests."""
    state = {"t": 0.0}

    def now():
        return state["t"]

    def advance(seconds):
        state["t"] += seconds

    return now, advance


def test_no_wait_needed_under_the_limit():
    now, _ = _clock()
    limiter = VTRateLimiter(max_calls=4, period_seconds=60, time_fn=now, sleep_fn=lambda s: None)

    for _ in range(4):
        assert limiter.wait_time_seconds() == 0
        limiter.wait_if_needed()


def test_wait_required_after_hitting_the_limit():
    now, advance = _clock()
    limiter = VTRateLimiter(max_calls=4, period_seconds=60, time_fn=now, sleep_fn=lambda s: None)

    for _ in range(4):
        limiter.wait_if_needed()

    advance(10)  # only 10s elapsed since the first call, 50s left in its window
    assert limiter.wait_time_seconds() == 50


def test_window_frees_up_after_period_elapses():
    now, advance = _clock()
    limiter = VTRateLimiter(max_calls=4, period_seconds=60, time_fn=now, sleep_fn=lambda s: None)

    for _ in range(4):
        limiter.wait_if_needed()

    advance(61)
    assert limiter.wait_time_seconds() == 0


def test_wait_if_needed_sleeps_the_computed_duration():
    now, advance = _clock()
    slept = []
    limiter = VTRateLimiter(max_calls=1, period_seconds=60, time_fn=now, sleep_fn=slept.append)

    limiter.wait_if_needed()
    advance(5)
    limiter.wait_if_needed()

    assert slept == [55]
