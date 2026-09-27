import time
from collections import deque


class VTRateLimiter:
    """Keeps calls to VirusTotal's free tier under `max_calls` per `period_seconds`.

    Tracks a rolling window of call timestamps and sleeps just long enough before the
    next call so the window never exceeds the limit. Scoped to VirusTotal only --
    other providers' looser free-tier limits are left to IOC_Enricher's own built-in
    429 retry/backoff.
    """

    def __init__(self, max_calls: int = 4, period_seconds: float = 60.0, sleep_fn=time.sleep, time_fn=time.monotonic):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._sleep = sleep_fn
        self._now = time_fn
        self._call_times: deque[float] = deque()

    def wait_time_seconds(self) -> float:
        """How long to sleep right now before it would be safe to make another call."""
        now = self._now()
        while self._call_times and now - self._call_times[0] >= self.period_seconds:
            self._call_times.popleft()
        if len(self._call_times) < self.max_calls:
            return 0.0
        return self.period_seconds - (now - self._call_times[0])

    def wait_if_needed(self) -> None:
        wait = self.wait_time_seconds()
        if wait > 0:
            self._sleep(wait)
        self._call_times.append(self._now())
