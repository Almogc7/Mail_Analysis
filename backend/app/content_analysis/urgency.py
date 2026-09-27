URGENCY_PHRASES: list[str] = [
    "verify your account",
    "urgent action required",
    "your account will be suspended",
    "your account has been suspended",
    "account has been limited",
    "your account has been compromised",
    "unusual activity detected",
    "confirm your identity",
    "wire transfer",
    "immediate action required",
    "final notice",
    "failure to respond",
    "click here immediately",
    "your account will be closed",
    "suspicious activity on your account",
    "action required within 24 hours",
    "your payment could not be processed",
    "update your billing information",
    "your access will be restricted",
]


def detect_urgency(text: str) -> list[str]:
    """Case-insensitive substring search for fixed urgency/pressure phrases. Returns the
    matched phrases (used both as evidence for its own finding and as the reusable
    "personalized/urgent claim" signal for the generic-greeting-mismatch heuristic)."""
    lowered = text.lower()
    return [phrase for phrase in URGENCY_PHRASES if phrase in lowered]
