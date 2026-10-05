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
    # Hebrew -- drafted, not reviewed by a native speaker; correct/extend as needed.
    # Hebrew equivalents of the English categories above (account threat / urgency /
    # financial), not yet validated against real-world Hebrew phishing samples.
    # A phrase taken from the single Kvish sample ("valid for one month only", soft expiry
    # pressure) was REMOVED: one sample's wording is not a lexicon, and it also fired on a
    # legitimate Hebrew newsletter (docs/DESIGN_V2.md, decision D13).
    "אנא אשר",  # "please confirm"
    "החשבון שלך ייחסם",  # "your account will be blocked"
    "נדרשת פעולה מיידית",  # "immediate action required"
    "פעילות חשודה זוהתה",  # "suspicious activity detected"
    "אמת את זהותך",  # "verify your identity"
    "החשבון שלך הוגבל",  # "your account has been limited"
    "פרטי התשלום שלך",  # "your payment details"
]


def detect_urgency(text: str) -> list[str]:
    """Case-insensitive substring search for fixed urgency/pressure phrases. Returns the
    matched phrases (used both as evidence for its own finding and as the reusable
    "personalized/urgent claim" signal for the generic-greeting-mismatch heuristic)."""
    lowered = text.lower()
    return [phrase for phrase in URGENCY_PHRASES if phrase in lowered]
