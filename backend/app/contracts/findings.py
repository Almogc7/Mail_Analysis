from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    module: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = {}
    weight: float = 0.0
    # A stable, content-free identifier of the KIND of finding (the registry is app/finding_codes.py). The title can contain an indicator; the code never does.
    # Optional and additive: an older result without it still parses.
    code: str | None = Field(default=None, pattern="^[A-Z][A-Z0-9_]{3,63}$")


class ModuleResult(BaseModel):
    module: str
    status: Literal["ok", "error", "skipped"]
    findings: list[Finding] = []
    raw_data: dict[str, Any] | None = None
