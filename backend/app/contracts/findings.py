from typing import Any, Literal

from pydantic import BaseModel

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    module: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = {}
    weight: float = 0.0


class ModuleResult(BaseModel):
    module: str
    status: Literal["ok", "error", "skipped"]
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}
