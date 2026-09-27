from typing import Literal

from pydantic import BaseModel


class LLMOpinion(BaseModel):
    narrative: str
    flags: list[str] = []
    model: str
    status: Literal["ok", "unavailable", "error"]
    error: str | None = None
