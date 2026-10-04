import threading
import time
import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app import feedback
from app.api.pipeline import run_pipeline
from app.config import JOB_TTL_SECONDS, MAX_UPLOAD_SIZE_BYTES
from app.contracts.analysis import AnalysisResult

router = APIRouter()

_ALLOWED_EXTENSIONS = (".eml", ".msg")


class AnalysisJob(BaseModel):
    job_id: str
    status: Literal["pending", "running", "done", "error"]
    current_step: str | None = None
    result: AnalysisResult | None = None
    error: str | None = None


# In-memory job store: fine for a single-user, local tool. Jobs do not survive a restart, and FINISHED jobs expire after JOB_TTL_SECONDS
# (default 30 minutes, 0 = never): the live result holds the message body text (D5 in docs/DESIGN_V2.md), which must not sit in memory
# indefinitely. A job that is still running is never expired from under its own thread.
_jobs: dict[str, AnalysisJob] = {}
_job_created: dict[str, float] = {}
_jobs_lock = threading.Lock()
_now = time.monotonic


def _purge_expired() -> None:
    if JOB_TTL_SECONDS <= 0:
        return
    cutoff = _now() - JOB_TTL_SECONDS
    with _jobs_lock:
        for job_id in [j for j, created in _job_created.items() if created < cutoff and _jobs.get(j) is not None and _jobs[j].status in ("done", "error")]:
            _jobs.pop(job_id, None)
            _job_created.pop(job_id, None)


def _set_job(job_id: str, **updates) -> None:
    with _jobs_lock:
        current = _jobs[job_id]
        _jobs[job_id] = current.model_copy(update=updates)


def _execute_job(job_id: str, raw_bytes: bytes, filename: str) -> None:
    _set_job(job_id, status="running")

    def on_step(step: str) -> None:
        _set_job(job_id, current_step=step)

    try:
        result = run_pipeline(raw_bytes, filename, on_step=on_step)
    except Exception as exc:
        # run_pipeline only lets parsing (Module 1) and scoring (Module 5) raise --
        # everything else is individually caught and recorded as a partial ModuleResult.
        _set_job(job_id, status="error", current_step=None, error=f"Analysis failed: {exc}")
        return

    _set_job(job_id, status="done", current_step=None, result=result)


@router.post("/analyze", status_code=202)
async def submit_analysis(file: UploadFile) -> dict[str, str]:
    filename = file.filename or ""
    if not filename.lower().endswith(_ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="File must be a .eml or .msg file")

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(raw_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_SIZE_BYTES} byte limit")

    _purge_expired()
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = AnalysisJob(job_id=job_id, status="pending")
        _job_created[job_id] = _now()

    thread = threading.Thread(target=_execute_job, args=(job_id, raw_bytes, filename), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "pending"}


@router.get("/analyze/{job_id}", response_model=AnalysisJob)
def get_analysis(job_id: str) -> AnalysisJob:
    _purge_expired()
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    return job


class FeedbackIn(BaseModel):
    agree: bool
    note: str | None = Field(default=None, max_length=feedback.NOTE_MAX_CHARS)


@router.post("/analyze/{job_id}/feedback")
def submit_feedback(job_id: str, body: FeedbackIn) -> dict:
    """Analyst agree/disagree on a finished analysis. Stored locally as hashes, verdict and signal
    names only (see app/feedback.py); the note is the one free-text field."""
    _purge_expired()
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    if job.status != "done" or job.result is None:
        raise HTTPException(status_code=409, detail="Analysis is not finished; nothing to give feedback on yet")
    try:
        return feedback.record_feedback(job.result, body.agree, body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/feedback/summary")
def feedback_summary() -> dict:
    return feedback.summary()
