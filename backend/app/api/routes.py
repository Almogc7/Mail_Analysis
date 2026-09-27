import threading
import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel

from app.api.pipeline import run_pipeline
from app.config import MAX_UPLOAD_SIZE_BYTES
from app.contracts.analysis import AnalysisResult

router = APIRouter()

_ALLOWED_EXTENSIONS = (".eml", ".msg")


class AnalysisJob(BaseModel):
    job_id: str
    status: Literal["pending", "running", "done", "error"]
    current_step: str | None = None
    result: AnalysisResult | None = None
    error: str | None = None


# In-memory job store -- fine for a single-user, home-network tool. Jobs don't survive a
# restart; no eviction/expiry in v1 (TODO if this ever needs to run unattended for long).
_jobs: dict[str, AnalysisJob] = {}
_jobs_lock = threading.Lock()


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

    job_id = uuid.uuid4().hex
    _jobs[job_id] = AnalysisJob(job_id=job_id, status="pending")

    thread = threading.Thread(target=_execute_job, args=(job_id, raw_bytes, filename), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "pending"}


@router.get("/analyze/{job_id}", response_model=AnalysisJob)
def get_analysis(job_id: str) -> AnalysisJob:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    return job
