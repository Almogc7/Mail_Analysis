import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as analyze_router

app = FastAPI(title="Mail Analysis")
app.include_router(analyze_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# One process serves both the API and the built web UI, so an analyst runs a single command (or one container) and opens
# http://localhost:8000. Mounted LAST so every API route above wins; only when the UI has been built (npm run build) or
# FRONTEND_DIST points at a build. Without a build the API still works and the dev setup (Vite on :5173) is unchanged.
FRONTEND_DIST = Path(os.getenv("FRONTEND_DIST") or Path(__file__).resolve().parents[2] / "frontend" / "dist")
if (FRONTEND_DIST / "index.html").is_file():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="ui")
