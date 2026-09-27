from fastapi import FastAPI

from app.api.routes import router as analyze_router

app = FastAPI(title="Mail Analysis")
app.include_router(analyze_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
