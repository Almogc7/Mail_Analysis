from fastapi import FastAPI

app = FastAPI(title="Mail Analysis")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
