# syntax=docker/dockerfile:1
# Mail Analysis in one container: the API and the built web UI on port 8000.
#   docker compose up --build        (see docs/QUICKSTART_WINDOWS.md)
# Nothing secret or organisation-specific is baked in: API keys, trusted receivers, brands and known senders are mounted from
# ./team-config at run time (docker-compose.yml). The malware corpus and every local file are excluded by .dockerignore.
# The repository is self-contained: nothing is fetched from any other repository.

# ---- 1. build the web UI -------------------------------------------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- 2. runtime ---------------------------------------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    FRONTEND_DIST=/app/frontend/dist \
    LOCAL_BRANDS_FILE=/config/brands.local.json \
    KNOWN_SENDERS_FILE=/config/known_senders.local.json \
    FEEDBACK_DB=/data/feedback.sqlite
RUN useradd --create-home --uid 10001 analyst && mkdir -p /data /config /app/backend && chown analyst /data
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --from=ui /ui/dist /app/frontend/dist
# python-dotenv finds backend/.env by walking up from app/config.py; point it at the mounted team config. A dangling link is ignored.
RUN ln -s /config/.env /app/backend/.env
# Build-time smoke test: the application and its lookup providers import and construct (no network is touched).
RUN python -c "from app.main import app; from app.enrichment.providers import get_clients; get_clients()"
USER analyst
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
