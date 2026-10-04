# syntax=docker/dockerfile:1
# Mail Analysis in one container: the API and the built web UI on port 8000.
#   docker compose up --build        (see docs/QUICKSTART_WINDOWS.md)
# Nothing secret or organisation-specific is baked in: API keys, trusted receivers, brands and known senders are mounted from
# ./team-config at run time (docker-compose.yml). The malware corpus and every local file are excluded by .dockerignore.

# ---- 1. build the web UI -------------------------------------------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- 2. fetch the sibling IOC_Enricher repo (the provider clients and the risk scorer) at a chosen ref ------------------
FROM python:3.12-slim AS ioc
ARG IOC_ENRICHER_REPO=https://github.com/Almogc7/ioc-enrichment-tool.git
ARG IOC_ENRICHER_REF=main
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone "$IOC_ENRICHER_REPO" /ioc && git -C /ioc checkout "$IOC_ENRICHER_REF" && rm -rf /ioc/.git

# ---- 3. runtime ---------------------------------------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    IOC_ENRICHER_PATH=/opt/IOC_Enricher \
    FRONTEND_DIST=/app/frontend/dist \
    LOCAL_BRANDS_FILE=/config/brands.local.json \
    KNOWN_SENDERS_FILE=/config/known_senders.local.json \
    FEEDBACK_DB=/data/feedback.sqlite
RUN useradd --create-home --uid 10001 analyst && mkdir -p /data /config /app/backend && chown analyst /data
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=ioc /ioc /opt/IOC_Enricher
COPY backend/app ./app
COPY --from=ui /ui/dist /app/frontend/dist
# python-dotenv finds backend/.env by walking up from app/config.py; point it at the mounted team config. A dangling link is ignored.
RUN ln -s /config/.env /app/backend/.env
# Fail the BUILD, with a readable message, if the chosen IOC_Enricher ref is too old for this app.
RUN python -c "import sys; sys.path.insert(0, '/opt/IOC_Enricher'); from IOC_Enricher import MalwareBazaarClient, RiskScorer, ScoreConfig, ThreatFoxClient, URLScanClient, VirusTotalClient" \
    || (echo "ERROR: the IOC_Enricher ref does not contain the provider clients this app needs (MalwareBazaarClient ...). Use a newer ref: --build-arg IOC_ENRICHER_REF=<commit>" && false)
USER analyst
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
