# ─────────────────────────────────────────────────────────────────────────
# NKS WDC Catalog API — minimal FastAPI container
#
# Build:
#   docker build -t nks-wdc-catalog-api services/catalog-api
# Run:
#   docker run -p 8765:8765 -v nks-wdc-catalog-state:/state \
#     -e NKS_WDC_CATALOG_STATE_DIR=/state nks-wdc-catalog-api
# ─────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app

# Install dependencies first so the requirements layer stays cacheable
# across app code edits — only re-runs when requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package + seed catalog data. State is volume-mounted so
# config-sync uploads persist across container restarts.
COPY app ./app

# State dir for config-sync JSON files (override via env when mounting
# an external volume in production).
ENV NKS_WDC_CATALOG_STATE_DIR=/state
RUN mkdir -p /state

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz').read()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765"]
