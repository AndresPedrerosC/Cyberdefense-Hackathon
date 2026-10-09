# Demo target source + lockfile for repo/SCA scans (demo/ is gitignored locally).
FROM node:20-slim AS demo
ARG JUICE_SHOP_REF=v15.0.0
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${JUICE_SHOP_REF}" https://github.com/juice-shop/juice-shop.git /juice-shop \
    && cd /juice-shop \
    && npm install --package-lock-only --ignore-scripts --no-audit --no-fund

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# Install runtime deps straight from pyproject (no build-system / package layout to install).
COPY pyproject.toml ./
RUN python -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); \
print('\n'.join(x for x in d['project']['dependencies'] if not x.startswith(('pytest','ruff'))))" \
    > requirements.txt \
    && pip install -r requirements.txt

COPY --from=demo /juice-shop demo/juice-shop

COPY app/ app/
COPY web/ web/
COPY rules/ rules/
COPY config/ config/
COPY scripts/ scripts/

RUN useradd --uid 10001 --no-create-home appuser \
    && mkdir -p data/cache \
    && chown -R appuser /srv/data /srv/config
USER appuser

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/api/health', timeout=4)" || exit 1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
