#!/bin/bash
# Wire the Cloud Run service to ClickHouse Cloud. Reads secrets from .env; never echoes them.
#   .env needs: CLICKHOUSE_ADMIN_PASSWORD (ClickHouse "default" user), CLICKHOUSE_APP_PASSWORD (new, no ';')
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROJECT="${PROJECT:-cyberdefense-hack-65e667}"
REGION="${REGION:-us-central1}"
ACCOUNT="${ACCOUNT:-apiaccsid@gmail.com}"
if [ -x ".venv/bin/python" ]; then PY=".venv/bin/python"; else PY="python3"; fi

set -a; source .env; set +a
: "${CLICKHOUSE_ADMIN_PASSWORD:?set CLICKHOUSE_ADMIN_PASSWORD in .env}"
: "${CLICKHOUSE_APP_PASSWORD:?set CLICKHOUSE_APP_PASSWORD in .env}"

export CLICKHOUSE_HOST="m614888n23.us-central1.gcp.clickhouse.cloud"
export CLICKHOUSE_PORT=8443 CLICKHOUSE_SECURE=true CLICKHOUSE_ADMIN_USER=default
export CLICKHOUSE_USER=cyberdefense_app CLICKHOUSE_PASSWORD="$CLICKHOUSE_APP_PASSWORD"
export CLICKHOUSE_DATABASE=cyberdefense

echo "==> Applying schema"
"$PY" scripts/apply_schema.py

echo "==> Loading OSV npm corpus"
"$PY" scripts/load_osv_corpus.py

echo "==> Storing app password in Secret Manager"
printf '%s' "$CLICKHOUSE_APP_PASSWORD" | gcloud secrets versions add clickhouse-app-password \
    --data-file=- --project "$PROJECT" --account "$ACCOUNT" >/dev/null

echo "==> Pointing Cloud Run at the secret"
gcloud run services update cyberdefense --region "$REGION" --project "$PROJECT" --account "$ACCOUNT" \
    --update-secrets CLICKHOUSE_PASSWORD=clickhouse-app-password:latest >/dev/null

URL=$(gcloud run services describe cyberdefense --region "$REGION" --project "$PROJECT" \
    --account "$ACCOUNT" --format='value(status.url)')
echo "==> Health: $(curl -s "$URL/api/health")"
echo "==> Stats:  $(curl -s "$URL/api/stats" | head -c 300)"
