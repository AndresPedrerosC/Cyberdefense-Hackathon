#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -x ".venv/bin/python" ]; then PY=".venv/bin/python"; else PY="python3"; fi

echo "Setting up demo environment in $ROOT"

JUICE_SHOP_DIR="demo/juice-shop"
JUICE_SHOP_REF="v15.0.0"

if [ ! -d "$JUICE_SHOP_DIR" ]; then
    echo "Cloning Juice Shop $JUICE_SHOP_REF..."
    mkdir -p demo
    git clone --depth 1 --branch "$JUICE_SHOP_REF" https://github.com/juice-shop/juice-shop.git "$JUICE_SHOP_DIR"
fi

COMMIT_SHA=$(git -C "$JUICE_SHOP_DIR" rev-parse HEAD)
echo "Juice Shop at SHA: $COMMIT_SHA"
COMMIT_SHA="$COMMIT_SHA" "$PY" - <<'EOF'
import os
from pathlib import Path
import yaml

path = Path("config/demo.yaml")
cfg = yaml.safe_load(path.read_text()) or {}
if cfg.get("juice_shop_commit") != os.environ["COMMIT_SHA"]:
    cfg["juice_shop_commit"] = os.environ["COMMIT_SHA"]
    path.write_text(yaml.dump(cfg, default_flow_style=False, sort_keys=False))
    print("Updated config/demo.yaml with commit SHA")
EOF

if [ ! -f "$JUICE_SHOP_DIR/package-lock.json" ]; then
    if command -v npm >/dev/null 2>&1; then
        echo "Generating package-lock.json (no install scripts run)..."
        (cd "$JUICE_SHOP_DIR" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund)
    else
        echo "WARN: npm not found; discovery will fall back to direct deps only"
    fi
fi

echo "Starting ClickHouse..."
docker compose up -d clickhouse

echo "Waiting for ClickHouse..."
ready=0
for _ in $(seq 1 30); do
    if curl -sf http://localhost:8123/ping | grep -q "Ok"; then
        ready=1
        echo "ClickHouse is ready"
        break
    fi
    sleep 2
done
if [ "$ready" -ne 1 ]; then
    echo "ERROR: ClickHouse did not become ready in 60s" >&2
    exit 1
fi

echo "Applying schema..."
"$PY" scripts/apply_schema.py

echo "Loading OSV npm corpus (this takes a minute)..."
"$PY" scripts/load_osv_corpus.py

echo "Demo environment ready."
echo "Run: DEMO_MODE=1 $PY -m uvicorn app.main:app --host 0.0.0.0 --port 3003 --reload"
