"""Advisory watcher for continuous monitoring."""

import time
from datetime import datetime

from app.schema import Target, StackItem, Advisory, Emit
from app.intel.osv import query_batch, fetch_advisories_batch
from app.config import load_demo_config


def poll_advisories(
    target: Target,
    inventory: list[StackItem],
    known_advisory_ids: set[str],
    emit: Emit,
) -> list[Advisory]:
    """Poll for new advisories affecting the inventory."""
    start = time.perf_counter()

    npm_items = [s for s in inventory if s.ecosystem == "npm" and s.package]
    if not npm_items:
        emit("monitor", "info", "No npm packages to poll", None)
        return []

    # Check holdback list
    config = load_demo_config()
    holdback = set(config.get("demo_holdback_advisories", []))
    released_holdback = set(config.get("released_advisories", []))

    # Build queries
    queries = []
    for item in npm_items:
        q = {"package": {"ecosystem": "npm", "name": item.package}}
        if item.version:
            q["version"] = item.version
        queries.append(q)

    # Query OSV
    advisory_ids = query_batch(queries, emit)

    # Filter out known and held-back (unless released)
    new_ids = []
    for aid in advisory_ids:
        if aid in known_advisory_ids:
            continue
        if aid in holdback and aid not in released_holdback:
            continue
        new_ids.append(aid)

    elapsed_ms = (time.perf_counter() - start) * 1000

    if not new_ids:
        emit("monitor", "info", f"Poll: {len(npm_items)} packages, 0 new advisories ({elapsed_ms:.0f}ms)", None)
        return []

    # Fetch new advisories
    new_advisories = fetch_advisories_batch(new_ids, emit)

    # Filter withdrawn
    new_advisories = [a for a in new_advisories if a.withdrawn is None]

    emit("monitor", "info", f"Poll: {len(npm_items)} packages, {len(new_advisories)} new advisories ({elapsed_ms:.0f}ms)", None)

    return new_advisories


def release_holdback(advisory_id: str, emit: Emit) -> bool:
    """Release a held-back advisory for demo replay."""
    import yaml
    from pathlib import Path

    config_path = Path("config/demo.yaml")
    if not config_path.exists():
        return False

    config = yaml.safe_load(config_path.read_text()) or {}

    holdback = config.get("demo_holdback_advisories", [])
    if advisory_id not in holdback:
        emit("monitor", "warn", f"{advisory_id} not in holdback list", None)
        return False

    released = config.get("released_advisories", [])
    if advisory_id in released:
        emit("monitor", "warn", f"{advisory_id} already released", None)
        return False

    released.append(advisory_id)
    config["released_advisories"] = released

    config_path.write_text(yaml.dump(config, default_flow_style=False))

    emit("monitor", "info", f"Released holdback advisory {advisory_id} for replay", None)
    return True
