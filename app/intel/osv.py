"""OSV.dev API client."""

import json
import time
from pathlib import Path
from typing import Any

import httpx

from app.schema import Advisory, AffectedRange, Emit
from app.config import CACHE_ONLY
from app.intel.severity import compute_severity

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
CACHE_DIR = Path("data/cache/osv")
BATCH_SIZE = 1000
CONCURRENCY = 8


def query_batch(packages: list[dict], emit: Emit) -> list[str]:
    """Query OSV for vulnerability IDs affecting packages.

    Args:
        packages: List of {"package": {"ecosystem": "npm", "name": "..."}, "version": "..."}

    Returns:
        List of advisory IDs
    """
    if CACHE_ONLY:
        emit("intel", "info", "CACHE_ONLY mode, skipping OSV query", None)
        return []

    if not packages:
        return []

    advisory_ids = set()

    # Batch queries
    for i in range(0, len(packages), BATCH_SIZE):
        batch = packages[i:i + BATCH_SIZE]
        queries = {"queries": batch}

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(OSV_QUERY_URL, json=queries)
                response.raise_for_status()

                results = response.json().get("results", [])
                for result in results:
                    for vuln in result.get("vulns", []):
                        advisory_ids.add(vuln.get("id"))

        except Exception as e:
            emit("intel", "warn", f"OSV query failed: {e}", None)

    return list(advisory_ids)


def fetch_advisory(advisory_id: str, emit: Emit) -> Advisory | None:
    """Fetch full advisory from OSV or cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / f"{advisory_id}.json"

    # Check cache first
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            return _parse_advisory(data, emit)
        except Exception:
            pass

    if CACHE_ONLY:
        return None

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(f"{OSV_VULN_URL}/{advisory_id}")
            response.raise_for_status()
            data = response.json()

            # Cache it
            cache_path.write_text(json.dumps(data))

            return _parse_advisory(data, emit)

    except Exception as e:
        emit("intel", "warn", f"Failed to fetch {advisory_id}: {e}", None)
        return None


def fetch_advisories_batch(advisory_ids: list[str], emit: Emit) -> list[Advisory]:
    """Fetch multiple advisories with concurrency."""
    advisories = []

    for advisory_id in advisory_ids:
        adv = fetch_advisory(advisory_id, emit)
        if adv:
            advisories.append(adv)
        time.sleep(0.1)  # Rate limit

    return advisories


def _parse_advisory(data: dict, emit: Emit) -> Advisory | None:
    """Parse OSV JSON into Advisory model."""
    try:
        advisory_id = data.get("id", "")
        aliases = data.get("aliases", [])

        # Find npm affected entry
        affected_list = data.get("affected", [])
        npm_affected = None
        for aff in affected_list:
            pkg = aff.get("package", {})
            if pkg.get("ecosystem", "").lower() == "npm":
                npm_affected = aff
                break

        if not npm_affected:
            return None

        package = npm_affected.get("package", {}).get("name", "")
        if not package:
            return None

        # Parse ranges
        ranges = []
        for r in npm_affected.get("ranges", []):
            range_type = r.get("type", "SEMVER")
            events = r.get("events", [])

            introduced = None
            fixed = None
            last_affected = None

            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]

            ranges.append(AffectedRange(
                type=range_type,
                introduced=introduced,
                fixed=fixed,
                last_affected=last_affected,
            ))

        # Explicit versions
        versions = npm_affected.get("versions", [])

        # Parse dates
        from datetime import datetime
        published = None
        modified = None
        withdrawn = None

        if data.get("published"):
            try:
                published = datetime.fromisoformat(data["published"].replace("Z", "+00:00"))
            except:
                pass

        if data.get("modified"):
            try:
                modified = datetime.fromisoformat(data["modified"].replace("Z", "+00:00"))
            except:
                pass

        if data.get("withdrawn"):
            try:
                withdrawn = datetime.fromisoformat(data["withdrawn"].replace("Z", "+00:00"))
            except:
                pass

        # Severity
        severity = compute_severity(data)
        cvss_vector = None
        for sev in data.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score")
                break

        return Advisory(
            advisory_id=advisory_id,
            aliases=aliases,
            ecosystem="npm",
            package=package,
            ranges=ranges,
            versions=versions,
            severity=severity,
            cvss_vector=cvss_vector,
            summary=data.get("summary", ""),
            published=published,
            modified=modified,
            withdrawn=withdrawn,
            source="osv",
            source_url=f"https://osv.dev/vulnerability/{advisory_id}",
        )

    except Exception as e:
        emit("intel", "warn", f"Failed to parse advisory: {e}", None)
        return None
