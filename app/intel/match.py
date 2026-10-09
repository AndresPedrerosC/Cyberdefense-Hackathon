"""Advisory matching with semver range checking."""

from datetime import datetime

import semver

from app.schema import StackItem, Advisory, Candidate, Emit
from app.ids import candidate_id
from app.intel.osv import query_batch, fetch_advisories_batch


def match_stack_items(
    stack_items: list[StackItem], run_id: str, emit: Emit
) -> tuple[list[Candidate], list[Advisory]]:
    """Match stack items against OSV advisories."""
    emit("intel", "info", f"Matching {len(stack_items)} stack items", None)

    # Filter to npm packages only
    npm_items = [s for s in stack_items if s.ecosystem == "npm" and s.package]
    if not npm_items:
        emit("intel", "info", "No npm packages to match", None)
        return [], []

    emit("intel", "info", f"Querying OSV for {len(npm_items)} npm packages", None)

    # Build query batch
    queries = []
    for item in npm_items:
        q = {"package": {"ecosystem": "npm", "name": item.package}}
        if item.version:
            q["version"] = item.version
        queries.append(q)

    # Query OSV
    advisory_ids = query_batch(queries, emit)
    emit("intel", "info", f"OSV returned {len(advisory_ids)} advisory IDs", None)

    if not advisory_ids:
        return [], []

    # Fetch full advisories
    advisories = fetch_advisories_batch(advisory_ids, emit)
    emit("intel", "info", f"Fetched {len(advisories)} advisories", None)

    # Filter withdrawn
    advisories = [a for a in advisories if a.withdrawn is None]

    # Build lookup
    items_by_package = {}
    for item in npm_items:
        pkg = item.package.lower()
        if pkg not in items_by_package:
            items_by_package[pkg] = []
        items_by_package[pkg].append(item)

    # Match
    candidates = []
    for advisory in advisories:
        pkg = advisory.package.lower()
        if pkg not in items_by_package:
            continue

        for item in items_by_package[pkg]:
            candidate = _match_item_to_advisory(item, advisory, run_id)
            if candidate:
                candidates.append(candidate)

    emit("intel", "info", f"Generated {len(candidates)} candidates", None)

    confirmed = sum(1 for c in candidates if c.match_type == "confirmed")
    possible = len(candidates) - confirmed
    emit("intel", "info", f"Matches: {confirmed} confirmed, {possible} possible", None)

    return candidates, advisories


def _match_item_to_advisory(item: StackItem, advisory: Advisory, run_id: str) -> Candidate | None:
    """Check if a stack item is affected by an advisory."""
    # Version unknown
    if not item.version:
        cid = candidate_id(item.id, advisory.advisory_id)
        reason = f"{item.package} matches {advisory.advisory_id} (version unknown)"

        # Check if declared_range overlaps
        if item.declared_range:
            reason += f"; declared range {item.declared_range} may overlap affected range"

        return Candidate(
            id=cid,
            run_id=run_id,
            target_id=item.target_id,
            stack_item_id=item.id,
            advisory_id=advisory.advisory_id,
            advisory_url=advisory.source_url,
            affected_range=_format_ranges(advisory.ranges),
            fixed_version=_get_fixed_version(advisory.ranges),
            match_type="possible",
            reason=reason,
            severity_hint=advisory.severity,
            risk_score=_compute_risk_score(advisory.severity, "possible"),
        )

    # Check explicit versions first
    if item.version in advisory.versions:
        cid = candidate_id(item.id, advisory.advisory_id)
        return Candidate(
            id=cid,
            run_id=run_id,
            target_id=item.target_id,
            stack_item_id=item.id,
            advisory_id=advisory.advisory_id,
            advisory_url=advisory.source_url,
            affected_range=_format_ranges(advisory.ranges),
            fixed_version=_get_fixed_version(advisory.ranges),
            match_type="confirmed",
            reason=f"{item.package} {item.version} is in explicit affected versions (source: OSV {advisory.advisory_id})",
            severity_hint=advisory.severity,
            risk_score=_compute_risk_score(advisory.severity, "confirmed"),
        )

    # Check ranges
    for r in advisory.ranges:
        if _version_in_range(item.version, r):
            cid = candidate_id(item.id, advisory.advisory_id)
            affected_str = _format_range(r)
            return Candidate(
                id=cid,
                run_id=run_id,
                target_id=item.target_id,
                stack_item_id=item.id,
                advisory_id=advisory.advisory_id,
                advisory_url=advisory.source_url,
                affected_range=affected_str,
                fixed_version=r.fixed,
                match_type="confirmed",
                reason=f"{item.package} {item.version} is within affected range {affected_str} (source: OSV {advisory.advisory_id})",
                severity_hint=advisory.severity,
                risk_score=_compute_risk_score(advisory.severity, "confirmed"),
            )

    return None


def _version_in_range(version: str, r) -> bool:
    """Check if version falls within an affected range.

    Note: introduced="0" means "affects all versions below fixed".
    """
    try:
        # Normalize version for semver
        v = _normalize_version(version)
        if not v:
            return False

        parsed = semver.Version.parse(v)

        introduced = r.introduced
        fixed = r.fixed
        last_affected = r.last_affected

        # Handle introduced - "0" means all versions from the beginning
        if introduced and introduced != "0":
            intro_v = _normalize_version(introduced)
            if intro_v:
                intro_parsed = semver.Version.parse(intro_v)
                if parsed < intro_parsed:
                    return False
        # If introduced is "0", all versions from beginning are affected (no lower bound check)

        # Handle fixed (version must be < fixed)
        if fixed:
            fix_v = _normalize_version(fixed)
            if fix_v:
                fix_parsed = semver.Version.parse(fix_v)
                if parsed >= fix_parsed:
                    return False

        # Handle last_affected (version must be <= last_affected)
        if last_affected:
            la_v = _normalize_version(last_affected)
            if la_v:
                la_parsed = semver.Version.parse(la_v)
                if parsed > la_parsed:
                    return False

        # If introduced is "0" or set, and we passed fixed/last_affected checks, it's affected
        if introduced == "0":
            # "0" means all versions below fixed are affected
            if fixed or last_affected:
                return True
            # No upper bound means all versions affected (unusual but possible)
            return True

        # If we got here with introduced set and no fixed/last_affected, it's affected
        if introduced and not fixed and not last_affected:
            return True

        # If fixed or last_affected was set and we passed those checks, it's affected
        if fixed or last_affected:
            return True

        return False

    except Exception:
        return False


def _normalize_version(v: str) -> str | None:
    """Normalize version string for semver parsing."""
    if not v:
        return None

    # Remove leading 'v'
    if v.startswith("v"):
        v = v[1:]

    # Handle versions like "1.0" -> "1.0.0"
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")

    # Take only first 3 parts and strip prerelease for comparison
    base = ".".join(parts[:3])

    # Remove any non-numeric suffix from last part
    import re
    base = re.sub(r'[^0-9.].*$', '', base)

    # Ensure we have valid parts
    parts = base.split(".")
    try:
        return ".".join(str(int(p)) for p in parts[:3])
    except:
        return None


def _format_range(r) -> str:
    """Format a single range for display."""
    parts = []
    if r.introduced:
        if r.introduced == "0":
            parts.append(">=0.0.0")
        else:
            parts.append(f">={r.introduced}")
    if r.fixed:
        parts.append(f"<{r.fixed}")
    elif r.last_affected:
        parts.append(f"<={r.last_affected}")
    return " ".join(parts) if parts else "all versions"


def _format_ranges(ranges: list) -> str:
    """Format all ranges for display."""
    return "; ".join(_format_range(r) for r in ranges)


def _get_fixed_version(ranges: list) -> str | None:
    """Get the first fixed version from ranges."""
    for r in ranges:
        if r.fixed:
            return r.fixed
    return None


def _compute_risk_score(severity: str, match_type: str) -> int:
    """Compute risk score per spec 7.4.2."""
    severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}.get(severity, 1)
    # For matching, use status weight 2 for confirmed, 1 for possible
    status_weight = 2 if match_type == "confirmed" else 1
    return severity_weight * status_weight
