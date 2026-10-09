from app.verify.presence import check_presence
from app.verify.semgrep_runner import run_semgrep, load_registry
from app.verify.runtime import check_runtime

from app.schema import Target, StackItem, Advisory, Candidate, Verification, Evidence, Emit
from app.ids import verification_id
from app.config import (
    get_allowed_hosts,
    is_repo_authorized,
    is_target_authorized,
    resolve_repo_path,
)


def verify(
    candidates: list[Candidate],
    stack_items: dict[str, StackItem],
    advisories: dict[str, Advisory],
    target: Target,
    run_id: str,
    emit: Emit,
) -> list[Verification]:
    """Verify candidates against authorized targets."""
    emit("verification", "info", f"Starting verification for {len(candidates)} candidates", None)

    # Authorization gate (SEC-1, SEC-2: defense in depth)
    authorized, reason = is_target_authorized(target.target_id, target.kind)
    if authorized and not is_repo_authorized(target.target_id, target.repo):
        authorized, reason = False, f"repo path {target.repo} does not match authorized repo"

    if not authorized:
        emit("verification", "warn", f"Target not authorized: {reason}", None)
        return _all_inconclusive(candidates, run_id, target, reason, emit)

    emit("verification", "info", f"Target authorized: {reason}", None)

    verifications = []

    # Load rule registry
    registry = load_registry(emit)

    if not target.repo:
        emit("verification", "warn", "No repo path for verification", None)
        return _all_inconclusive(candidates, run_id, target, "no repo path", emit)
    # Same resolution the authorization gate used, so the checked path is the scanned path.
    repo_path = str(resolve_repo_path(target.repo))

    # V1: Dependency presence checks
    emit("verification", "info", "Running dependency presence checks", None)
    presence_results = check_presence(candidates, stack_items, repo_path, emit)

    # V2: Semgrep checks (run once for all candidates)
    emit("verification", "info", "Running Semgrep analysis", None)
    advisory_ids = [c.advisory_id for c in candidates]
    semgrep_hits = run_semgrep(repo_path, advisory_ids, registry, emit)
    semgrep_error = semgrep_hits.pop("_error", None)

    # V3: Runtime checks (if owned_deployment)
    runtime_results = {}
    if target.kind == "owned_deployment" and target.deploy_url:
        emit("verification", "info", "Running runtime checks", None)
        allowed_hosts = get_allowed_hosts(target.target_id)
        runtime_results = check_runtime(candidates, target.deploy_url, allowed_hosts, emit)

    # Build verifications
    for candidate in candidates:
        vid = verification_id(candidate.id, run_id)
        evidence = []
        checks_performed = []

        # Presence check
        presence = presence_results.get(candidate.id)
        if presence is not None:
            checks_performed.append("dependency-present")
            if not presence:
                # Not installed = not_present
                evidence.append(Evidence(
                    kind="dependency-present",
                    detail="Dependency not found in lockfile or node_modules",
                ))
                verifications.append(Verification(
                    id=vid,
                    run_id=run_id,
                    target_id=target.target_id,
                    candidate_id=candidate.id,
                    status="not_present",
                    evidence=evidence,
                    checks_performed=checks_performed,
                    suggested_fix=_suggest_fix(candidate, advisories.get(candidate.advisory_id)),
                    target="connected-repo",
                ))
                continue
            else:
                evidence.append(Evidence(
                    kind="dependency-present",
                    detail="Dependency confirmed in lockfile",
                ))

        # Semgrep check
        semgrep_hit = semgrep_hits.get(candidate.advisory_id)
        if semgrep_hit:
            rule_file = registry.get(candidate.advisory_id)
            if rule_file:
                checks_performed.append(f"semgrep:{rule_file}")
            evidence.append(Evidence(
                kind="semgrep",
                detail=semgrep_hit["detail"],
                source_url=semgrep_hit.get("source_url"),
            ))
        elif candidate.advisory_id in registry:
            checks_performed.append(f"semgrep:{registry[candidate.advisory_id]}")
            if semgrep_error:
                evidence.append(Evidence(kind="error", detail=semgrep_error["detail"]))

        # Runtime check
        runtime_hit = runtime_results.get(candidate.id)
        if runtime_hit:
            checks_performed.append("runtime")
            evidence.append(Evidence(
                kind="runtime",
                detail=runtime_hit["detail"],
                source_url=runtime_hit.get("source_url"),
            ))

        # Determine status
        has_rule = candidate.advisory_id in registry
        status = _determine_status(
            presence, semgrep_hit, runtime_hit, has_rule,
            semgrep_errored=semgrep_error is not None and has_rule,
        )

        verifications.append(Verification(
            id=vid,
            run_id=run_id,
            target_id=target.target_id,
            candidate_id=candidate.id,
            status=status,
            evidence=evidence,
            checks_performed=checks_performed,
            suggested_fix=_suggest_fix(candidate, advisories.get(candidate.advisory_id)),
            target="connected-repo" if target.kind == "connected_repo" else "owned-authorized",
        ))

    verified = sum(1 for v in verifications if v.status == "verified")
    present = sum(1 for v in verifications if v.status == "present")
    not_present = sum(1 for v in verifications if v.status == "not_present")

    emit("verification", "info", f"Verification complete: {verified} verified, {present} present, {not_present} not_present", None)

    return verifications


def _all_inconclusive(
    candidates: list[Candidate], run_id: str, target: Target, reason: str, emit: Emit
) -> list[Verification]:
    """Return inconclusive for all candidates (unauthorized)."""
    verifications = []
    for candidate in candidates:
        vid = verification_id(candidate.id, run_id)
        verifications.append(Verification(
            id=vid,
            run_id=run_id,
            target_id=target.target_id,
            candidate_id=candidate.id,
            status="inconclusive",
            evidence=[Evidence(kind="not-authorized", detail=reason)],
            checks_performed=[],
            suggested_fix=None,
            target=None,
        ))
    return verifications


def _determine_status(
    presence: bool | None,
    semgrep_hit: dict | None,
    runtime_hit: dict | None,
    has_rule: bool,
    semgrep_errored: bool = False,
) -> str:
    """Determine verification status per spec 7.3.3."""
    if presence is False:
        return "not_present"
    if semgrep_hit and not semgrep_errored:
        return "verified"
    if runtime_hit:
        return "verified"
    if semgrep_errored:
        return "inconclusive"
    if presence is True:
        return "present"
    return "inconclusive"


def _suggest_fix(candidate: Candidate, advisory: Advisory | None) -> str:
    """Generate suggested fix text."""
    if candidate.fixed_version:
        # Extract package name from stack_item_id if possible
        pkg = "the package"
        if advisory:
            pkg = advisory.package
        return f"Upgrade {pkg} to >={candidate.fixed_version}"

    url = candidate.advisory_url or ""
    return f"No fixed version published. See advisory for mitigations: {url}"
