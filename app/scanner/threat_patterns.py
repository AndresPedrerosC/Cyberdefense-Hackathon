"""Threat pattern surfacer: correlate findings across pillars into attack narratives.

Takes the outputs of the other pillars (advisory candidates, stack inventory, enumerated
endpoints, deep vuln findings) and chains them into named attack patterns with a MITRE
ATT&CK mapping and a plain-English narrative.

A threat is a plain dict:
    {id, name, tactic, score, components, narrative, mitre_techniques, remediation_priority}
"""

import hashlib

from app.schema import Emit

_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}


def _get(obj, key, default=None):
    """Read a field from a pydantic model or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _threat_id(name: str, components: list[str]) -> str:
    return hashlib.sha1((name + "|" + "|".join(sorted(components))).encode()).hexdigest()[:16]


def _has_vuln_type(vuln_findings, *types) -> list[dict]:
    return [f for f in vuln_findings if _get(f, "type") in types]


def surface_threats(candidates, stack_items, endpoints, vuln_findings, emit: Emit) -> list[dict]:
    candidates = candidates or []
    stack_items = stack_items or []
    endpoints = endpoints or []
    vuln_findings = vuln_findings or []

    threats: list[dict] = []
    si_by_id = {_get(s, "id"): s for s in stack_items}

    def cand_pkg(c) -> str:
        pkg = _get(c, "package")
        if pkg:
            return pkg
        si = si_by_id.get(_get(c, "stack_item_id"))
        return (_get(si, "package") or "") if si else ""

    public_eps = [e for e in endpoints if _get(e, "classification") == "public"]
    api_eps = [e for e in endpoints if _get(e, "kind") == "api"]
    admin_eps = [e for e in endpoints if _get(e, "kind") == "admin"]
    no_auth_api = [e for e in api_eps if not _get(e, "auth_required")]
    secrets = _has_vuln_type(vuln_findings, "secret_exposure", "npmrc_auth_token")
    confusion = _has_vuln_type(
        vuln_findings, "dependency_confusion", "dependency_confusion_candidate", "typosquatting"
    )
    high_sev_candidates = [
        c for c in candidates if _get(c, "severity_hint", "unknown") in ("critical", "high")
    ]

    # 1. Supply chain attack.
    if confusion:
        comps = [f"vuln:{_get(f, 'id')}" for f in confusion]
        threats.append(_build(
            "Supply chain attack", "Initial Access", comps,
            ["T1195", "T1195.002"],
            {"confusion": confusion}, emit,
        ))

    # 2. Credential exposure chain.
    if secrets and (public_eps or no_auth_api):
        comps = [f"vuln:{_get(f, 'id')}" for f in secrets]
        comps += [f"endpoint:{_get(e, 'path')}" for e in (public_eps or no_auth_api)[:5]]
        threats.append(_build(
            "Credential exposure chain", "Credential Access", comps,
            ["T1552", "T1552.001"],
            {"secrets": secrets, "endpoints": public_eps or no_auth_api}, emit,
        ))

    # 3. Lateral movement surface.
    if admin_eps and high_sev_candidates:
        comps = [f"endpoint:{_get(e, 'path')}" for e in admin_eps[:5]]
        comps += [f"candidate:{_get(c, 'advisory_id')}" for c in high_sev_candidates[:5]]
        threats.append(_build(
            "Lateral movement surface", "Lateral Movement", comps,
            ["T1190", "T1210"],
            {"admin": admin_eps, "candidates": high_sev_candidates}, emit,
        ))

    # 4. Data exfiltration risk.
    db_candidates = [
        c for c in candidates
        if any(k in cand_pkg(c).lower()
               for k in ("mongo", "sequelize", "postgres", "mysql", "redis", "knex", "typeorm", "prisma"))
    ]
    if db_candidates and no_auth_api:
        comps = [f"candidate:{_get(c, 'advisory_id')}" for c in db_candidates[:5]]
        comps += [f"endpoint:{_get(e, 'path')}" for e in no_auth_api[:5]]
        threats.append(_build(
            "Data exfiltration risk", "Exfiltration", comps,
            ["T1190", "T1041"],
            {"db": db_candidates, "endpoints": no_auth_api}, emit,
        ))

    # 5. Outdated dependency chain.
    outdated = _outdated_items(stack_items)
    if len(outdated) >= 5 and high_sev_candidates:
        comps = [f"pkg:{_get(i, 'package')}" for i in outdated[:8]]
        comps += [f"candidate:{_get(c, 'advisory_id')}" for c in high_sev_candidates[:3]]
        threats.append(_build(
            "Outdated dependency chain", "Initial Access", comps,
            ["T1190"],
            {"outdated": outdated, "candidates": high_sev_candidates}, emit,
        ))

    threats.sort(key=lambda t: t["score"], reverse=True)
    emit("report", "info", f"Surfaced {len(threats)} threat patterns", None)
    return threats


def _outdated_items(stack_items) -> list:
    """Packages pinned a couple of major versions back (best-effort from the version string)."""
    out = []
    for item in stack_items:
        ver = _get(item, "version")
        major = _major(ver)
        if major is not None and major <= 1:
            out.append(item)
    return out


def _major(ver) -> int | None:
    if not ver:
        return None
    head = str(ver).lstrip("^~=v ").split(".", 1)[0]
    return int(head) if head.isdigit() else None


def _build(name, tactic, components, techniques, context, emit) -> dict:
    pattern = {
        "id": _threat_id(name, components),
        "name": name,
        "tactic": tactic,
        "components": components,
        "mitre_techniques": techniques,
    }
    pattern["score"] = score_threat(pattern, context)
    pattern["narrative"] = generate_attack_narrative({**pattern, "_context": context}, emit)
    pattern["remediation_priority"] = (
        "immediate" if pattern["score"] >= 8
        else "high" if pattern["score"] >= 5
        else "medium"
    )
    return pattern


def score_threat(pattern, context) -> float:
    """0-10: severity of chained components x breadth of the chain."""
    sevs: list[int] = []
    for group in context.values():
        for item in group or []:
            sev = _get(item, "severity") or _get(item, "severity_hint") or "unknown"
            # endpoints carry risk_level rather than severity
            if sev == "unknown":
                rl = _get(item, "risk_level")
                sev = rl if rl in _SEV_WEIGHT else "unknown"
            sevs.append(_SEV_WEIGHT.get(sev, 1))

    if not sevs:
        return 0.0
    peak = max(sevs)  # 1..4
    chain = len(pattern["components"])
    chain_bonus = min(chain, 6) / 6.0  # 0..1
    # peak scaled to 0..7, chain bonus to 0..3
    score = (peak / 4.0) * 7.0 + chain_bonus * 3.0
    return round(min(score, 10.0), 1)


def generate_attack_narrative(threat_pattern, emit: Emit = None) -> str:
    name = threat_pattern["name"]
    ctx = threat_pattern.get("_context", {})
    steps: list[str]

    if name == "Supply chain attack":
        pkgs = ", ".join(sorted({_get(f, "package") for f in ctx.get("confusion", []) if _get(f, "package")}))
        steps = [
            f"Initial access: attacker publishes a malicious look-alike/internal package ({pkgs}) to the public registry.",
            "Execution: a routine `npm install` pulls the attacker's higher-versioned package and runs its install scripts.",
            "Persistence: the payload lands in node_modules and re-runs on every clean install or CI build.",
            "Exfiltration: build-time secrets and source are shipped to an attacker endpoint.",
        ]
    elif name == "Credential exposure chain":
        steps = [
            "Initial access: a hard-coded secret is read straight from the repo or a committed .npmrc.",
            "Execution: the credential authenticates against the live, reachable deployment.",
            "Persistence: an unauthenticated API accepts the stolen token for ongoing access.",
            "Exfiltration: data is pulled through the open API with valid credentials.",
        ]
    elif name == "Lateral movement surface":
        steps = [
            "Initial access: an exposed admin/dashboard endpoint is reachable from the internet.",
            "Execution: a known vuln in an auth/session library is exploited against it.",
            "Persistence: the attacker establishes an admin session with no rate limiting to slow them.",
            "Lateral movement: admin access is pivoted into adjacent services.",
        ]
    elif name == "Data exfiltration risk":
        steps = [
            "Initial access: a public API endpoint with no auth is discovered.",
            "Execution: a known vuln in the database driver/ORM is triggered through unvalidated input.",
            "Persistence: the attacker scripts repeated queries against the endpoint.",
            "Exfiltration: records are drained through the open API.",
        ]
    elif name == "Outdated dependency chain":
        steps = [
            "Initial access: several dependencies are multiple major versions behind with public CVEs.",
            "Execution: a known exploit for one transitive dependency fires against the public app.",
            "Persistence: the unpatched version keeps the hole open across deploys.",
            "Exfiltration: the foothold is used to reach data or further systems.",
        ]
    else:
        steps = ["Initial access -> execution -> persistence -> exfiltration."]

    narrative = f"{name}: " + " ".join(f"({i}) {s}" for i, s in enumerate(steps, 1))
    return narrative
