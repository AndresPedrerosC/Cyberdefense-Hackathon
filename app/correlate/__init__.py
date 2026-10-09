"""Correlator: the core of a run. Joins every skill's output into findings.

  skills -> exposure graph -> reach (per vulnerable package) -> impact -> score -> narrate

A finding exists because of a path through the graph (route -> handler -> import -> package ->
advisory), not because one API returned a match. Severity comes from the impact class and the
path, with every adjustment written down; the advisory's CVSS rating rides along for reference.
"""

import hashlib
import re

import semver

from app.correlate.graph import Graph
from app.correlate.narrate import refine_with_model, template_dependency
from app.correlate.reach import Reach, Reachability
from app.correlate.score import LEVELS, score_dependency, score_exposure
from app.intel.impact import IMPACT_BASE, classify, model_symbol, symbol_candidates
from app.schema import Finding, PathStep

TIER_RANK = {"exposed": 3, "called": 2, "imported": 1, "installed": 0}
SECRET_TYPES = {"secret_exposure", "npmrc_auth_token"}
MAX_MODEL_SYMBOLS = 15
STAKES_ROUTES = [
    ("sign-in", re.compile(r"login|signin|sign-in|password|reset|2fa|totp|oauth|token", re.I)),
    ("payments", re.compile(r"payment|checkout|wallet|card|order|basket|cart", re.I)),
]


def build_graph(results) -> Graph:
    g = Graph()
    for r in results:
        g.merge(r.nodes, r.edges)
    return g


def correlate(graph: Graph, ctx, client=None, model: str | None = None) -> list[Finding]:
    """Findings for a run. `client` is an OpenAI-compatible client, or None for template-only."""
    engine = Reachability(graph, ctx.repo_path)
    stakes = list(ctx.shared.get("stakes") or []) + code_stakes(graph)
    findings = dependency_findings(graph, ctx, engine, stakes, client, model)
    findings += exposure_findings(graph, ctx, engine)
    if client is not None and model:
        kept = refine_with_model(findings, client, model, ctx.emit)
        ctx.emit("report", "info", f"Model rewrote {kept} findings; the rest use the evidence "
                 "template", None)
    findings.sort(key=lambda f: (-LEVELS.index(f.severity) if f.severity in LEVELS else 1,
                                 -TIER_RANK[f.reach], f.package or f.title))
    return findings


def code_stakes(graph: Graph) -> list[str]:
    out = []
    for label, rx in STAKES_ROUTES:
        hit = next((r for r in graph.of_kind("route") if rx.search(r.data.get("path") or "")),
                   None)
        if hit:
            out.append(f"the app handles {label} ({hit.label})")
    return out


# --------------------------------------------------------------------------- #
# vulnerable dependencies
# --------------------------------------------------------------------------- #

def dependency_findings(graph, ctx, engine: Reachability, stakes, client, model) -> list[Finding]:
    candidates = ctx.shared.get("candidates") or []
    advisories = ctx.shared.get("advisories") or {}
    verifications = ctx.shared.get("verifications") or {}
    stack = ctx.shared.get("stack_map") or {}
    model_calls = 0

    scored: dict[str, list[tuple]] = {}
    for c in candidates:
        v = verifications.get(c.id)
        if v is not None and v.status == "not_present":
            continue
        a = advisories.get(c.advisory_id)
        si = stack.get(c.stack_item_id)
        pkg = (a.package if a else None) or (si.package if si else None)
        if not a or not pkg:
            continue
        impact, why = classify(a)
        symbols = symbol_candidates(a, pkg)
        if (not symbols and client is not None and model and model_calls < MAX_MODEL_SYMBOLS
                and engine._used(f"pkg:{pkg}")):
            model_calls += 1
            try:
                sym = model_symbol(a, client, model)
            except Exception as e:
                ctx.emit("report", "warn", f"Symbol extraction failed for {a.advisory_id}: {e}",
                         None)
                sym = None
            symbols = [sym] if sym else []
        reach = engine.assess(pkg, c.advisory_id, symbols)
        sev, reasons = score_dependency(impact, why, reach, c.severity_hint, c.match_type, stakes)
        scored.setdefault(pkg, []).append((c, a, si, impact, reach, sev, reasons))

    findings = []
    for pkg, rows in scored.items():
        rows.sort(key=lambda r: (LEVELS.index(r[5]), TIER_RANK[r[4].tier],
                                 LEVELS.index(IMPACT_BASE.get(r[3], "low"))), reverse=True)
        c, a, si, impact, reach, sev, reasons = rows[0]
        ids = [c.advisory_id] + [r[0].advisory_id for r in rows[1:]
                                 if r[0].advisory_id != c.advisory_id]
        if len(ids) > 1:
            reasons = reasons + [f"Worst of {len(ids)} advisories for {pkg}"]
        f = Finding(
            id=_fid(ctx.run_id, "dep", pkg), run_id=ctx.run_id, kind="vulnerable-dependency",
            title="", attacker_gets="", how_reachable="", impact=impact, reach=reach.tier,
            auth_required=reach.auth_required, via=reach.via[0] if reach.via else None,
            symbol=reach.symbol, path=reach.steps, severity=sev, severity_reasons=reasons,
            cvss_severity=c.severity_hint, advisory_ids=ids, package=pkg,
            version=si.version if si else None, fix=_fix(pkg, [r[0] for r in rows], reach),
        )
        f.title, f.attacker_gets, f.how_reachable = template_dependency(f, reach)
        findings.append(f)
    return findings


def _fix(pkg: str, cands, reach: Reach) -> str:
    fixed = [c.fixed_version for c in cands if c.fixed_version]
    best = None
    for v in fixed:
        try:
            if best is None or semver.Version.parse(v.lstrip("v")) > semver.Version.parse(
                    best.lstrip("v")):
                best = v
        except ValueError:
            best = best or v
    if not best:
        return f"No fixed version of {pkg} is published; remove it or isolate the code path."
    msg = f"Upgrade {pkg} to {best} or later"
    if reach.via:
        msg += f" (it comes in through {reach.via[0]}, so upgrade that or add an override)"
    return msg + "."


# --------------------------------------------------------------------------- #
# secrets and misconfiguration
# --------------------------------------------------------------------------- #

def exposure_findings(graph: Graph, ctx, engine: Reachability) -> list[Finding]:
    served = [(r, d) for r in graph.of_kind("route") for d in r.data.get("static_dirs") or []]
    out = []
    for n in graph.of_kind("exposure"):
        d = n.data
        file, pkg = d.get("file"), d.get("package")
        kind = "exposed-secret" if d.get("type") in SECRET_TYPES else "misconfig"
        tier, where, steps = "installed", "", []
        if file:
            hit = next(((r, sd) for r, sd in served
                        if file == sd or file.startswith(sd.rstrip("/") + "/")), None)
            routes = engine.file_routes.get(f"file:{file}") or []
            if hit:
                r, sd = hit
                where = r.data.get("path", "").rstrip("/") + "/" + file[len(sd):].lstrip("/")
                tier = "exposed"
                steps.append(PathStep(node_id=r.id, kind="route", label=r.label,
                                      detail=f"serves the {sd}/ folder, registered at "
                                             f"{r.data.get('file')}:{r.data.get('line')}"))
            elif routes:
                r = routes[0][0]
                tier, where = "imported", r.label
                steps.append(PathStep(node_id=r.id, kind="route", label=r.label,
                                      detail="handler chain loads this file"))
            steps.append(PathStep(node_id=f"file:{file}", kind="file", label=file,
                                  detail=f"line {d.get('line')}" if d.get("line") else ""))
            sev, reasons = score_exposure(d.get("severity", "medium"), tier, where)
        else:
            used = bool(pkg) and engine._used(f"pkg:{pkg}")
            sev = d.get("severity") if d.get("severity") in LEVELS else "medium"
            reasons = [f"Scanner rated it {sev}"]
            if pkg and used:
                tier = "imported"
                reasons.append(f"The app imports {pkg}")
            elif pkg:
                sev = LEVELS[max(0, LEVELS.index(sev) - 1)]
                reasons.append(f"Nothing in the app imports {pkg} (-1)")
            if pkg:
                steps.append(PathStep(node_id=f"pkg:{pkg}", kind="package", label=pkg))
        steps.append(PathStep(node_id=n.id, kind="exposure", label=d.get("title", ""),
                              detail=d.get("detail", "")))
        out.append(Finding(
            id=_fid(ctx.run_id, "exp", d.get("id", n.id)), run_id=ctx.run_id, kind=kind,
            title=_exposure_title(d, tier, where), attacker_gets=_exposure_gets(kind, tier, where),
            how_reachable=_exposure_how(d, tier, where), impact="data-exposure" if
            kind == "exposed-secret" else "misconfig", reach=tier, path=steps, severity=sev,
            severity_reasons=reasons, cvss_severity="unknown", package=pkg,
            fix=d.get("remediation")))
    return out


def _exposure_title(d: dict, tier: str, where: str) -> str:
    title = d.get("title") or "Exposure"
    if d.get("file"):
        title += f" in {d['file']}"
    return title + (f", served at {where}" if tier == "exposed" else "")


def _exposure_gets(kind: str, tier: str, where: str) -> str:
    if kind != "exposed-secret":
        return "A weaker build or install setup that an attacker can lean on in a supply-chain " \
               "attack."
    if tier == "exposed":
        return f"Anyone who requests {where} gets the credential, no login needed."
    return "Anyone who can read the source or the built image gets the credential."


def _exposure_how(d: dict, tier: str, where: str) -> str:
    loc = f"{d['file']}:{d['line']}" if d.get("file") and d.get("line") else d.get("file") or ""
    if tier == "exposed":
        return f"{loc} sits inside a folder the app serves as static files, at {where}."
    if tier == "imported":
        return f"{loc} is loaded by the handler chain of {where}; it is not served directly."
    if loc:
        return f"{loc} is in the repository; no route serves it and no app code loads it."
    return d.get("detail") or ""


def _fid(run_id: str, *parts: str) -> str:
    return hashlib.sha256("|".join((run_id, *parts)).encode()).hexdigest()[:16]
