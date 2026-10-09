"""FastAPI application: routes and startup."""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi import Path as PathParam
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from app import config, orchestrator, store
from app.config import (
    DEMO_MODE,
    PROJECT_ROOT,
    get_allowed_hosts,
    is_repo_authorized,
    is_repo_path_allowed,
    is_target_authorized,
    resolve_repo_path,
)
from app.events import make_emit
from app.integrations import senso
from app.recon.domain import normalize_domain
from app.recon.kb import KnowledgeBase
from app.recon.runner import get_live
from app.recon.runner import save as save_kb
from app.schema import RunTrigger, Target, TargetKind
from app.verify.runtime import deploy_url_refusal


@asynccontextmanager
async def lifespan(_: FastAPI):
    watcher = asyncio.create_task(orchestrator.watcher_loop())
    try:
        yield
    finally:
        watcher.cancel()


app = FastAPI(title="Continuous Exposure Agent", version="0.1.0", lifespan=lifespan)


TARGET_ID_PATTERN = r"^t_[a-z0-9_]{1,40}$"
RUN_ID_PATTERN = r"^r_[A-Za-z0-9_]{1,60}$"
# RFC 1123 hostname: no scheme, port, path, userinfo or IP-literal brackets.
HOSTNAME_PATTERN = (
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

TargetIdPath = Annotated[str, PathParam(pattern=TARGET_ID_PATTERN)]
RunIdPath = Annotated[str, PathParam(pattern=RUN_ID_PATTERN)]


class CreateTargetRequest(BaseModel):
    kind: TargetKind
    name: str = Field(min_length=1, max_length=200)
    # Lets a caller bind to a pre-authorized id from config/demo.yaml (e.g. t_juiceshop).
    target_id: str | None = Field(default=None, pattern=TARGET_ID_PATTERN)
    domain: str | None = Field(default=None, max_length=253, pattern=HOSTNAME_PATTERN)
    repo: str | None = Field(default=None, min_length=1, max_length=1024)
    deploy_url: str | None = Field(default=None, max_length=2048)

    @field_validator("repo")
    @classmethod
    def _no_nul(cls, v: str | None) -> str | None:
        if v is not None and "\x00" in v:
            raise ValueError("repo must not contain NUL bytes")
        return v

    @field_validator("deploy_url")
    @classmethod
    def _http_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            parsed = urlparse(v)
            parsed.port
        except ValueError as e:
            raise ValueError(f"invalid deploy_url: {e}") from None
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("deploy_url must be an http(s) URL with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("deploy_url must not carry credentials")
        return v


class StartRunRequest(BaseModel):
    target_id: str = Field(pattern=TARGET_ID_PATTERN)
    trigger: RunTrigger = "manual"


class ReplayRequest(BaseModel):
    advisory_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")


def _get_target(target_id: str) -> Target | None:
    target = orchestrator.get_targets().get(target_id)
    if target:
        return target
    result = store.get_client().query(
        "SELECT target_id, kind, name, domain, repo, deploy_url, created_ts "
        "FROM targets FINAL WHERE target_id = {t:String} LIMIT 1",
        parameters={"t": target_id},
    )
    if not result.result_rows:
        return None
    tid, kind, name, domain, repo, deploy_url, created_ts = result.result_rows[0]
    target = Target(
        target_id=tid, kind=kind, name=name, domain=domain or None,
        repo=repo or None, deploy_url=deploy_url or None, created_ts=created_ts,
    )
    orchestrator.get_targets()[tid] = target
    return target


def _check_pinned_target(target_id: str, req: CreateTargetRequest, repo: str | None) -> None:
    """A pre-authorized id may only be (re)bound with exactly its configured scope."""
    authorized, reason = is_target_authorized(target_id, req.kind)
    if not authorized:
        raise HTTPException(403, f"Cannot bind pre-authorized target: {reason}")
    if not is_repo_authorized(target_id, repo):
        raise HTTPException(403, "Repo does not match the pre-authorized target")
    if req.deploy_url:
        refusal = deploy_url_refusal(req.deploy_url, get_allowed_hosts(target_id))
        if refusal:
            raise HTTPException(403, refusal)


@app.post("/api/targets")
async def create_target(req: CreateTargetRequest):
    repo = None
    if req.repo is not None:
        if not is_repo_path_allowed(req.repo):
            raise HTTPException(400, "Repo path is outside the allowed repo roots")
        repo = str(resolve_repo_path(req.repo))

    if req.target_id:
        target_id = req.target_id
        if target_id in config.load_demo_config().get("authorized_targets", {}):
            _check_pinned_target(target_id, req, repo)
        elif _get_target(target_id):
            raise HTTPException(409, "Target id already exists")
    else:
        # A repo path that matches a configured target binds to that target's pre-authorized id.
        target_id = (
            config.find_authorized_target_id(req.kind, req.repo)
            or f"t_{uuid.uuid4().hex[:8]}"
        )

    domain = req.domain
    if req.kind == "public":
        try:
            domain = normalize_domain(req.domain or req.name)
        except ValueError as e:
            raise HTTPException(400, f"Invalid domain: {e}")
    target = Target(
        target_id=target_id,
        kind=req.kind,
        name=req.name,
        domain=domain,
        repo=repo,
        deploy_url=req.deploy_url,
    )
    store.insert_target(target)
    orchestrator.get_targets()[target_id] = target

    authorized, reason = is_target_authorized(target_id, req.kind)
    return {"target_id": target_id, "authorized": authorized, "authorization_reason": reason}


@app.post("/api/runs")
async def start_run(req: StartRunRequest):
    target = _get_target(req.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    result = await orchestrator.start_run(target, req.trigger)
    return {**result, "target_id": req.target_id}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: RunIdPath):
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return run


def _rows_by_key(query: str, params: dict) -> dict:
    result = store.get_client().query(query, parameters=params)
    return {row[0]: row[1:] for row in result.result_rows}


@app.get("/api/runs/{run_id}/report")
async def get_report(run_id: RunIdPath):
    """Ranked findings with evidence chains."""
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")

    client = store.get_client()
    cand_rows = client.query(
        "SELECT id, stack_item_id, advisory_id, advisory_url, match_type, severity_hint, "
        "risk_score, fixed_version, explanation, reason FROM candidates "
        "WHERE run_id = {run_id:String} ORDER BY risk_score DESC, advisory_id",
        parameters={"run_id": run_id},
    ).result_rows

    comp = client.query(
        "SELECT count(), countIf(d) FROM (SELECT id, any(direct) AS d FROM stack_items "
        "WHERE run_id = {run_id:String} GROUP BY id)",
        parameters={"run_id": run_id},
    ).result_rows[0]
    summary = {
        "components": comp[0],
        "direct_components": comp[1],
        "verification_authorized": run.get("verification_authorized"),
    }

    if not cand_rows:
        return {"run_id": run_id, "state": run["state"], "summary": summary, "findings": []}

    si_ids = list({r[1] for r in cand_rows})
    adv_ids = list({r[2] for r in cand_rows})

    stack = _rows_by_key(
        "SELECT id, any(package), any(version), any(direct), any(status), any(source_url), "
        "any(ecosystem) FROM stack_items WHERE run_id = {run_id:String} AND id IN {ids:Array(String)} GROUP BY id",
        {"run_id": run_id, "ids": si_ids},
    )
    vers = _rows_by_key(
        "SELECT candidate_id, any(status), any(evidence), any(suggested_fix), any(checks_performed) "
        "FROM verifications WHERE run_id = {run_id:String} GROUP BY candidate_id",
        {"run_id": run_id},
    )
    advs = _rows_by_key(
        "SELECT advisory_id, argMax(summary, modified), max(replayed), any(source) "
        "FROM advisories WHERE advisory_id IN {ids:Array(String)} GROUP BY advisory_id",
        {"ids": adv_ids},
    )

    findings = []
    for cid, si_id, adv_id, adv_url, match_type, severity, risk, fixed_v, expl, reason in cand_rows:
        si = stack.get(si_id)
        ver = vers.get(cid)
        adv = advs.get(adv_id)
        findings.append({
            "candidate_id": cid,
            "advisory_id": adv_id,
            "advisory_url": adv_url or None,
            "match_type": match_type,
            "severity": severity,
            "risk_score": risk,
            "fixed_version": fixed_v,
            "reason": reason or None,
            "explanation": expl,
            "package": si[0] if si else None,
            "version": si[1] if si else None,
            "direct": bool(si[2]) if si else False,
            "status": si[3] if si else None,
            "source_url": (si[4] or None) if si else None,
            "verification_status": ver[0] if ver else "inconclusive",
            "evidence": json.loads(ver[1]) if ver and ver[1] else [],
            "suggested_fix": (ver[2] or None) if ver else None,
            "checks_performed": json.loads(ver[3]) if ver and ver[3] else [],
            "summary": (adv[0] or None) if adv else None,
            "replayed": bool(adv[1]) if adv else False,
            # "config" marks a configuration finding observed during public recon.
            "ecosystem": si[5] if si else None,
            "source": (adv[2] or None) if adv else None,
        })

    return {"run_id": run_id, "state": run["state"], "summary": summary, "findings": findings}


@app.get("/api/runs/{run_id}/knowledge")
async def get_knowledge(run_id: RunIdPath):
    """Latest knowledge base snapshot for a public-domain run."""
    kb = get_live(run_id)
    if kb:
        return Response(kb.model_dump_json(), media_type="application/json")
    doc = await asyncio.to_thread(store.get_knowledge, run_id)
    if not doc:
        raise HTTPException(404, "No knowledge base for this run")
    return Response(doc, media_type="application/json")


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=senso.MAX_QUESTION_CHARS)

    @field_validator("question")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("question must not be blank")
        return v


async def _load_kb(run_id: str) -> KnowledgeBase | None:
    kb = get_live(run_id)
    if kb:
        return kb
    doc = await asyncio.to_thread(store.get_knowledge, run_id)
    return KnowledgeBase.model_validate_json(doc) if doc else None


def _senso_status(kb: KnowledgeBase) -> dict:
    s = kb.senso
    if not senso.is_configured():
        state = "not_configured"
    elif s.get("state"):
        state = s["state"]
    else:
        # Ingest runs as the run closes out; until then there is nothing to ask.
        state = "pending" if kb.status == "complete" else "waiting"
    return {"configured": senso.is_configured(), "state": state, "title": s.get("title"),
            "error": s.get("error"), "ingested_ts": s.get("ingested_ts")}


@app.get("/api/runs/{run_id}/senso")
async def get_senso_status(run_id: RunIdPath):
    """Whether this run's knowledge base is in Senso yet. Polls Senso while it is ingesting."""
    kb = await _load_kb(run_id)
    if not kb:
        raise HTTPException(404, "No knowledge base for this run")
    if await asyncio.to_thread(senso.refresh_state, kb):
        await asyncio.to_thread(save_kb, kb)
    return _senso_status(kb)


@app.post("/api/runs/{run_id}/ask")
async def ask_knowledge(run_id: RunIdPath, req: AskRequest):
    """Answer a question from this run's knowledge base document in Senso."""
    if not senso.is_configured():
        raise HTTPException(503, "Senso is not configured")
    kb = await _load_kb(run_id)
    if not kb:
        raise HTTPException(404, "No knowledge base for this run")
    content_id = kb.senso.get("content_id")
    if not content_id:
        raise HTTPException(409, "This run's knowledge base has not been ingested into Senso")
    try:
        result = await asyncio.to_thread(senso.search, req.question, [content_id])
    except senso.SensoError as e:
        raise HTTPException(502, str(e)) from None
    return {**result, "powered_by": "senso", "document": kb.senso.get("title")}


@app.get("/api/runs/{run_id}/vulnscan")
async def get_vulnscan(run_id: RunIdPath):
    """Deep dependency / secret / misconfiguration findings for a run."""
    from app import scanner
    return {"run_id": run_id, "findings": scanner.get_scan_results(run_id, "vulnscan") or []}


@app.get("/api/runs/{run_id}/endpoints")
async def get_endpoints(run_id: RunIdPath):
    """Enumerated attack-surface endpoints for a run."""
    from app import scanner
    return {"run_id": run_id, "endpoints": scanner.get_scan_results(run_id, "endpoints") or []}


@app.get("/api/runs/{run_id}/threats")
async def get_threats(run_id: RunIdPath):
    """Correlated threat patterns for a run."""
    from app import scanner
    return {"run_id": run_id, "threats": scanner.get_scan_results(run_id, "threats") or []}


@app.get("/api/targets/{target_id}/changes")
async def get_changes(target_id: TargetIdPath):
    """Diff between the latest two complete runs."""
    result = store.get_client().query(
        "SELECT run_id FROM runs WHERE target_id = {t:String} AND state = 'complete' "
        "ORDER BY finished_ts DESC LIMIT 2",
        parameters={"t": target_id},
    )
    rows = result.result_rows
    if len(rows) < 2:
        return {"changes": [], "current_run_id": rows[0][0] if rows else None,
                "previous_run_id": None}

    current_run_id, prev_run_id = rows[0][0], rows[1][0]
    changes = [
        {"type": "new", "candidate_id": cid, "description": f"New candidate: {cid[:12]}"}
        for cid in store.get_new_candidates(current_run_id, prev_run_id)
    ]
    changes += [
        {
            "type": "change",
            "candidate_id": vc["candidate_id"],
            "before": vc["before"],
            "after": vc["after"],
            "description": f"Status change: {vc['candidate_id'][:12]} {vc['before']} -> {vc['after']}",
        }
        for vc in store.get_verification_changes(current_run_id, prev_run_id)
    ]
    return {"changes": changes, "current_run_id": current_run_id, "previous_run_id": prev_run_id}


@app.get("/api/events")
async def get_events(
    target_id: Annotated[str, Query(pattern=TARGET_ID_PATTERN)],
    since: Annotated[str | None, Query(max_length=64)] = None,
):
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(400, "Invalid 'since' timestamp")
    return store.get_events(target_id, since_dt)


@app.get("/api/stats")
async def get_stats():
    stats = store.get_corpus_stats()
    counts = store.get_record_counts()
    return {
        "advisories_total": stats.get("total", 0),
        "advisories_by_severity": stats.get("by_severity", {}),
        "total_records": sum(counts.values()),
        "record_counts": counts,
        "last_query_latency_ms": store.get_last_query_latency(),
        "demo_mode": DEMO_MODE,
    }


@app.post("/api/advisories/replay")
async def replay_advisory(req: ReplayRequest):
    if not DEMO_MODE:
        raise HTTPException(404, "Not found")

    from app.intel.watcher import release_holdback

    emit = make_emit("system")
    if not release_holdback(req.advisory_id, emit):
        raise HTTPException(
            400, f"Advisory {req.advisory_id} not in holdback list or already released"
        )
    # release_holdback rewrites demo.yaml; drop the cached copy so the poll sees it.
    config._demo_config = None

    targets = [t for t in orchestrator.get_targets().values() if t.kind != "public"]
    for target in targets:
        orchestrator.poll_target_soon(target)

    emit("monitor", "info", f"Replayed advisory {req.advisory_id} (demo mode)", None)
    return {
        "released": req.advisory_id,
        "replayed": True,
        "polling_targets": [t.target_id for t in targets],
    }


@app.get("/api/health")
async def health():
    ch_ok = False
    try:
        store.get_client().query("SELECT 1")
        ch_ok = True
    except Exception:
        pass
    return {"status": "ok" if ch_ok else "degraded", "clickhouse": ch_ok, "demo_mode": DEMO_MODE}


app.mount("/", StaticFiles(directory=PROJECT_ROOT / "web", html=True), name="web")
