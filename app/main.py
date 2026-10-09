"""FastAPI application: routes and startup."""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import config, orchestrator, store
from app.config import DEMO_MODE, PROJECT_ROOT, is_target_authorized
from app.events import make_emit
from app.schema import RunTrigger, Target, TargetKind


@asynccontextmanager
async def lifespan(_: FastAPI):
    watcher = asyncio.create_task(orchestrator.watcher_loop())
    try:
        yield
    finally:
        watcher.cancel()


app = FastAPI(title="Continuous Exposure Agent", version="0.1.0", lifespan=lifespan)


class CreateTargetRequest(BaseModel):
    kind: TargetKind
    name: str = Field(min_length=1, max_length=200)
    # Lets a caller bind to a pre-authorized id from config/demo.yaml (e.g. t_juiceshop).
    target_id: str | None = Field(default=None, pattern=r"^t_[a-z0-9_]{1,40}$")
    domain: str | None = None
    repo: str | None = None
    deploy_url: str | None = None


class StartRunRequest(BaseModel):
    target_id: str
    trigger: RunTrigger = "manual"


class ReplayRequest(BaseModel):
    advisory_id: str


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


@app.post("/api/targets")
async def create_target(req: CreateTargetRequest):
    target_id = req.target_id or f"t_{uuid.uuid4().hex[:8]}"
    target = Target(
        target_id=target_id,
        kind=req.kind,
        name=req.name,
        domain=req.domain,
        repo=req.repo,
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
async def get_run(run_id: str):
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return run


def _rows_by_key(query: str, params: dict) -> dict:
    result = store.get_client().query(query, parameters=params)
    return {row[0]: row[1:] for row in result.result_rows}


@app.get("/api/runs/{run_id}/report")
async def get_report(run_id: str):
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

    if not cand_rows:
        return {"run_id": run_id, "state": run["state"], "findings": []}

    si_ids = list({r[1] for r in cand_rows})
    adv_ids = list({r[2] for r in cand_rows})

    stack = _rows_by_key(
        "SELECT id, any(package), any(version), any(direct), any(status), any(source_url) "
        "FROM stack_items WHERE run_id = {run_id:String} AND id IN {ids:Array(String)} GROUP BY id",
        {"run_id": run_id, "ids": si_ids},
    )
    vers = _rows_by_key(
        "SELECT candidate_id, any(status), any(evidence), any(suggested_fix), any(checks_performed) "
        "FROM verifications WHERE run_id = {run_id:String} GROUP BY candidate_id",
        {"run_id": run_id},
    )
    advs = _rows_by_key(
        "SELECT advisory_id, argMax(summary, modified), max(replayed) "
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
        })

    return {"run_id": run_id, "state": run["state"], "findings": findings}


@app.get("/api/targets/{target_id}/changes")
async def get_changes(target_id: str):
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
async def get_events(target_id: str, since: str | None = None):
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
