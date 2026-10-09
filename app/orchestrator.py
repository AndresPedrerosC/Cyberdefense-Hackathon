"""Run orchestrator: state machine, async queue, auth gate, risk scoring, change detection."""

import asyncio
import hashlib
import uuid
from datetime import datetime

from app import events as ev
from app import store
from app.config import POLL_INTERVAL_SECONDS, is_target_authorized
from app.schema import Advisory, Emit, Run, RunState, RunTrigger, StackItem, Target

_runs: dict[str, Run] = {}
_targets: dict[str, Target] = {}
_active: dict[str, asyncio.Task] = {}
# A queued follow-up owns its Run up front so the caller can poll it by id.
_pending: dict[str, tuple[Run, list[str] | None]] = {}
_background: set[asyncio.Task] = set()


def _make_run_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"r_{ts}_{uuid.uuid4().hex[:4]}"


def _emit(target_id: str, run_id: str | None = None) -> Emit:
    return ev.make_emit(target_id, run_id)


def _update_run_state(run: Run, state: RunState, error: str | None = None) -> None:
    run.state = state
    if error:
        run.error = error
    if state in ("complete", "failed"):
        run.finished_ts = datetime.utcnow()
    store.insert_run(run)


def _inventory_hash(items: list[StackItem]) -> str:
    ids = sorted(i.id for i in items)
    return hashlib.sha1("|".join(ids).encode()).hexdigest()[:16]


def _risk_score(severity: str, status: str, match_type: str, item_status: str) -> int:
    """Risk score per spec 7.4.2: severity weight x verification-status weight."""
    sev_w = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 1)
    if item_status == "inferred" and match_type == "possible":
        return sev_w
    stat_w = {"verified": 3, "present": 2, "inconclusive": 1, "not_present": 0}.get(status, 1)
    return sev_w * stat_w


def _rehydrate_inventory(raw: list[dict], target_id: str, run_id: str) -> list[StackItem]:
    now = datetime.utcnow()
    return [StackItem(**r, target_id=target_id, run_id=run_id, ts=now) for r in raw]


def _new_run(target: Target, trigger: RunTrigger) -> Run:
    run = Run(
        run_id=_make_run_id(),
        target_id=target.target_id,
        trigger=trigger,
        state="queued",
        started_ts=datetime.utcnow(),
    )
    _runs[run.run_id] = run
    store.insert_run(run)
    return run


async def run_pipeline(run: Run, target: Target, scoped_advisory_ids: list[str] | None = None) -> str:
    """Execute one full pipeline run for a pre-allocated Run. Returns run_id.

    discover -> skills (dependencies first, then code paths, live endpoints, exposures, recon)
    -> exposure graph -> correlate -> findings.
    """
    from app.discovery import discover

    run_id = run.run_id
    emit = _emit(target.target_id, run_id)
    scoped = set(scoped_advisory_ids) if run.trigger == "advisory" and scoped_advisory_ids else None

    try:
        _update_run_state(run, "discovering")
        emit("discovery", "info", f"Run {run_id} started (trigger={run.trigger})", None)

        prev = store.get_latest_complete_run(target.target_id) if scoped else None
        if prev:
            raw = await asyncio.to_thread(store.get_stack_items_for_run, prev["run_id"])
            stack_items = _rehydrate_inventory(raw, target.target_id, run_id)
            _restore_lock_edges(stack_items, target)
            emit("discovery", "info",
                 f"Reusing inventory from {prev['run_id']} ({len(stack_items)} items)", None)
        else:
            stack_items = await asyncio.to_thread(discover, target, run_id, emit)

        if not stack_items and target.kind == "public":
            emit("discovery", "info", "No versioned JavaScript libraries found; the services "
                 "this domain runs on are listed in the Knowledgebase", None)
        elif not stack_items:
            emit("discovery", "warn", "No stack items discovered", None)

        run.inventory_hash = _inventory_hash(stack_items)
        store.insert_stack_items(stack_items)

        authorized, reason = is_target_authorized(target.target_id, target.kind)
        run.verification_authorized = authorized
        run.authorization_reason = reason

        findings = await asyncio.to_thread(
            _run_skills_and_correlate, run, target, stack_items, scoped, emit
        )
        _detect_changes(target.target_id, run_id, emit)

        _update_run_state(run, "complete")
        _finish_knowledge(run_id, "complete", emit)
        exposed = sum(1 for f in findings if f.reach == "exposed")
        emit("report", "info",
             f"Run {run_id} complete: {len(findings)} findings, {exposed} reachable from a "
             "route", None)

    except Exception as e:
        failed_stage = run.state
        _update_run_state(run, "failed", f"{failed_stage}: {e}")
        _finish_knowledge(run_id, "failed", emit)
        emit("system", "error", f"Run {run_id} failed at {failed_stage}: {e}", None)
        raise

    return run_id


def _restore_lock_edges(stack_items: list[StackItem], target: Target) -> None:
    """Rehydrated inventory loses lockfile parents and dev flags (not persisted); re-read them
    so a scoped advisory run can still trace a transitive package to the code that uses it."""
    if not target.repo:
        return
    from app.discovery.repo import discover_repo

    try:
        fresh = {s.package: s for s in discover_repo(target, "", lambda *_: None)}
    except Exception:
        return
    for s in stack_items:
        f = fresh.get(s.package)
        if f:
            s.parents, s.dev = f.parents, f.dev


def _run_skills_and_correlate(run: Run, target: Target, stack_items: list[StackItem],
                              scoped: set[str] | None, emit: Emit) -> list:
    """Run every applicable skill, join their output in the exposure graph, and correlate."""
    from app import config, scanner
    from app.agent.llm import get_client, is_available
    from app.correlate import build_graph, correlate
    from app.recon.runner import get_live
    from app.skills import SkillContext, registry, run_skill

    repo_path = None
    if target.repo and config.is_repo_path_allowed(target.repo):
        resolved = config.resolve_repo_path(target.repo)
        repo_path = resolved if resolved.is_dir() else None

    ctx = SkillContext(target=target, run_id=run.run_id, emit=emit, stack_items=stack_items,
                       repo_path=repo_path, kb=get_live(run.run_id), scoped_advisory_ids=scoped,
                       set_state=lambda s: _update_run_state(run, s))
    results = []
    for skill in registry():
        if skill.name == "dependencies":
            # The advisory pipeline is the run's state machine; its failure fails the run.
            results.append(skill.run(ctx))
            _record_intel_status(run.run_id, stack_items, emit)
            _update_run_state(run, "reporting")
        else:
            results.append(run_skill(skill, ctx))

    graph = build_graph(results)
    client = model = None
    if config.LLM_ENABLED:
        ok, detail = is_available()
        if ok:
            client, model = get_client(), config.LLM_MODEL
        else:
            emit("report", "info", f"Model unavailable ({detail}); findings use the evidence "
                 "template", None)
    findings = correlate(graph, ctx, client, model)

    by_name = {r.name: r for r in results}
    scanner.store_scan_results(run.run_id, "findings", [f.model_dump(mode="json")
                                                        for f in findings])
    scanner.store_scan_results(run.run_id, "graph", graph.to_dict())
    scanner.store_scan_results(run.run_id, "skills", [r.summary() for r in results])
    scanner.store_scan_results(run.run_id, "vulnscan", by_name["exposures"].data or [])
    scanner.store_scan_results(run.run_id, "endpoints", by_name["live_endpoints"].data or [])
    scanner.store_scan_results(run.run_id, "routes",
                               (by_name["code_graph"].data or {}).get("routes", []))
    _record_intel(run.run_id, findings, emit)
    return findings


def _record_intel_status(run_id: str, stack_items: list[StackItem], emit: Emit) -> None:
    """Mark the public-domain KB as cross-referencing, noting when nothing was checkable."""
    from app.recon.runner import get_live, save

    kb = get_live(run_id)
    if not kb:
        return
    kb.status = "cross-referencing"
    npm = [s for s in stack_items if s.ecosystem == "npm" and s.package]
    kb.coverage["osv"] = "ok" if npm else "skipped"
    if not npm:
        emit("intel", "info", "OSV: no versioned JavaScript libraries on the site to check", None)
    save(kb, emit)


def _record_intel(run_id: str, findings, emit: Emit) -> None:
    """Mirror correlated findings into the public-domain KB's Exposure view."""
    from app.recon.kb import IntelHit
    from app.recon.runner import get_live, save

    kb = get_live(run_id)
    if not kb:
        return
    for f in findings:
        if f.kind != "vulnerable-dependency":
            continue
        kb.intel.append(IntelHit(
            source="osv", id=f.advisory_ids[0], title=f.title, tech=f.package,
            severity=f.severity, match="confirmed" if f.reach != "installed" else "possible",
            url=f"https://osv.dev/vulnerability/{f.advisory_ids[0]}",
            detail=f"{f.attacker_gets} {f.how_reachable}",
            fixed_version=None,
        ))
    save(kb, emit)


def _finish_knowledge(run_id: str, status: str, emit: Emit) -> None:
    """Close out the public-domain knowledge base, if this run built one."""
    from app.recon.runner import get_live, save

    kb = get_live(run_id)
    if kb:
        kb.status = status
        save(kb, emit)


def _detect_changes(target_id: str, current_run_id: str, emit: Emit) -> None:
    """Compare current run (not yet complete) to the previous complete run."""
    prev = store.get_latest_complete_run(target_id)
    if not prev or prev["run_id"] == current_run_id:
        return
    prev_run_id = prev["run_id"]

    new_candidates = store.get_new_candidates(current_run_id, prev_run_id)
    if new_candidates:
        emit("report", "info", f"New candidates since {prev_run_id}: {len(new_candidates)}", None)

    for change in store.get_verification_changes(current_run_id, prev_run_id):
        emit("report", "info",
             f"Status change: {change['candidate_id'][:8]} {change['before']} -> {change['after']}",
             change["candidate_id"])


async def start_run(
    target: Target,
    trigger: RunTrigger,
    scoped_advisory_ids: list[str] | None = None,
) -> dict:
    """Start a run, or coalesce into one queued follow-up if a run is already active."""
    tid = target.target_id
    _targets[tid] = target

    active = _active.get(tid)
    if active and not active.done():
        if tid in _pending:
            follow, prev_ids = _pending[tid]
        else:
            follow, prev_ids = _new_run(target, trigger), None
        merged = sorted(set(prev_ids or []) | set(scoped_advisory_ids or [])) or None
        # A full-rescan trigger dominates a scoped advisory trigger.
        if trigger != "advisory" and follow.trigger != trigger:
            follow.trigger = trigger
            store.insert_run(follow)
        _pending[tid] = (follow, merged if follow.trigger == "advisory" else None)
        _emit(tid)("system", "info",
                   f"Run already active for {tid}, queued follow-up {follow.run_id} "
                   f"trigger={follow.trigger}", None)
        return {"run_id": follow.run_id, "queued": True, "trigger": follow.trigger}

    run = _new_run(target, trigger)
    _active[tid] = asyncio.create_task(_run_and_followup(run, target, scoped_advisory_ids))
    return {"run_id": run.run_id, "queued": False, "trigger": trigger}


async def _run_and_followup(run: Run, target: Target, scoped_advisory_ids: list[str] | None) -> None:
    tid = target.target_id
    try:
        await run_pipeline(run, target, scoped_advisory_ids)
    except Exception:
        pass  # already recorded on the run and emitted to the feed
    finally:
        _active.pop(tid, None)
        if tid in _pending:
            next_run, next_ids = _pending.pop(tid)
            next_run.started_ts = datetime.utcnow()
            _active[tid] = asyncio.create_task(_run_and_followup(next_run, target, next_ids))


async def poll_target(target: Target) -> list[str]:
    """Poll OSV once for a target; start a scoped advisory run on new hits."""
    from app.intel.watcher import poll_advisories

    if target.kind == "public":
        return []

    tid = target.target_id
    emit = _emit(tid)
    prev = store.get_latest_complete_run(tid)
    if not prev:
        return []

    known_ids = store.get_known_advisory_ids(tid)
    raw = store.get_stack_items_for_run(prev["run_id"])
    inventory = _rehydrate_inventory(raw, tid, prev["run_id"])

    try:
        new_advisories: list[Advisory] = await asyncio.to_thread(
            poll_advisories, target, inventory, known_ids, emit
        )
    except Exception as e:
        emit("monitor", "error", f"Poll failed: {e}", None)
        return []

    if not new_advisories:
        return []

    new_ids = [a.advisory_id for a in new_advisories]
    emit("monitor", "info", f"New advisories detected: {', '.join(new_ids)}", None)
    await start_run(target, "advisory", scoped_advisory_ids=new_ids)
    return new_ids


def poll_target_soon(target: Target) -> None:
    task = asyncio.create_task(poll_target(target))
    _background.add(task)
    task.add_done_callback(_background.discard)


async def watcher_loop() -> None:
    """Background watcher: polls OSV for new advisories every POLL_INTERVAL_SECONDS."""
    _emit("system")("system", "info",
                    f"Watcher started, poll interval={POLL_INTERVAL_SECONDS}s", None)
    while True:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        for target in list(_targets.values()):
            try:
                await poll_target(target)
            except Exception as e:
                _emit(target.target_id)("monitor", "error", f"Watcher error: {e}", None)


def get_targets() -> dict[str, Target]:
    return _targets


def get_all_runs() -> list[Run]:
    return list(_runs.values())
