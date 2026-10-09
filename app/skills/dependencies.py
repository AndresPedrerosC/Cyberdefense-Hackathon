"""Dependency advisories skill: installed packages matched against OSV, then verified.

This is the old core pipeline (match -> holdback/scope filter -> verify -> score), moved behind
the skill interface unchanged. Its candidates still back /report and the advisory watcher; the
correlator reads them from ctx.shared to decide which ones are actually reachable.
"""

import json
import re

from app import store
from app.config import load_demo_config
from app.correlate.graph import Edge, Node
from app.skills import SkillContext, SkillResult


class DependenciesSkill:
    name = "dependencies"
    label = "Dependency advisories"

    def applies_to(self, ctx: SkillContext) -> bool:
        return True  # a run with no packages still records an empty, checked result

    def run(self, ctx: SkillContext) -> SkillResult:
        # Not `from app.intel import match`: once app.intel.match is imported, that name is the
        # module.
        from app.intel.match import match_stack_items as match
        from app.orchestrator import _posture_rows, _record_intel, _record_posture, _risk_score
        from app.verify import verify

        emit, run_id, target = ctx.emit, ctx.run_id, ctx.target
        stack_items = ctx.stack_items
        ctx.set_state("matching")
        candidates, advisories = match(stack_items, run_id, emit)

        cfg = load_demo_config()
        released = set(cfg.get("released_advisories", []) or [])
        held = set(cfg.get("demo_holdback_advisories", []) or []) - released
        if held:
            candidates = [c for c in candidates if c.advisory_id not in held]
            advisories = [a for a in advisories if a.advisory_id not in held]
        if ctx.scoped_advisory_ids:
            candidates = [c for c in candidates if c.advisory_id in ctx.scoped_advisory_ids]
            advisories = [a for a in advisories if a.advisory_id in ctx.scoped_advisory_ids]
        for a in advisories:
            if a.advisory_id in released:
                a.replayed = True

        store.insert_advisories(advisories)
        emit("intel", "info",
             f"Matched {len(candidates)} candidates from {len(advisories)} advisories", None)
        _record_intel(run_id, stack_items, candidates, advisories, emit)
        posture = [] if ctx.scoped_advisory_ids else _record_posture(run_id, emit)

        ctx.set_state("verifying")
        si_map = {s.id: s for s in stack_items}
        adv_map = {a.advisory_id: a for a in advisories}
        verifications = verify(candidates, si_map, adv_map, target, run_id, emit)
        store.insert_verifications(verifications)

        ver_map = {v.candidate_id: v for v in verifications}
        for c in candidates:
            v = ver_map.get(c.id)
            si = si_map.get(c.stack_item_id)
            c.risk_score = _risk_score(
                c.severity_hint,
                v.status if v else "inconclusive",
                c.match_type,
                si.status if si else "inferred",
            )
        persisted = list(candidates)
        if posture:
            # Configuration findings live on the board and report, not in the exposure graph.
            p_items, p_advs, p_cands, p_vers = _posture_rows(posture, target, run_id)
            store.insert_stack_items(p_items)
            store.insert_advisories(p_advs)
            store.insert_verifications(p_vers)
            persisted += p_cands
        # Persisted after scoring so the report's ORDER BY risk_score reflects verification.
        store.insert_candidates(persisted)

        ctx.shared.update(candidates=candidates, advisories=adv_map, verifications=ver_map,
                          stack_map=si_map)
        nodes, edges = to_graph(stack_items, candidates, adv_map, ver_map, ctx)
        return SkillResult(
            name=self.name,
            detail=f"{len(stack_items)} packages, {len(candidates)} advisory matches",
            nodes=nodes, edges=edges,
        )


def to_graph(stack_items, candidates, adv_map, ver_map, ctx: SkillContext):
    sk = DependenciesSkill.name
    nodes: list[Node] = []
    edges: list[Edge] = []
    for s in stack_items:
        if s.ecosystem != "npm" or not s.package:
            continue
        key = ""
        try:
            key = json.loads(s.evidence or "{}").get("key", "")
        except ValueError:
            pass
        nodes.append(Node(id=f"pkg:{s.package}", kind="package", label=s.package, skill=sk,
                          source_url=s.source_url, data={
                              "version": s.version, "direct": s.direct, "dev": s.dev,
                              "status": s.status, "lock_key": key,
                              "stack_item_id": s.id}))
        for parent in s.parents:
            if parent:
                edges.append(Edge(src=f"pkg:{parent}", dst=f"pkg:{s.package}",
                                  kind="depends_on", detail=f"{parent} depends on {s.package}",
                                  skill=sk))
    for c in candidates:
        a = adv_map.get(c.advisory_id)
        if not a:
            continue
        nodes.append(Node(id=f"adv:{a.advisory_id}", kind="advisory", label=a.advisory_id,
                          skill=sk, source_url=a.source_url, data={
                              "summary": a.summary, "severity": a.severity,
                              "cwe_ids": a.cwe_ids, "aliases": a.aliases}))
        edges.append(Edge(src=f"adv:{a.advisory_id}", dst=f"pkg:{a.package}", kind="affects",
                          detail=c.reason or "", skill=sk))
        v = ver_map.get(c.id)
        for ev in (v.evidence if v else []):
            if ev.kind != "semgrep" or not ev.source_url:
                continue
            m = re.match(r"file://(.+)#L(\d+)$", ev.source_url)
            if not m:
                continue
            path = m.group(1)
            root = str(ctx.repo_path or "")
            rel = path[len(root):].lstrip("/") if root and path.startswith(root) else path
            edges.append(Edge(src=f"file:{rel}", dst=f"adv:{a.advisory_id}", kind="calls",
                              line=int(m.group(2)), detail=ev.detail, skill="rules"))
    return nodes, edges
