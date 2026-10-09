"""Skills: the tools the agent runs against a target.

Each skill observes one thing (advisories for installed packages, the code's import and route
map, the live attack surface, secrets on disk, public recon) and contributes nodes and edges to
the exposure graph. No skill produces findings on its own; app.correlate joins their output.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

from app.correlate.graph import Edge, Node
from app.schema import Emit, StackItem, Target

SkillStatus = Literal["ok", "skipped", "failed"]


@dataclass
class SkillContext:
    target: Target
    run_id: str
    emit: Emit
    stack_items: list[StackItem] = field(default_factory=list)
    repo_path: Path | None = None  # resolved, authorized repo root, or None
    kb: Any = None  # app.recon.kb.KnowledgeBase for public targets
    scoped_advisory_ids: set[str] | None = None
    set_state: Callable[[str], None] = lambda _state: None
    # Outputs earlier skills leave for later ones (e.g. dependencies -> correlator).
    shared: dict = field(default_factory=dict)


@dataclass
class SkillResult:
    name: str
    status: SkillStatus = "ok"
    detail: str = ""
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    data: Any = None  # raw output, served as-is by the skill's own API view

    def summary(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "nodes": len(self.nodes), "edges": len(self.edges)}


class Skill(Protocol):
    name: str
    label: str

    def applies_to(self, ctx: SkillContext) -> bool: ...

    def run(self, ctx: SkillContext) -> SkillResult: ...


def run_skill(skill: Skill, ctx: SkillContext) -> SkillResult:
    """Run one skill in isolation: a failure is reported, never raised."""
    if not skill.applies_to(ctx):
        return SkillResult(name=skill.name, status="skipped", detail="not applicable to target")
    try:
        result = skill.run(ctx)
    except Exception as e:
        ctx.emit("report", "warn", f"Skill {skill.name} failed: {e}", None)
        return SkillResult(name=skill.name, status="failed", detail=f"{type(e).__name__}: {e}"[:300])
    ctx.emit("report", "info", f"Skill {skill.name}: {result.status}"
             + (f", {result.detail}" if result.detail else ""), None)
    return result


def registry() -> list[Skill]:
    """Skills in run order. Dependencies runs first so later skills can read its candidates."""
    from app.skills.code_graph import CodeGraphSkill
    from app.skills.dependencies import DependenciesSkill
    from app.skills.exposures import ExposuresSkill
    from app.skills.live_endpoints import LiveEndpointsSkill
    from app.skills.recon import ReconSkill

    return [DependenciesSkill(), CodeGraphSkill(), LiveEndpointsSkill(), ExposuresSkill(),
            ReconSkill()]
