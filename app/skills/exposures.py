"""Exposure skill: hard-coded secrets, install-time misconfigurations and supply-chain names."""

from app import config
from app.correlate.graph import Edge, Node
from app.skills import SkillContext, SkillResult


class ExposuresSkill:
    name = "exposures"
    label = "Secrets and misconfig"

    def applies_to(self, ctx: SkillContext) -> bool:
        return True

    def run(self, ctx: SkillContext) -> SkillResult:
        from app.scanner import vulnerability_scanner as vs

        findings = vs.scan_dependencies(ctx.stack_items, ctx.run_id, ctx.emit)
        target = ctx.target
        if target.kind in ("connected_repo", "owned_deployment") and target.repo:
            if ctx.repo_path is not None:
                findings += vs.scan_secrets_exposure(ctx.repo_path, ctx.emit)
                findings += vs.scan_misconfigurations(ctx.repo_path, ctx.emit)
            elif not config.is_repo_path_allowed(target.repo):
                ctx.emit("verification", "warn",
                         "Repo outside allowed roots; skipping repo scan", None)

        nodes, edges = [], []
        for f in findings:
            nid = f"exp:{f['id']}"
            nodes.append(Node(id=nid, kind="exposure", label=f["title"], skill=self.name,
                              data=f))
            if f.get("file"):
                edges.append(Edge(src=f"file:{f['file']}", dst=nid, kind="contains",
                                  line=f.get("line"), detail=f["title"], skill=self.name))
            elif f.get("package"):
                edges.append(Edge(src=f"pkg:{f['package']}", dst=nid, kind="contains",
                                  detail=f["title"], skill=self.name))
        return SkillResult(name=self.name, nodes=nodes, edges=edges, data=findings,
                           detail=f"{len(findings)} findings")
