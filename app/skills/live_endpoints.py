"""Live attack surface skill: which paths the running app answers, and whether they need auth."""

from app.correlate.graph import Node
from app.skills import SkillContext, SkillResult


class LiveEndpointsSkill:
    name = "live_endpoints"
    label = "Live endpoints"

    def applies_to(self, ctx: SkillContext) -> bool:
        return ctx.target.kind in ("public", "owned_deployment") and bool(
            ctx.target.domain or ctx.target.deploy_url)

    def run(self, ctx: SkillContext) -> SkillResult:
        from app.scanner import endpoint_enumerator

        endpoints = endpoint_enumerator.enumerate_endpoints(ctx.target, ctx.run_id, ctx.emit)
        endpoints = endpoint_enumerator.fingerprint_endpoints(endpoints, ctx.target, ctx.emit)
        nodes = [Node(id=f"ep:{ep['path']}", kind="endpoint", label=ep["path"], skill=self.name,
                      source_url=ep.get("url"), data={
                          "classification": ep.get("classification"),
                          "status_code": ep.get("status_code"), "kind": ep.get("kind"),
                          "auth_required": ep.get("auth_required"),
                          "risk_level": ep.get("risk_level"),
                          "tech_signals": ep.get("tech_signals") or {}})
                 for ep in endpoints]
        answered = sum(1 for ep in endpoints if ep.get("classification") == "public")
        return SkillResult(name=self.name, nodes=nodes, data=endpoints,
                           detail=f"{len(endpoints)} endpoints, {answered} answer without auth")
