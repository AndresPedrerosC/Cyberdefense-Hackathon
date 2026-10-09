"""Recon skill: what public-domain recon learned, as context for the correlator.

The collectors themselves run during discovery (they also produce the inventory); this skill
turns the knowledge base into graph nodes: the services the site runs on, which client-side
libraries it ships, and org signals that raise the stakes (payments, sign-in).
"""

from app.correlate.graph import Edge, Node
from app.skills import SkillContext, SkillResult

SENSITIVE_SAAS = {"stripe": "takes payments", "paypal": "takes payments",
                  "auth0": "runs sign-in", "okta": "runs sign-in", "clerk": "runs sign-in",
                  "firebase": "stores user data", "supabase": "stores user data"}


class ReconSkill:
    name = "recon"
    label = "Public recon"

    def applies_to(self, ctx: SkillContext) -> bool:
        return ctx.kb is not None

    def run(self, ctx: SkillContext) -> SkillResult:
        kb = ctx.kb
        nodes: list[Node] = []
        edges: list[Edge] = []
        stakes: list[str] = []
        site = kb.web.get("final_url") or f"https://{kb.domain}/"
        nodes.append(Node(id="ep:/", kind="endpoint", label="/", skill=self.name,
                          source_url=site, data={"classification": "public",
                                                 "status_code": kb.web.get("status")}))
        for t in kb.stack:
            nid = f"tech:{t.name}"
            nodes.append(Node(id=nid, kind="tech", label=t.name, skill=self.name,
                              source_url=t.source or None,
                              data={"category": t.category, "version": t.version,
                                    "evidence": t.evidence, "npm": t.npm}))
            if t.npm:
                # A library shipped in the page is loaded by every visitor of that page.
                edges.append(Edge(src="ep:/", dst=f"pkg:{t.npm}", kind="loads",
                                  detail=f"{site} loads {t.name}: {t.evidence}"[:200],
                                  skill=self.name))
            for key, why in SENSITIVE_SAAS.items():
                if key in t.name.lower():
                    stakes.append(f"{kb.domain} {why} ({t.name})")
        ctx.shared["stakes"] = sorted(set(stakes))
        return SkillResult(name=self.name, nodes=nodes, edges=edges,
                           detail=f"{len(kb.stack)} services, {len(stakes)} high-stakes signals",
                           data={"stakes": ctx.shared["stakes"]})
