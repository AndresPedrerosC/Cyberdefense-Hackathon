"""Research agent, SPA bundle mining and stack summary. Scripted fake model, no network."""

import json
from types import SimpleNamespace

import app.agent.research as research_mod
from app.agent.research import candidate_links, grounded, initial_sources, research
from app.recon.kb import FetchedPage, KnowledgeBase
from app.recon.spa import _is_copy, is_shell, mine_bundle
from app.recon.stack import derive_stack

ABOUT = ("<html><body><h1>About Acme</h1><p>Acme Freight builds routing software for mid-size "
         "shippers across Ohio and Michigan. Founded in 2012 in Columbus, Ohio, the company "
         "serves over 300 carriers. Our platform runs on AWS and integrates with Salesforce for "
         "customer accounts. We work with regional carriers and national retailers.</p>"
         '<a href="/team">Team</a> <a href="https://evil.com/about">x</a> '
         '<a href="/login">Login</a> <a href="/brochure.pdf">PDF</a></body></html>')


def _kb() -> KnowledgeBase:
    return KnowledgeBase(domain="acme.com", run_id="r1", target_id="t1")


def _page(url: str, html: str, status: int = 200) -> FetchedPage:
    from urllib.parse import urlsplit
    return FetchedPage(url=url, final_url=url, host=urlsplit(url).hostname, status=status,
                       html=html)


def _noop(*_):
    pass


class FakeClient:
    """Answers each chat.completions.create call with the next scripted JSON payload."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        body = self.replies.pop(0) if self.replies else {}
        msg = SimpleNamespace(content=json.dumps(body), tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_grounded_requires_verbatim_quote():
    text = "Founded in 2012 in Columbus, Ohio, the company serves carriers."
    assert grounded("founded in 2012 in Columbus", text)
    assert grounded("Columbus,  Ohio,   the company", text)
    assert not grounded("Founded in 2015 in Columbus", text)
    assert not grounded("Ohio", text)


def test_candidate_links_stay_in_scope_and_skip_noise():
    kb = _kb()
    links = candidate_links(kb, [_page("https://acme.com/about", ABOUT)], set())
    assert links == ["https://acme.com/team"]


def test_pipeline_keeps_grounded_facts_and_rejects_invented_ones():
    kb = _kb()
    client = FakeClient([
        {"read": ["https://acme.com/team"], "why": "team page"},
        {"facts": [
            {"key": "industry", "value": "Freight routing software",
             "quote": "Acme Freight builds routing software for mid-size shippers"},
            {"key": "founded", "value": "2012", "quote": "Founded in 2012 in Columbus"},
            {"key": "location", "value": "Texas", "quote": "Headquartered in Austin, Texas"},
            {"key": "secrets", "value": "x", "quote": "Acme Freight builds routing software"},
        ]},
        {"profile": "Acme Freight is a 2012 freight routing software company in Ohio."},
    ])
    saves = []
    orig = research_mod.fetch_in_scope
    research_mod.fetch_in_scope = lambda kb, url, emit: _page(url, "<p>short</p>")
    try:
        research(kb, [_page("https://acme.com/about", ABOUT)], _noop,
                 lambda k, e: saves.append(k.status), client=client)
    finally:
        research_mod.fetch_in_scope = orig

    agent_facts = {f.key: f.value for f in kb.facts if f.by == "agent"}
    assert agent_facts == {"industry": "Freight routing software", "founded": "2012"}
    assert kb.company["industry"] == "Freight routing software"
    assert "location" not in kb.company
    assert kb.agent.profile.startswith("Acme Freight")
    assert kb.coverage["agent"] == "ok"
    kinds = [s.kind for s in kb.agent.steps]
    assert kinds[:3] == ["thought", "plan", "read"] and "extract" in kinds and kinds[-1] == "final"
    assert "enriching" in saves
    assert all(c["response_format"] == {"type": "json_object"} for c in client.calls)


def test_model_unavailable_is_recorded(monkeypatch):
    monkeypatch.setattr(research_mod, "is_available", lambda: (False, "down"))
    kb = _kb()
    research(kb, [], _noop, lambda k, e: None)
    assert kb.coverage["agent"] == "skipped"
    assert kb.agent.steps[-1].kind == "error"


def test_initial_sources_use_spa_copy_when_page_is_empty():
    kb = _kb()
    kb.web["spa"] = {"copy": ["We design storefronts for independent coffee roasters."] * 3}
    sources = initial_sources(kb, [_page("https://acme.com/", "<div id=root></div>")])
    assert [s[0] for s in sources] == ["app bundle"]


def test_spa_copy_filter_and_bundle_mining():
    assert is_shell("", ["./assets/index-abc.js"])
    assert not is_shell("x" * 300, ["./assets/index-abc.js"])
    assert _is_copy("I'm a software engineer working with small businesses.")
    assert not _is_copy("A React form was unexpectedly submitted.")
    assert not _is_copy("1px solid transparent and more")
    assert not _is_copy("for the full message use the dev build")
    js = ('var a="We build ordering systems for restaurants in Vancouver.";'
          'x.push("/projects");y="https://github.com/acme";z="hi@acme.com";'
          'w="Invalid hook call detected in component";')
    mined = mine_bundle(js)
    assert mined["copy"] == ["We build ordering systems for restaurants in Vancouver."]
    assert mined["routes"] == ["/projects"]
    assert mined["links"] == ["https://github.com/acme"]
    assert mined["emails"] == ["hi@acme.com"]


def test_derive_stack_from_recon_evidence():
    kb = _kb()
    kb.infra.update({"hosting": "Fastly", "ips": [{"asn": "54113"}], "registrar": "GoDaddy",
                     "tls": {"issuer": "Let's Encrypt"}})
    kb.dns["ns"] = ["ns1.domaincontrol.com"]
    kb.mail["provider"] = "Google Workspace"
    kb.web.update({"server": "nginx/1.25.3", "headers": {"x-vercel-id": "abc"},
                   "external_hosts": ["fonts.googleapis.com"],
                   "spa": {"build": ["Vite"], "frameworks": ["React"], "bundles": []}})
    derive_stack(kb)
    got = {t.name: (t.category, t.version) for t in kb.stack}
    assert got["Fastly"] == ("hosting", None)
    assert got["GoDaddy DNS"] == ("dns", None)
    assert got["Google Workspace"] == ("mail", None)
    assert got["nginx"] == ("web-server", "1.25.3")
    assert got["Vercel"][0] == "hosting"
    assert got["Google Fonts"][0] == "saas"
    assert got["React"] == ("js-library", None)


def test_profile_is_plain_text():
    from app.agent.research import plain
    assert plain("A **solo** shop—mostly `cloud` work") == "A solo shop, mostly cloud work"
