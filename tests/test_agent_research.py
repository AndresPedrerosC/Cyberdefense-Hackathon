"""Research agent: tool scoping and the loop, driven by a scripted fake model (no network)."""

import json
from types import SimpleNamespace

import app.agent.research as research_mod
from app.agent.research import ToolBox, research
from app.recon.kb import KnowledgeBase


def _kb() -> KnowledgeBase:
    return KnowledgeBase(domain="acme.com", run_id="r1", target_id="t1")


def _noop_emit(*_):
    pass


def _call(i, name, **args):
    return SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=name,
                                                                 arguments=json.dumps(args)))


class FakeClient:
    """Returns one scripted message per chat.completions.create call."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        msg = self.script.pop(0) if self.script else SimpleNamespace(content="", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_dns_lookup_refuses_other_domains(monkeypatch):
    monkeypatch.setattr(research_mod, "lookup", lambda n, t: ["should not be called"])
    tools = ToolBox(_kb(), _noop_emit)
    assert tools.dns_lookup("evil.com", "A").startswith("Refused")
    assert tools.dns_lookup("acme.com.evil.com", "A").startswith("Refused")
    assert tools.dns_lookup("acme.com", "PTR").startswith("Record type")


def test_dns_lookup_allows_scope_and_underscore_names(monkeypatch):
    monkeypatch.setattr(research_mod, "lookup", lambda n, t: [f"{t} for {n}"])
    tools = ToolBox(_kb(), _noop_emit)
    assert tools.dns_lookup("mail.acme.com", "mx") == "MX for mail.acme.com"
    assert tools.dns_lookup("_dmarc.acme.com", "TXT") == "TXT for _dmarc.acme.com"


def test_fetch_page_budget_and_refusal(monkeypatch):
    monkeypatch.setattr(research_mod, "fetch_in_scope", lambda kb, p, e: None)
    tools = ToolBox(_kb(), _noop_emit)
    for _ in range(4):
        assert tools.fetch_page("https://evil.com/").startswith("Refused")
    assert "budget" in tools.fetch_page("/about")


def test_record_fact_validates_and_fills_company():
    kb = _kb()
    tools = ToolBox(kb, _noop_emit)
    assert tools.record_fact("secrets", "k", "v", "s").startswith("Category")
    assert tools.record_fact("company", "", "v", "s").startswith("Both")
    assert tools.record_fact("company", "Industry", "Logistics", "https://acme.com/about") == (
        "Recorded.")
    assert kb.company["industry"] == "Logistics"
    assert kb.facts[-1].by == "agent"


def test_loop_records_facts_and_finishes(monkeypatch):
    monkeypatch.setattr(research_mod, "LLM_MAX_STEPS", 5)
    kb = _kb()
    profile = "Acme is a logistics company based in Ohio. It sells freight software to shippers."
    client = FakeClient([
        SimpleNamespace(content="Checking the basics.", tool_calls=[
            _call(1, "record_fact", category="company", key="industry", value="Logistics",
                  source="https://acme.com/"),
        ]),
        SimpleNamespace(content=None, tool_calls=[_call(2, "finish", profile=profile)]),
    ])
    saves = []
    research(kb, [], _noop_emit, lambda k, e: saves.append(k.status), client=client)
    assert kb.agent.profile == profile
    assert kb.coverage["agent"] == "ok"
    assert [s.kind for s in kb.agent.steps] == [
        "thought", "tool_call", "tool_result", "tool_call", "tool_result"]
    assert "enriching" in saves
    # Tool results are fed back to the model on the next turn.
    assert client.calls[1]["messages"][-1]["role"] == "tool"


def test_loop_asks_for_profile_when_model_stops_early():
    kb = _kb()
    client = FakeClient([
        SimpleNamespace(content="Nothing to do.", tool_calls=[]),
        SimpleNamespace(content="Acme makes freight software for mid-size shippers in the US.",
                        tool_calls=None),
    ])
    research(kb, [], _noop_emit, lambda k, e: None, client=client)
    assert kb.agent.profile.startswith("Acme makes freight")
    assert "tools" not in client.calls[-1]


def test_model_unavailable_is_skipped(monkeypatch):
    monkeypatch.setattr(research_mod, "is_available", lambda: (False, "down"))
    kb = _kb()
    research(kb, [], _noop_emit, lambda k, e: None)
    assert kb.coverage["agent"] == "skipped"
    assert kb.status == "building"
