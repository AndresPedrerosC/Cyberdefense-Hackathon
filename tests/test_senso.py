"""Senso integration: no-key no-op, ingest payload, ask endpoint, error handling. httpx is mocked."""

import json
import sys
from unittest.mock import MagicMock

import httpx
import pytest

if "clickhouse_connect" not in sys.modules:
    for name in ("clickhouse_connect", "clickhouse_connect.driver", "clickhouse_connect.driver.client"):
        sys.modules[name] = MagicMock()

from fastapi.testclient import TestClient

from app import main, orchestrator
from app.integrations import senso
from app.recon import runner
from app.recon.kb import Fact, IntelHit, KnowledgeBase, Subdomain, Tech

RUN_ID = "r_20261009_120000_abcd"
KEY = "tgr_test_key_not_real"
CONTENT_ID = "fba6665f-0000-4000-8000-000000000001"
NODE_ID = "6d982360-0000-4000-8000-000000000002"


class FakeSenso:
    """Records every request and answers by (method, path)."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], httpx.Response | Exception] = {}

    def on(self, method, path, status=200, body=None, exc=None):
        self.routes[(method, path)] = exc or httpx.Response(status, json=body or {})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.method, request.url.path.removeprefix("/api/v1"))
        r = self.routes.get(key)
        if isinstance(r, Exception):
            raise r
        return r or httpx.Response(404, json={"status": 404, "message": "no route"})

    def body(self, i=-1) -> dict:
        return json.loads(self.requests[i].content)


@pytest.fixture
def fake(monkeypatch):
    f = FakeSenso()
    monkeypatch.setattr(senso, "_transport", httpx.MockTransport(f))
    return f


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("SENSO_API_KEY", KEY)
    monkeypatch.delenv("SENSO_BASE_URL", raising=False)


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.delenv("SENSO_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def no_clickhouse(monkeypatch):
    monkeypatch.setattr(runner.store, "insert_knowledge", MagicMock())
    monkeypatch.setattr(main.store, "get_knowledge", MagicMock(return_value=None))
    monkeypatch.setattr(runner, "_live", {})


def make_kb(**kw) -> KnowledgeBase:
    kb = KnowledgeBase(domain="example.com", run_id=RUN_ID, target_id="t_example", **kw)
    kb.company = {"name": "Example Corp", "location": "Toronto"}
    kb.mail = {"provider": "Google Workspace", "spf": {"record": "v=spf1 -all", "all": "-all"},
               "dmarc": {"record": "v=DMARC1; p=none", "policy": "none"}}
    kb.dns = {"ns": ["ns1.example.net"], "dnssec": False}
    kb.facts.append(Fact(category="company", key="founded", value="2004",
                         source="https://example.com/about", by="agent"))
    kb.stack.append(Tech(name="nginx", category="web-server", version="1.18.0",
                         evidence="Server header", source="https://example.com/"))
    kb.subdomains.append(Subdomain(name="vpn.example.com", interesting="remote access (vpn)"))
    kb.intel.append(IntelHit(source="nvd", id="CVE-2021-23017", title="nginx resolver bug",
                             tech="nginx", severity="high", url="https://nvd.nist.gov/x"))
    kb.agent.profile = "Example Corp sells widgets."
    return kb


def emit_log():
    log = []
    return log, lambda stage, level, msg, ref=None: log.append((stage, level, msg))


# ---- No key: everything is a no-op ----


def test_no_key_ingest_is_noop(no_key, fake):
    kb = make_kb(status="complete")
    log, emit = emit_log()
    senso.ingest_kb(kb, emit)
    assert kb.coverage["senso"] == "skipped"
    assert kb.senso == {"state": "not_configured"}
    assert fake.requests == []
    assert log == []


def test_no_key_request_raises_without_network(no_key, fake):
    with pytest.raises(senso.SensoError, match="not configured"):
        senso.search("q", [CONTENT_ID])
    assert fake.requests == []


def test_finish_knowledge_without_key_marks_skipped(no_key, fake):
    kb = make_kb()
    runner._live[RUN_ID] = kb
    orchestrator._finish_knowledge(RUN_ID, "complete", emit_log()[1])
    assert kb.status == "complete"
    assert kb.coverage["senso"] == "skipped"
    assert fake.requests == []


# ---- Ingest ----


def test_ingest_payload_shape(keyed, fake):
    fake.on("POST", "/org/kb/raw", 202, {"id": CONTENT_ID, "kb_node_id": NODE_ID,
                                         "processing_status": "processing"})
    kb = make_kb(status="complete")
    log, emit = emit_log()
    senso.ingest_kb(kb, emit)

    req = fake.requests[0]
    assert str(req.url) == "https://apiv2.senso.ai/api/v1/org/kb/raw"
    assert req.headers["X-API-Key"] == KEY
    body = fake.body()
    assert set(body) == {"text", "title", "summary"}  # spec: additionalProperties false
    assert body["title"] == f"example.com knowledge base, run {RUN_ID}"
    text = body["text"]
    for needle in ("Example Corp sells widgets.", "founded: 2004 (source: https://example.com/about",
                   "nginx 1.18.0", "v=spf1 -all", "p=none", "vpn.example.com: remote access",
                   "CVE-2021-23017", "ns1.example.net"):
        assert needle in text
    assert KEY not in text

    assert kb.coverage["senso"] == "ok"
    assert kb.senso["state"] == "ingesting"
    assert kb.senso["content_id"] == CONTENT_ID
    assert kb.senso["kb_node_id"] == NODE_ID
    assert log == [("report", "info", f"Ingested into Senso: {body['title']}")]


def test_ingest_honors_base_url(keyed, fake, monkeypatch):
    monkeypatch.setenv("SENSO_BASE_URL", "https://senso.internal/api/v1/")
    fake.on("POST", "/org/kb/raw", 202, {"id": CONTENT_ID, "processing_status": "complete"})
    kb = make_kb()
    senso.ingest_kb(kb, emit_log()[1])
    assert str(fake.requests[0].url) == "https://senso.internal/api/v1/org/kb/raw"
    assert kb.senso["state"] == "ready"


@pytest.mark.parametrize("status,needle", [
    (401, "rejected the API key"), (402, "out of credits"), (409, "identical document"),
    (500, "HTTP 500"),
])
def test_ingest_http_errors(keyed, fake, status, needle):
    fake.on("POST", "/org/kb/raw", status, {"status": status, "message": "nope"})
    kb = make_kb()
    log, emit = emit_log()
    senso.ingest_kb(kb, emit)
    assert kb.coverage["senso"] == "failed"
    assert kb.senso["state"] == "failed"
    assert needle in kb.senso["error"]
    assert log[0][:2] == ("report", "warn")
    assert log[0][2].startswith("Senso ingest failed: ")
    assert KEY not in log[0][2]


def test_ingest_network_error(keyed, fake):
    fake.on("POST", "/org/kb/raw", exc=httpx.ConnectError("boom"))
    kb = make_kb()
    log, emit = emit_log()
    senso.ingest_kb(kb, emit)
    assert kb.senso["state"] == "failed"
    assert "could not reach Senso" in log[0][2]


def test_finish_knowledge_ingests_only_complete_runs(keyed, fake):
    fake.on("POST", "/org/kb/raw", 202, {"id": CONTENT_ID, "processing_status": "pending"})
    kb = make_kb()
    runner._live[RUN_ID] = kb
    orchestrator._finish_knowledge(RUN_ID, "failed", emit_log()[1])
    assert fake.requests == [] and "senso" not in kb.coverage
    orchestrator._finish_knowledge(RUN_ID, "complete", emit_log()[1])
    assert len(fake.requests) == 1 and kb.coverage["senso"] == "ok"


def test_refresh_state_marks_ready(keyed, fake):
    fake.on("GET", f"/org/kb/nodes/{NODE_ID}", 200, {"content": {"processing_status": "complete"}})
    kb = make_kb()
    kb.senso = {"state": "ingesting", "content_id": CONTENT_ID, "kb_node_id": NODE_ID}
    assert senso.refresh_state(kb) is True
    assert kb.senso["state"] == "ready"


# ---- API ----


@pytest.fixture
def api():
    return TestClient(main.app)


def test_ask_requires_configuration(no_key, api):
    runner._live[RUN_ID] = make_kb(status="complete")
    r = api.post(f"/api/runs/{RUN_ID}/ask", json={"question": "Is DMARC enforced?"})
    assert r.status_code == 503
    s = api.get(f"/api/runs/{RUN_ID}/senso").json()
    assert s["configured"] is False and s["state"] == "not_configured"


def test_ask_scoped_search(keyed, fake, api):
    fake.on("POST", "/org/search", 200, {
        "query": "q", "search_type": "hybrid", "answer": "No. DMARC is p=none.",
        "total_results": 1, "max_results": 5, "processing_time_ms": 12,
        "results": [{"content_chunk_id": "c1", "content_id": CONTENT_ID, "kb_node_id": NODE_ID,
                     "version_id": "v1", "chunk_index": 0, "rank": 1, "score": 0.91,
                     "title": "example.com knowledge base",
                     "chunk_text": "DMARC: v=DMARC1; p=none (source: https://example.com/dmarc)."
                                   " See javascript:alert(1)"}],
    })
    kb = make_kb(status="complete")
    kb.senso = {"state": "ready", "content_id": CONTENT_ID, "title": "t"}
    runner._live[RUN_ID] = kb

    r = api.post(f"/api/runs/{RUN_ID}/ask", json={"question": "  Is DMARC enforced?  "})
    assert r.status_code == 200
    data = r.json()
    assert data["answer"] == "No. DMARC is p=none."
    assert data["powered_by"] == "senso"
    c = data["citations"][0]
    assert c["title"] == "example.com knowledge base" and c["score"] == 0.91
    assert c["urls"] == ["https://example.com/dmarc"]  # only http(s)

    body = fake.body()
    assert body == {"query": "Is DMARC enforced?", "max_results": 5,
                    "content_ids": [CONTENT_ID], "require_scoped_ids": True}


def test_ask_before_ingest_conflicts(keyed, fake, api):
    runner._live[RUN_ID] = make_kb(status="complete")
    r = api.post(f"/api/runs/{RUN_ID}/ask", json={"question": "anything"})
    assert r.status_code == 409
    assert fake.requests == []
    assert api.get(f"/api/runs/{RUN_ID}/senso").json()["state"] == "pending"


def test_ask_upstream_error_is_502(keyed, fake, api):
    fake.on("POST", "/org/search", 402, {"status": 402, "message": "Out of credits"})
    kb = make_kb(status="complete")
    kb.senso = {"state": "ready", "content_id": CONTENT_ID}
    runner._live[RUN_ID] = kb
    r = api.post(f"/api/runs/{RUN_ID}/ask", json={"question": "anything"})
    assert r.status_code == 502
    assert "out of credits" in r.json()["detail"]
    assert KEY not in r.text


@pytest.mark.parametrize("payload", [{}, {"question": ""}, {"question": "   "},
                                     {"question": "x" * 501}])
def test_ask_validation(keyed, api, payload):
    runner._live[RUN_ID] = make_kb(status="complete")
    assert api.post(f"/api/runs/{RUN_ID}/ask", json=payload).status_code == 422


def test_ask_unknown_run_404(keyed, api):
    assert api.post(f"/api/runs/{RUN_ID}/ask", json={"question": "q"}).status_code == 404
    assert api.post("/api/runs/bad id/ask", json={"question": "q"}).status_code in (404, 422)


def test_status_endpoint_polls_while_ingesting(keyed, fake, api):
    fake.on("GET", f"/org/kb/nodes/{NODE_ID}", 200, {"content": {"processing_status": "complete"}})
    kb = make_kb(status="complete")
    kb.senso = {"state": "ingesting", "content_id": CONTENT_ID, "kb_node_id": NODE_ID}
    runner._live[RUN_ID] = kb
    assert api.get(f"/api/runs/{RUN_ID}/senso").json()["state"] == "ready"
