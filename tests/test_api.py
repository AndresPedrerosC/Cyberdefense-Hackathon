"""API tests: FastAPI routes over ASGI with ClickHouse and the orchestrator mocked out."""

import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

pytest.importorskip("clickhouse_connect", reason="project deps not installed; see SECURITY_AUDIT.md for setup")

import app.config as config  # noqa: E402
import app.main as main
from app import orchestrator
from app.schema import Target

PINNED = "t_juiceshop"
RUN_ID = "r_20261009_120000_abcd"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def demo_cfg(monkeypatch):
    cfg = {"authorized_targets": {PINNED: {
        "kinds": ["connected_repo", "owned_deployment"],
        "repo": "demo/juice-shop",
        "allowed_hosts": ["localhost:3004"],
    }}}
    monkeypatch.setattr(config, "_demo_config", cfg)
    monkeypatch.setattr(config, "ALLOWED_REPO_ROOTS", [(config.PROJECT_ROOT / "demo").resolve()])
    return cfg


@pytest.fixture(autouse=True)
def targets(monkeypatch):
    registry: dict[str, Target] = {}
    monkeypatch.setattr(orchestrator, "_targets", registry)
    return registry


class FakeClickHouse:
    """Routes query() by SQL substring to canned rows; records every call."""

    def __init__(self):
        self.routes: list[tuple[str, list]] = []
        self.calls: list[tuple[str, dict]] = []
        self.fail = False

    def on(self, needle, rows):
        self.routes.append((needle, rows))

    def query(self, sql, parameters=None):
        if self.fail:
            raise ConnectionError("clickhouse down")
        self.calls.append((sql, parameters or {}))
        for needle, rows in self.routes:
            if needle in sql:
                return SimpleNamespace(result_rows=rows)
        return SimpleNamespace(result_rows=[])


@pytest.fixture
def ch(monkeypatch):
    fake = FakeClickHouse()
    for name, value in {
        "get_client": lambda: fake,
        "insert_target": MagicMock(),
        "insert_event": MagicMock(),
        "get_run": MagicMock(return_value=None),
        "get_events": MagicMock(return_value=[]),
        "get_new_candidates": MagicMock(return_value=[]),
        "get_verification_changes": MagicMock(return_value=[]),
        "get_corpus_stats": MagicMock(return_value={"total": 3, "by_severity": {"high": 3}}),
        "get_record_counts": MagicMock(return_value={"targets": 1, "runs": 2}),
        "get_last_query_latency": MagicMock(return_value=1.5),
    }.items():
        monkeypatch.setattr(main.store, name, value)
    return fake


@pytest.fixture
def start_run(monkeypatch):
    m = AsyncMock(return_value={"run_id": RUN_ID, "queued": False, "trigger": "manual"})
    monkeypatch.setattr(orchestrator, "start_run", m)
    return m


@pytest.fixture
async def client(ch):
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


pytestmark = pytest.mark.anyio


# POST /api/targets: happy paths

async def test_create_target_generates_unauthorized_id(client, targets):
    r = await client.post("/api/targets", json={"kind": "public", "name": "Acme",
                                                "domain": "example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["target_id"].startswith("t_") and len(body["target_id"]) == 10
    assert body["authorized"] is False
    assert targets[body["target_id"]].domain == "example.com"
    main.store.insert_target.assert_called_once()


async def test_bind_pinned_target_with_matching_scope(client, targets):
    r = await client.post("/api/targets", json={
        "target_id": PINNED, "kind": "connected_repo", "name": "Juice",
        "repo": "demo/juice-shop"})
    assert r.status_code == 200
    assert r.json()["authorized"] is True
    stored = targets[PINNED].repo
    assert stored == str((config.PROJECT_ROOT / "demo" / "juice-shop").resolve())


async def test_rebinding_pinned_target_is_idempotent(client):
    payload = {"target_id": PINNED, "kind": "connected_repo", "name": "J",
               "repo": "demo/juice-shop"}
    assert (await client.post("/api/targets", json=payload)).status_code == 200
    assert (await client.post("/api/targets", json=payload)).status_code == 200


async def test_pinned_owned_deployment_with_allowed_host(client):
    r = await client.post("/api/targets", json={
        "target_id": PINNED, "kind": "owned_deployment", "name": "J",
        "repo": "demo/juice-shop", "deploy_url": "http://localhost:3004/"})
    assert r.status_code == 200 and r.json()["authorized"] is True


# POST /api/targets: spoofing and hijack (SECURITY_AUDIT H-1)

@pytest.mark.parametrize("payload,detail", [
    ({"kind": "public", "domain": "example.com"}, "not authorized"),
    ({"kind": "connected_repo", "repo": "demo/other"}, "Repo does not match"),
    ({"kind": "owned_deployment", "repo": "demo/juice-shop",
      "deploy_url": "http://evil.example.com/"}, "not in allowed_hosts"),
    ({"kind": "owned_deployment", "repo": "demo/juice-shop",
      "deploy_url": "http://localhost:6379/"}, "not in allowed_hosts"),
])
async def test_spoofing_pinned_target_is_forbidden(client, targets, payload, detail):
    r = await client.post("/api/targets", json={"target_id": PINNED, "name": "x", **payload})
    assert r.status_code == 403
    assert detail in r.json()["detail"]
    assert PINNED not in targets
    main.store.insert_target.assert_not_called()


async def test_existing_unpinned_target_cannot_be_hijacked(client, targets):
    targets["t_victim"] = Target(target_id="t_victim", kind="connected_repo", name="v",
                                 repo="/victim")
    r = await client.post("/api/targets", json={
        "target_id": "t_victim", "kind": "connected_repo", "name": "pwn",
        "repo": "demo/juice-shop"})
    assert r.status_code == 409
    assert targets["t_victim"].repo == "/victim"


async def test_hijack_check_also_consults_clickhouse(client, ch):
    ch.on("FROM targets FINAL", [("t_old", "public", "o", "a.com", "", "", datetime.utcnow())])
    r = await client.post("/api/targets", json={"target_id": "t_old", "kind": "public",
                                                "name": "x", "domain": "b.com"})
    assert r.status_code == 409
    assert ch.calls[0][1] == {"t": "t_old"}


# POST /api/targets: input validation (SECURITY_AUDIT H-2, M-1)

@pytest.mark.parametrize("repo", [
    "/etc", "/", "../../../../etc", "demo/../../..", "demo/../app", "~/.ssh", "demo/\x00x",
])
async def test_repo_outside_allowed_roots_rejected(client, repo):
    r = await client.post("/api/targets", json={"kind": "connected_repo", "name": "x",
                                                "repo": repo})
    assert r.status_code in (400, 422)
    main.store.insert_target.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("target_id", "T_UPPER"),
    ("target_id", "t_x'; DROP TABLE targets; --"),
    ("target_id", "t_" + "a" * 41),
    ("name", ""),
    ("name", "n" * 201),
    ("domain", "127.0.0.1:8123/?query=DROP"),
    ("domain", "evil.com/path"),
    ("domain", "user@internal"),
    ("domain", "https://example.com"),
    ("domain", "a" * 254),
    ("domain", "-bad.example.com"),
    ("deploy_url", "file:///etc/passwd"),
    ("deploy_url", "gopher://localhost:3004/_SET"),
    ("deploy_url", "http://admin:pw@localhost:3004/"),
    ("deploy_url", "http://localhost:99999/"),
    ("deploy_url", "http://" + "a" * 2050),
    ("repo", "r" * 1025),
    ("kind", "admin"),
])
async def test_create_target_input_validation(client, field, value):
    payload = {"kind": "public", "name": "x", field: value}
    r = await client.post("/api/targets", json=payload)
    assert r.status_code == 422, (field, value, r.text)
    main.store.insert_target.assert_not_called()


async def test_non_json_content_type_rejected(client):
    """A cross-site <form> can only send simple content types; they must not parse."""
    r = await client.post("/api/targets", content='{"kind":"public","name":"x"}',
                          headers={"content-type": "text/plain"})
    assert r.status_code == 422


# POST /api/runs

async def test_start_run_unknown_target_404(client, start_run):
    r = await client.post("/api/runs", json={"target_id": "t_nobody"})
    assert r.status_code == 404
    start_run.assert_not_called()


async def test_start_run_known_target(client, targets, start_run):
    targets["t_known"] = Target(target_id="t_known", kind="public", name="k")
    r = await client.post("/api/runs", json={"target_id": "t_known"})
    assert r.status_code == 200
    assert r.json() == {"run_id": RUN_ID, "queued": False, "trigger": "manual",
                        "target_id": "t_known"}
    assert start_run.call_args.args[1] == "manual"


@pytest.mark.parametrize("payload", [
    {"target_id": "../../etc"},
    {"target_id": "t_ok", "trigger": "rm -rf"},
    {},
])
async def test_start_run_validation(client, start_run, payload):
    assert (await client.post("/api/runs", json=payload)).status_code == 422
    start_run.assert_not_called()


# Read endpoints

async def test_get_run_404_and_found(client):
    assert (await client.get(f"/api/runs/{RUN_ID}")).status_code == 404
    main.store.get_run.return_value = {"run_id": RUN_ID, "state": "complete"}
    assert (await client.get(f"/api/runs/{RUN_ID}")).json()["state"] == "complete"


@pytest.mark.parametrize("path", [
    "/api/runs/r_x%27%20OR%201=1",
    "/api/runs/not-a-run-id",
    "/api/runs/r_" + "a" * 61 + "/report",
    "/api/targets/T_BAD/changes",
    "/api/events?target_id=t_x%27--",
    "/api/events",
    "/api/events?target_id=t_ok&since=" + "9" * 65,
])
async def test_read_endpoints_reject_malformed_ids(client, path):
    assert (await client.get(path)).status_code == 422


async def test_report_without_candidates(client, ch):
    main.store.get_run.return_value = {"run_id": RUN_ID, "state": "complete"}
    r = await client.get(f"/api/runs/{RUN_ID}/report")
    assert r.json() == {"run_id": RUN_ID, "state": "complete", "findings": []}


async def test_report_joins_evidence_chain(client, ch):
    main.store.get_run.return_value = {"run_id": RUN_ID, "state": "complete"}
    ch.on("FROM candidates", [
        ("c1", "s1", "GHSA-1", "https://osv.dev/GHSA-1", "confirmed", "high", 9, "4.17.21",
         None, "in range"),
        ("c2", "s2", "GHSA-2", "", "possible", "low", 1, None, None, ""),
    ])
    ch.on("FROM stack_items", [("s1", "lodash", "4.17.20", 1, "confirmed", "")])
    ch.on("FROM verifications", [("c1", "verified",
                                  json.dumps([{"kind": "semgrep", "detail": "hit"}]),
                                  "Upgrade lodash", json.dumps(["semgrep:r.yaml"]))])
    ch.on("FROM advisories", [("GHSA-1", "Prototype pollution", 1)])
    findings = (await client.get(f"/api/runs/{RUN_ID}/report")).json()["findings"]
    f1, f2 = findings
    assert f1["package"] == "lodash" and f1["direct"] is True
    assert f1["verification_status"] == "verified"
    assert f1["evidence"] == [{"kind": "semgrep", "detail": "hit"}]
    assert f1["summary"] == "Prototype pollution" and f1["replayed"] is True
    assert f2["verification_status"] == "inconclusive"
    assert f2["advisory_url"] is None and f2["package"] is None
    for sql, params in ch.calls:
        assert RUN_ID not in sql  # always bound as a parameter, never interpolated


async def test_changes_with_fewer_than_two_runs(client, ch):
    ch.on("FROM runs", [(RUN_ID,)])
    body = (await client.get("/api/targets/t_any/changes")).json()
    assert body == {"changes": [], "current_run_id": RUN_ID, "previous_run_id": None}


async def test_changes_diff(client, ch):
    ch.on("FROM runs", [("r_new",), ("r_old",)])
    main.store.get_new_candidates.return_value = ["cand_aaaaaaaaaaaa_x"]
    main.store.get_verification_changes.return_value = [
        {"candidate_id": "cand_bbbbbbbbbbbb", "before": "present", "after": "verified"}]
    changes = (await client.get("/api/targets/t_any/changes")).json()["changes"]
    assert [c["type"] for c in changes] == ["new", "change"]
    assert changes[1]["after"] == "verified"


async def test_events_since_parsing(client):
    assert (await client.get("/api/events", params={"target_id": "t_a",
                                                    "since": "garbage"})).status_code == 400
    r = await client.get("/api/events", params={"target_id": "t_a",
                                                "since": "2026-10-09T12:00:00Z"})
    assert r.status_code == 200
    assert main.store.get_events.call_args.args == ("t_a", datetime(2026, 10, 9, 12, 0))


async def test_stats_and_health(client, ch):
    stats = (await client.get("/api/stats")).json()
    assert stats["total_records"] == 3 and stats["advisories_total"] == 3
    assert (await client.get("/api/health")).json()["status"] == "ok"
    ch.fail = True
    health = (await client.get("/api/health")).json()
    assert health == {"status": "degraded", "clickhouse": False,
                      "demo_mode": main.DEMO_MODE}


# Demo replay

async def test_replay_hidden_outside_demo_mode(client, monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    r = await client.post("/api/advisories/replay", json={"advisory_id": "GHSA-1"})
    assert r.status_code == 404


async def test_replay_in_demo_mode(client, monkeypatch, targets):
    import app.intel.watcher as watcher
    monkeypatch.setattr(main, "DEMO_MODE", True)
    release = MagicMock(side_effect=[True, False])
    poll = MagicMock()
    monkeypatch.setattr(watcher, "release_holdback", release)
    monkeypatch.setattr(orchestrator, "poll_target_soon", poll)
    targets["t_repo"] = Target(target_id="t_repo", kind="connected_repo", name="r")
    targets["t_pub"] = Target(target_id="t_pub", kind="public", name="p")
    ok = await client.post("/api/advisories/replay", json={"advisory_id": "GHSA-1"})
    assert ok.status_code == 200 and ok.json()["polling_targets"] == ["t_repo"]
    again = await client.post("/api/advisories/replay", json={"advisory_id": "GHSA-1"})
    assert again.status_code == 400


@pytest.mark.parametrize("aid", ["", "../../etc/passwd", "GHSA 1", "G" * 101])
async def test_replay_advisory_id_validation(client, monkeypatch, aid):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    r = await client.post("/api/advisories/replay", json={"advisory_id": aid})
    assert r.status_code == 422
