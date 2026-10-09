import asyncio
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# clickhouse_connect is a runtime dep not installed in the test env; stub it out
# before any app module imports it (same pattern as test_api.py).
if "clickhouse_connect" not in sys.modules:
    _ch = MagicMock()
    _ch_driver = MagicMock()
    _ch_driver_client = MagicMock()
    sys.modules["clickhouse_connect"] = _ch
    sys.modules["clickhouse_connect.driver"] = _ch_driver
    sys.modules["clickhouse_connect.driver.client"] = _ch_driver_client

from app import orchestrator
from app.schema import Target

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def harness(monkeypatch):
    inserted = []
    gate = asyncio.Event()
    started = []

    async def fake_pipeline(run, target, scoped_ids=None):
        started.append((run.run_id, run.trigger, scoped_ids))
        await gate.wait()
        run.state = "complete"
        return run.run_id

    monkeypatch.setattr(orchestrator.store, "insert_run", lambda run: inserted.append(run.model_copy()))
    monkeypatch.setattr(orchestrator, "_emit", lambda *a, **k: (lambda *x: None))
    monkeypatch.setattr(orchestrator, "run_pipeline", fake_pipeline)
    for name in ("_active", "_pending", "_runs"):
        monkeypatch.setattr(orchestrator, name, {})
    return gate, started, inserted


def _target():
    return Target(target_id="t_q", kind="connected_repo", name="q", repo="/tmp/q")


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)


async def test_queued_start_returns_runnable_run_id(harness):
    gate, started, _ = harness
    first = await orchestrator.start_run(_target(), "manual")
    await _settle()
    queued = await orchestrator.start_run(_target(), "manual")

    assert queued["queued"] is True
    assert queued["run_id"] and queued["run_id"] != first["run_id"]
    assert orchestrator._runs[queued["run_id"]].state == "queued"

    gate.set()
    await _settle()
    assert [s[0] for s in started] == [first["run_id"], queued["run_id"]]


async def test_repeated_queue_coalesces_into_one_run(harness):
    gate, started, _ = harness
    await orchestrator.start_run(_target(), "manual")
    await _settle()
    a = await orchestrator.start_run(_target(), "advisory", ["GHSA-a"])
    b = await orchestrator.start_run(_target(), "advisory", ["GHSA-b"])

    assert a["run_id"] == b["run_id"]
    gate.set()
    await _settle()
    assert started[1] == (a["run_id"], "advisory", ["GHSA-a", "GHSA-b"])


async def test_manual_trigger_upgrades_queued_advisory_run(harness):
    gate, started, inserted = harness
    await orchestrator.start_run(_target(), "advisory", ["GHSA-a"])
    await _settle()
    a = await orchestrator.start_run(_target(), "advisory", ["GHSA-b"])
    m = await orchestrator.start_run(_target(), "manual")

    assert m["run_id"] == a["run_id"] and m["trigger"] == "manual"
    assert inserted[-1].run_id == m["run_id"] and inserted[-1].trigger == "manual"
    gate.set()
    await _settle()
    assert started[1] == (m["run_id"], "manual", None)
