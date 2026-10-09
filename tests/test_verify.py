"""Unit tests for the verification pillar (spec section 3)."""

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

import app.config as config
from app.schema import Candidate, StackItem, Target
from app.verify import _determine_status, verify
from app.verify import presence as presence_mod
from app.verify import runtime as runtime_mod
from app.verify import semgrep_runner as sg
from app.verify.presence import check_presence
from app.verify.runtime import check_runtime
from app.verify.semgrep_runner import run_semgrep

FIXTURES = Path(__file__).parent / "fixtures" / "verify"
ROOT = Path(__file__).parent.parent
RUN = "run1"
TID = "t_juiceshop"
ADV = "GHSA-test-1111"


@pytest.fixture
def emit():
    return MagicMock()


@pytest.fixture(autouse=True)
def demo_cfg(monkeypatch):
    cfg = {
        "authorized_targets": {
            TID: {
                "kinds": ["connected_repo", "owned_deployment"],
                "allowed_hosts": ["localhost:3004", "127.0.0.1:3004"],
            }
        }
    }
    monkeypatch.setattr(config, "_demo_config", cfg)
    return cfg


def mk_target(kind="connected_repo", tid=TID, repo="/repo", deploy_url=None):
    return Target(target_id=tid, kind=kind, name="t", repo=repo, deploy_url=deploy_url)


def mk_candidate(cid="c1", adv=ADV, si="s1", fixed="4.17.21"):
    return Candidate(id=cid, run_id=RUN, target_id=TID, stack_item_id=si,
                     advisory_id=adv, fixed_version=fixed)


def mk_stack(pkg="lodash", version="4.17.20", sid="s1"):
    return StackItem(id=sid, run_id=RUN, target_id=TID, ecosystem="npm",
                     package=pkg, version=version)


def run_verify(presence, semgrep_hits, registry, target=None, runtime=None):
    cand = mk_candidate()
    target = target or mk_target()
    with patch("app.verify.load_registry", return_value=registry), \
         patch("app.verify.check_presence", return_value={cand.id: presence}), \
         patch("app.verify.run_semgrep", return_value=semgrep_hits), \
         patch("app.verify.check_runtime", return_value=runtime or {}):
        return verify([cand], {"s1": mk_stack()}, {}, target, RUN, MagicMock())


HIT = {ADV: {"detail": "matched", "source_url": "file://a.js#L1"}}


# 1. Decision table

def test_not_installed_is_not_present():
    (v,) = run_verify(False, {}, {ADV: "r.yaml"})
    assert v.status == "not_present"
    assert v.evidence[0].kind == "dependency-present"


def test_not_installed_wins_over_semgrep_hit():
    (v,) = run_verify(False, HIT, {ADV: "r.yaml"})
    assert v.status == "not_present"


def test_installed_with_semgrep_hit_is_verified():
    (v,) = run_verify(True, HIT, {ADV: "r.yaml"})
    assert v.status == "verified"
    kinds = [e.kind for e in v.evidence]
    assert "semgrep" in kinds and "dependency-present" in kinds
    assert "semgrep:r.yaml" in v.checks_performed


def test_installed_no_hit_rule_exists_is_present():
    (v,) = run_verify(True, {}, {ADV: "r.yaml"})
    assert v.status == "present"
    assert "semgrep:r.yaml" in v.checks_performed


def test_installed_no_rule_is_present():
    (v,) = run_verify(True, {}, {})
    assert v.status == "present"
    assert not any(c.startswith("semgrep") for c in v.checks_performed)


def test_error_unknown_presence_is_inconclusive():
    (v,) = run_verify(None, {}, {ADV: "r.yaml"})
    assert v.status == "inconclusive"


def test_runtime_hit_is_verified():
    t = mk_target("owned_deployment", deploy_url="http://localhost:3004")
    (v,) = run_verify(True, {}, {}, target=t,
                      runtime={"c1": {"detail": "version header"}})
    assert v.status == "verified"
    assert "runtime" in v.checks_performed
    assert v.target == "owned-authorized"


def test_determine_status_table():
    assert _determine_status(False, None, None, True) == "not_present"
    assert _determine_status(True, {"detail": "x"}, None, True) == "verified"
    assert _determine_status(True, None, None, True) == "present"
    assert _determine_status(True, None, None, False) == "present"
    assert _determine_status(None, None, None, True) == "inconclusive"


def test_suggested_fix_with_and_without_fixed_version():
    (v,) = run_verify(True, {}, {})
    assert ">=4.17.21" in v.suggested_fix
    cand = mk_candidate(fixed=None)
    with patch("app.verify.load_registry", return_value={}), \
         patch("app.verify.check_presence", return_value={cand.id: True}), \
         patch("app.verify.run_semgrep", return_value={}):
        (v2,) = verify([cand], {"s1": mk_stack()}, {}, mk_target(), RUN, MagicMock())
    assert v2.suggested_fix.startswith("No fixed version")


def test_semgrep_timeout_yields_error_sentinel_and_warns(rules_dir, emit):
    with patch("app.verify.semgrep_runner.subprocess.run",
               side_effect=subprocess.TimeoutExpired("semgrep", 60)):
        out = run_semgrep("/repo", [ADV], {ADV: "r.yaml"}, emit)
    assert set(out) == {"_error"}
    assert any("timed out" in c.args[2] for c in emit.call_args_list)


def test_timeout_flows_to_inconclusive_when_presence_unknown():
    (v,) = run_verify(None, {}, {ADV: "r.yaml"})
    assert v.status == "inconclusive"


SEMGREP_ERR = {"_error": {"detail": "Semgrep timed out", "source_url": None}}


def test_semgrep_error_with_presence_and_rule_is_inconclusive():
    (v,) = run_verify(True, dict(SEMGREP_ERR), {ADV: "r.yaml"})
    assert v.status == "inconclusive"
    assert any(e.kind == "error" for e in v.evidence)


def test_semgrep_error_without_rule_keeps_present():
    (v,) = run_verify(True, dict(SEMGREP_ERR), {})
    assert v.status == "present"


def test_semgrep_error_does_not_override_not_present():
    (v,) = run_verify(False, dict(SEMGREP_ERR), {ADV: "r.yaml"})
    assert v.status == "not_present"


def test_determine_status_semgrep_errored():
    assert _determine_status(True, None, None, True, semgrep_errored=True) == "inconclusive"
    assert _determine_status(True, None, {"detail": "x"}, True, semgrep_errored=True) == "verified"


# 2. Authorization gate

@pytest.mark.parametrize("kind,tid", [
    ("public", TID),
    ("connected_repo", "t_unlisted"),
    ("owned_deployment", "t_unlisted"),
])
def test_unauthorized_targets_refused(kind, tid):
    cand = mk_candidate()
    target = mk_target(kind, tid=tid)
    with patch("app.verify.check_presence") as pres, \
         patch("app.verify.run_semgrep") as sem, \
         patch("app.verify.check_runtime") as rt:
        vs = verify([cand], {"s1": mk_stack()}, {}, target, RUN, MagicMock())
    assert [v.status for v in vs] == ["inconclusive"]
    assert vs[0].evidence[0].kind == "not-authorized"
    assert vs[0].target is None
    pres.assert_not_called()
    sem.assert_not_called()
    rt.assert_not_called()


def test_repo_path_mismatch_refused(demo_cfg):
    demo_cfg["authorized_targets"][TID]["repo"] = "demo/juice-shop"
    with patch("app.verify.check_presence") as pres, patch("app.verify.run_semgrep") as sem:
        (v,) = verify([mk_candidate()], {"s1": mk_stack()}, {}, mk_target(repo="/etc"),
                      RUN, MagicMock())
    assert v.status == "inconclusive"
    assert v.evidence[0].kind == "not-authorized"
    pres.assert_not_called()
    sem.assert_not_called()


def test_repo_path_match_passes(demo_cfg):
    demo_cfg["authorized_targets"][TID]["repo"] = "demo/juice-shop"
    (v,) = run_verify(True, {}, {}, target=mk_target(repo=str(ROOT / "demo" / "juice-shop")))
    assert v.status == "present"


def test_authorized_connected_repo_passes_gate():
    (v,) = run_verify(True, {}, {})
    assert v.status == "present"
    assert v.evidence[-1].kind != "not-authorized"


def test_missing_repo_path_inconclusive():
    cand = mk_candidate()
    with patch("app.verify.load_registry", return_value={}):
        (v,) = verify([cand], {"s1": mk_stack()}, {}, mk_target(repo=None), RUN, MagicMock())
    assert v.status == "inconclusive"


# 3. Runtime check

def test_runtime_refuses_host_outside_allowed(emit):
    with patch.object(runtime_mod.httpx, "Client") as client:
        out = check_runtime([mk_candidate()], "http://evil.example.com", ["localhost:3004"], emit)
    assert out == {}
    client.assert_not_called()
    assert emit.call_args.args[1] == "error"
    assert "not in allowed_hosts" in emit.call_args.args[2]


def test_runtime_refuses_wrong_port(emit):
    with patch.object(runtime_mod.httpx, "Client") as client:
        check_runtime([mk_candidate()], "http://localhost:9999", ["localhost:3004"], emit)
    client.assert_not_called()


def test_runtime_allows_listed_host_and_uses_get_only(emit):
    resp = MagicMock(headers={"server": "nginx"})
    client = MagicMock()
    client.get.return_value = resp
    client.__enter__.return_value = client
    with patch.object(runtime_mod.httpx, "Client", return_value=client):
        check_runtime([mk_candidate()], "http://localhost:3004", ["localhost:3004"], emit)
    client.get.assert_called_once_with("http://localhost:3004")
    client.post.assert_not_called()


def test_runtime_network_error_is_swallowed(emit):
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.side_effect = RuntimeError("boom")
    with patch.object(runtime_mod.httpx, "Client", return_value=client):
        out = check_runtime([mk_candidate()], "http://localhost:3004", ["localhost:3004"], emit)
    assert out == {}
    assert any(c.args[1] == "warn" for c in emit.call_args_list)


def test_verify_passes_allowed_hosts_to_runtime():
    t = mk_target("owned_deployment", deploy_url="http://localhost:3004")
    cand = mk_candidate()
    with patch("app.verify.load_registry", return_value={}), \
         patch("app.verify.check_presence", return_value={cand.id: True}), \
         patch("app.verify.run_semgrep", return_value={}), \
         patch("app.verify.check_runtime", return_value={}) as rt:
        verify([cand], {"s1": mk_stack()}, {}, t, RUN, MagicMock())
    assert rt.call_args.args[2] == ["localhost:3004", "127.0.0.1:3004"]


# 4. Semgrep runner

def _proc(stdout, rc=1, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    (tmp_path / "r.yaml").write_text("rules: []\n")
    monkeypatch.setattr(sg, "RULES_DIR", tmp_path)
    return tmp_path


def test_semgrep_parses_saved_json(rules_dir, emit):
    saved = (FIXTURES / "semgrep_output.json").read_text()
    with patch("app.verify.semgrep_runner.subprocess.run", return_value=_proc(saved)) as run:
        out = run_semgrep("/repo", [ADV], {ADV: "r.yaml"}, emit)
    assert set(out) == {ADV}
    assert "src/routes/search.js:42" in out[ADV]["detail"]
    assert "rules.ghsa-test-1111" in out[ADV]["detail"]
    assert out[ADV]["source_url"] == "file://src/routes/search.js#L42"
    cmd = run.call_args.args[0]
    assert Path(cmd[0]).name == "semgrep" and cmd[1] == "scan" and "--metrics=off" in cmd
    assert cmd[-1] == "/repo"


def test_semgrep_no_rules_mapped_skips_subprocess(rules_dir, emit):
    with patch("app.verify.semgrep_runner.subprocess.run") as run:
        assert run_semgrep("/repo", ["GHSA-unknown"], {}, emit) == {}
    run.assert_not_called()


def test_semgrep_bad_exit_code(rules_dir, emit):
    with patch("app.verify.semgrep_runner.subprocess.run", return_value=_proc("", 2, "err")):
        assert set(run_semgrep("/repo", [ADV], {ADV: "r.yaml"}, emit)) == {"_error"}


def test_semgrep_invalid_json(rules_dir, emit):
    with patch("app.verify.semgrep_runner.subprocess.run", return_value=_proc("not json")):
        assert set(run_semgrep("/repo", [ADV], {ADV: "r.yaml"}, emit)) == {"_error"}
    assert any("parse" in c.args[2] for c in emit.call_args_list)


def test_semgrep_not_installed(rules_dir, emit):
    with patch("app.verify.semgrep_runner.subprocess.run", side_effect=FileNotFoundError):
        assert set(run_semgrep("/repo", [ADV], {ADV: "r.yaml"}, emit)) == {"_error"}
    assert any("not installed" in c.args[2] for c in emit.call_args_list)


def test_load_registry(tmp_path, monkeypatch, emit):
    reg = tmp_path / "registry.yaml"
    monkeypatch.setattr(sg, "REGISTRY_FILE", reg)
    assert sg.load_registry(emit) == {}
    reg.write_text("advisories:\n  GHSA-x: x.yaml\n")
    assert sg.load_registry(emit) == {"GHSA-x": "x.yaml"}
    reg.write_text(": : bad: [")
    assert sg.load_registry(emit) == {}


# Presence

def test_presence_lockfile_fixture(tmp_path, emit):
    shutil.copy(FIXTURES / "package-lock.json", tmp_path / "package-lock.json")
    items = {
        "s1": mk_stack("lodash", "4.17.20", "s1"),
        "s2": mk_stack("@scope/pkg", "1.2.3", "s2"),
        "s3": mk_stack("qs", "6.5.0", "s3"),
        "s4": mk_stack("missing", "1.0.0", "s4"),
    }
    cands = [mk_candidate(f"c{i}", si=f"s{i}") for i in range(1, 5)]
    res = check_presence(cands, items, str(tmp_path), emit)
    assert res == {"c1": True, "c2": True, "c3": True, "c4": False}


def test_presence_unknown_stack_item_is_none(tmp_path, emit):
    res = check_presence([mk_candidate(si="nope")], {}, str(tmp_path), emit)
    assert res == {"c1": None}


def test_presence_node_modules_version_match(tmp_path, emit):
    pkg = tmp_path / "node_modules" / "lodash"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"version": "4.17.20"}))
    items = {"s1": mk_stack("lodash", "4.17.20")}
    assert check_presence([mk_candidate()], items, str(tmp_path), emit) == {"c1": True}
    (pkg / "package.json").write_text(json.dumps({"version": "4.17.21"}))
    assert check_presence([mk_candidate()], items, str(tmp_path), emit) == {"c1": False}


def test_presence_v1_lockfile(tmp_path, emit):
    (tmp_path / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 1, "dependencies": {"a": {"dependencies": {"Nested": {}}}}}))
    items = {"s1": mk_stack("nested", None)}
    assert check_presence([mk_candidate()], items, str(tmp_path), emit) == {"c1": True}


def test_presence_corrupt_lockfile_warns(tmp_path, emit):
    (tmp_path / "package-lock.json").write_text("{nope")
    check_presence([mk_candidate()], {"s1": mk_stack()}, str(tmp_path), emit)
    assert any(c.args[1] == "warn" for c in emit.call_args_list)


def test_extract_pkg_name():
    f = presence_mod._extract_pkg_name
    assert f("node_modules/lodash") == "lodash"
    assert f("node_modules/@scope/pkg") == "@scope/pkg"
    assert f("node_modules/express/node_modules/qs") == "qs"
    assert f("lib/foo") is None


# 5. Each shipped rule hits its test snippet

def _shipped_rules():
    reg = ROOT / "rules" / "registry.yaml"
    data = yaml.safe_load(reg.read_text()) or {}
    return sorted(set((data.get("advisories") or {}).values()))


def _snippet_for(rule_file):
    stem = Path(rule_file).stem
    for d in (ROOT / "rules" / "tests", ROOT / "rules"):
        for ext in (".js", ".ts"):
            for name in (stem + ext, stem + ".test" + ext):
                if (d / name).exists():
                    return d / name
    return None


@pytest.mark.parametrize("rule_file", _shipped_rules() or [None])
def test_shipped_rule_hits_its_snippet(rule_file):
    if rule_file is None:
        pytest.skip("no rules registered in rules/registry.yaml")
    if not shutil.which("semgrep"):
        pytest.skip("semgrep not installed")
    rule_path = ROOT / "rules" / rule_file
    assert rule_path.exists(), f"registered rule missing: {rule_file}"
    snippet = _snippet_for(rule_file)
    assert snippet, f"no test snippet found for {rule_file}"
    proc = subprocess.run(
        ["semgrep", "scan", "--json", "--metrics=off", "--config", str(rule_path), str(snippet)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode in (0, 1), proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert results, f"{rule_file} did not match {snippet}"
    assert all(r["extra"]["metadata"].get("advisory_id") for r in results)
