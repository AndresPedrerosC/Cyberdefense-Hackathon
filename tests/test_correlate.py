"""Correlator: code graph extraction, reachability tiers, contextual severity, narration."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.correlate import build_graph, correlate
from app.correlate.graph import Node
from app.correlate.narrate import validate
from app.discovery.repo import discover_repo
from app.intel.impact import classify, symbol_candidates
from app.schema import Advisory, Candidate, Target
from app.skills import SkillContext, SkillResult
from app.skills.code_graph import CodeGraphSkill, parse_file, scan_repo
from app.skills.dependencies import to_graph as deps_graph
from app.skills.exposures import ExposuresSkill

SERVER = """\
const express = require('express')
const search = require('./routes/search')
const admin = require('./routes/admin')
const security = require('./lib/security')
const app = express()
app.get('/rest/search', search())
app.use('/admin', security.isAuthorized())
app.get('/admin/report', admin.report())
app.use('/public', express.static('public'))
// app.get('/commented/out', search())
"""
SEARCH = """\
const _ = require('lodash')
module.exports = () => (req, res) => res.json(_.template(req.query.q)())
"""
ADMIN = """\
import jwt from 'jsonwebtoken'
export const report = () => (req, res) => res.send(jwt.decode(req.headers.token))
"""
SECURITY = "exports.isAuthorized = () => (req, res, next) => next()\n"
UNUSED = "const v = require('vulnlib')\n"  # lives under test/, which is not app code
LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"express": "^4", "lodash": "^4", "jsonwebtoken": "^8",
                              "vulnlib": "^1"},
             "devDependencies": {"mocha": "^10"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0"}},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/jsonwebtoken": {"version": "8.5.1"},
        "node_modules/vulnlib": {"version": "1.0.0"},
        "node_modules/mocha": {"version": "10.0.0", "dev": True},
    },
}
# Assembled at runtime so no credential-shaped literal is committed.
FAKE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.fixture
def repo(tmp_path):
    files = {
        "server.js": SERVER, "routes/search.js": SEARCH, "routes/admin.ts": ADMIN,
        "lib/security.js": SECURITY, "test/unused.js": UNUSED,
        "public/config.js": f'window.cfg = {{ awsKey: "{FAKE_KEY}" }}\n',
        "package.json": json.dumps({"name": "fixture", "private": True,
                                    "dependencies": LOCK["packages"][""]["dependencies"],
                                    "devDependencies": {"mocha": "^10"}}),
        "package-lock.json": json.dumps(LOCK),
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def _adv(aid, pkg, cwes=(), summary="", details=""):
    return Advisory(advisory_id=aid, ecosystem="npm", package=pkg, severity="critical",
                    summary=summary, details=details, cwe_ids=list(cwes),
                    source_url=f"https://osv.dev/vulnerability/{aid}")


ADVISORIES = [
    _adv("GHSA-lodash", "lodash", ["CWE-94"], "Command injection in lodash",
         "Untrusted input passed to `_.template` can execute code."),
    _adv("GHSA-jwt", "jsonwebtoken", ["CWE-347"], "Signature bypass in jsonwebtoken"),
    _adv("GHSA-qs", "qs", ["CWE-1321"], "Prototype pollution in qs"),
    _adv("GHSA-vuln", "vulnlib", ["CWE-94"], "Code injection in vulnlib"),
    _adv("GHSA-mocha", "mocha", ["CWE-1333"], "ReDoS in mocha"),
]


def _run(repo, endpoints=(), client=None, model=None):
    target = Target(target_id="t_fix", kind="connected_repo", name="fix", repo=str(repo))
    with patch("app.discovery.repo.config.is_repo_path_allowed", return_value=True), \
            patch("app.discovery.repo.config.resolve_repo_path", return_value=repo):
        items = discover_repo(target, "r1", lambda *a: None)
    by_pkg = {s.package: s for s in items}
    cands = [Candidate(id=f"c-{a.package}", run_id="r1", target_id="t_fix",
                       stack_item_id=by_pkg[a.package].id, advisory_id=a.advisory_id,
                       match_type="confirmed", severity_hint="critical",
                       fixed_version="99.0.0") for a in ADVISORIES]
    adv_map = {a.advisory_id: a for a in ADVISORIES}
    ctx = SkillContext(target=target, run_id="r1", emit=lambda *a: None, stack_items=items,
                       repo_path=repo)
    ctx.shared.update(candidates=cands, advisories=adv_map, verifications={},
                      stack_map={s.id: s for s in items})
    nodes, edges = deps_graph(items, cands, adv_map, {}, ctx)
    results = [SkillResult(name="dependencies", nodes=nodes, edges=edges),
               CodeGraphSkill().run(ctx), ExposuresSkill().run(ctx)]
    if endpoints:
        results.append(SkillResult(name="live_endpoints", nodes=[
            Node(id=f"ep:{p}", kind="endpoint", label=p, data={"classification": c})
            for p, c in endpoints]))
    findings = correlate(build_graph(results), ctx, client, model)
    return {f.package or f.title: f for f in findings}


# --------------------------------------------------------------------------- #
# code graph
# --------------------------------------------------------------------------- #

def test_code_graph_reads_imports_routes_auth_and_static_dirs(repo):
    files = scan_repo(repo)
    assert "test/unused.js" not in files  # test code is not app code
    routes = {(r.method, r.path): r for f in files.values() for r in f.routes}
    assert ("GET", "/commented/out") not in routes
    assert routes[("GET", "/rest/search")].auth_by is None
    assert routes[("GET", "/rest/search")].targets[0].module == "routes/search.js"
    assert "isAuthorized" in routes[("GET", "/admin/report")].auth_by
    assert routes[("USE", "/public")].static_dirs == ["public"]
    imports = {b.module for b in files["routes/admin.ts"].imports}
    assert imports == {"jsonwebtoken"}


def test_parse_file_import_forms(tmp_path):
    (tmp_path / "local.js").write_text("")
    code = """
import def, { a as b, c } from 'pkg-a'
import * as ns from '@scope/pkg-b/sub'
import fs = require('fs')
const { x, y: z } = require('pkg-c')
const m = require('pkg-d').inner
const l = require('./local')
require('pkg-e')
"""
    info = parse_file("index.js", code, tmp_path)
    got = {name: (b.module, b.member, b.local) for name, b in info.bindings.items()}
    assert got["def"] == ("pkg-a", "default", False)
    assert got["b"] == ("pkg-a", "a", False)
    assert got["ns"] == ("@scope/pkg-b", None, False)
    assert "fs" not in got  # builtins are not packages
    assert got["z"] == ("pkg-c", "y", False)
    assert got["m"] == ("pkg-d", "inner", False)
    assert got["l"] == ("local.js", None, True)
    assert any(b.module == "pkg-e" and not b.name for b in info.imports)


def test_object_keys_are_not_read_as_handler_references(tmp_path):
    code = "const payment = require('./p')\napp.use(featurePolicy({ payment: ['self'] }))\n"
    (tmp_path / "p.js").write_text("")
    route = parse_file("s.js", code, tmp_path).routes[0]
    assert route.targets == []


# --------------------------------------------------------------------------- #
# reachability + severity
# --------------------------------------------------------------------------- #

def test_reach_tiers_and_contextual_severity(repo):
    f = _run(repo, endpoints=[("/rest/search", "public")])

    lodash = f["lodash"]
    assert lodash.reach == "exposed" and lodash.auth_required is False
    assert lodash.symbol == "_.template"
    assert lodash.severity == "critical"
    labels = [s.label for s in lodash.path]
    assert labels[:4] == ["/rest/search", "GET /rest/search", "routes/search.js",
                          "_.template"]
    assert lodash.path[-1].node_id == "adv:GHSA-lodash"

    jwt = f["jsonwebtoken"]
    assert jwt.reach == "exposed" and jwt.auth_required is True
    assert jwt.severity == "medium"  # critical, -1 auth, -1 vulnerable call not confirmed

    qs = f["qs"]
    assert qs.reach == "exposed" and qs.via == "express"
    assert qs.severity == "medium"  # high base, -1 only reached through express
    assert any("express" in r for r in qs.severity_reasons)

    assert f["vulnlib"].reach == "installed" and f["vulnlib"].severity == "low"
    assert f["mocha"].reach == "installed"
    assert "Development dependency" in f["mocha"].how_reachable
    for finding in f.values():
        assert finding.title and "GHSA" not in finding.title


def test_served_secret_is_exposed_with_url(repo):
    f = _run(repo)
    secret = next(x for x in f.values() if x.kind == "exposed-secret")
    assert secret.reach == "exposed"
    assert "/public/config.js" in secret.attacker_gets
    assert secret.severity == "critical"


def test_impact_classification_and_symbols():
    assert classify(_adv("A", "p", ["CWE-400", "CWE-94"]))[0] == "rce"
    assert classify(_adv("A", "p", [], "Prototype Pollution in p"))[0] == "prototype-pollution"
    assert classify(_adv("A", "p"))[0] == "info"
    adv = _adv("A", "p", details="Calling `merge()` or `p.unsafe` with `true` in `1.2.3`")
    assert symbol_candidates(adv) == ["merge", "p.unsafe"]


# --------------------------------------------------------------------------- #
# narration grounding
# --------------------------------------------------------------------------- #

class FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **_):
        msg = SimpleNamespace(content=json.dumps(self.payload))
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_model_text_naming_an_off_path_file_falls_back_to_template(repo):
    bad = {"title": "Code injection via routes/upload.js", "attacker_gets": "Runs code in "
           "routes/upload.js handler.", "how_reachable": "Through GET /rest/upload.",
           "cites": ["adv:GHSA-lodash"]}
    f = _run(repo, client=FakeClient(bad), model="m")["lodash"]
    assert f.narrated_by == "template"
    assert "routes/upload.js" not in f.title + f.attacker_gets + f.how_reachable


def test_grounded_model_text_is_kept(repo):
    good = {"title": "Search box runs attacker templates as code",
            "attacker_gets": "Anyone can send a query that lodash compiles and runs on the "
                             "server.",
            "how_reachable": "GET /rest/search hands the query to routes/search.js, which "
                             "passes it to _.template.",
            "cites": ["file:routes/search.js", "adv:GHSA-lodash"]}
    f = _run(repo, client=FakeClient(good), model="m")["lodash"]
    assert f.narrated_by == "model"
    assert f.title == good["title"]


def test_validate_rejects_uncited_and_overclaiming_text():
    step = SimpleNamespace
    finding = SimpleNamespace(
        path=[step(node_id="file:a.js", kind="file", label="a.js", detail="")],
        reach="imported", package="p")
    assert validate({"title": "Fine title here", "cites": []}, finding) == {}
    out = validate({"title": "Reachable without auth from a.js",
                    "attacker_gets": "Gets data via a.js", "cites": ["file:a.js"]}, finding)
    assert "title" not in out and out["attacker_gets"] == "Gets data via a.js"
