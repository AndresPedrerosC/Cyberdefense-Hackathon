"""Unit tests for the discovery pillar: repo parsing, aliases, public gating, SSRF guard."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import app.config as config
from app.discovery import discover
from app.discovery import net, public
from app.discovery import repo as repo_mod
from app.discovery.aliases import resolve_alias
from app.discovery.repo import _extract_package_name, discover_repo
from app.schema import Target

RUN = "run1"


@pytest.fixture
def emit():
    return MagicMock()


@pytest.fixture
def repo_root(tmp_path, monkeypatch):
    root = tmp_path / "repos"
    root.mkdir()
    monkeypatch.setattr(config, "ALLOWED_REPO_ROOTS", [root.resolve()])
    return root


def mk_target(kind="connected_repo", repo=None, domain=None, tid="t_disc"):
    return Target(target_id=tid, kind=kind, name="n", repo=repo, domain=domain)


def write_repo(path, pkg, lock=None):
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(json.dumps(pkg))
    if lock is not None:
        (path / "package-lock.json").write_text(json.dumps(lock))
    return path


def by_pkg(items):
    return {(i.package, i.version): i for i in items}


# Aliases

@pytest.mark.parametrize("name,pkg", [
    ("React", "react"), ("  react.js ", "react"), ("Angular", "@angular/core"),
    ("@angular/core", "@angular/core"), ("Next.js", "next"), ("babel", "@babel/core"),
    ("left-pad", None), ("", None), (None, None),
])
def test_resolve_alias(name, pkg):
    assert resolve_alias(name) == pkg


# Repo discovery

def test_v3_lockfile_parsing_direct_vs_transitive(repo_root, emit):
    r = write_repo(repo_root / "app", {"dependencies": {"express": "^4.17.0"},
                                        "devDependencies": {"@types/node": "*"}}, {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/express": {"version": "4.17.1"},
            "node_modules/@types/node": {"version": "20.1.0"},
            "node_modules/qs": {"version": "6.7.0"},
            "node_modules/express/node_modules/qs": {"version": "6.5.0"},
            "node_modules/linked": {"link": True},
        },
    })
    items = by_pkg(discover_repo(mk_target(repo=str(r)), RUN, emit))
    assert set(items) == {("express", "4.17.1"), ("@types/node", "20.1.0"),
                          ("qs", "6.7.0"), ("qs", "6.5.0")}
    assert items[("express", "4.17.1")].direct is True
    assert items[("express", "4.17.1")].declared_range == "^4.17.0"
    assert items[("@types/node", "20.1.0")].direct is True
    assert items[("qs", "6.5.0")].direct is False
    assert items[("qs", "6.5.0")].declared_range is None
    assert all(i.status == "confirmed" and i.confidence == "high" for i in items.values())


def test_duplicate_package_versions_are_deduplicated(repo_root, emit):
    r = write_repo(repo_root / "dup", {"dependencies": {}}, {
        "lockfileVersion": 2,
        "packages": {
            "node_modules/a/node_modules/ms": {"version": "2.1.2"},
            "node_modules/b/node_modules/ms": {"version": "2.1.2"},
        },
    })
    items = discover_repo(mk_target(repo=str(r)), RUN, emit)
    assert [(i.package, i.version) for i in items] == [("ms", "2.1.2")]


def test_v1_lockfile_nested_dependencies(repo_root, emit):
    r = write_repo(repo_root / "v1", {"dependencies": {"a": "1.x"}}, {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "noversion": {},
        },
    })
    items = by_pkg(discover_repo(mk_target(repo=str(r)), RUN, emit))
    assert set(items) == {("a", "1.0.0"), ("b", "2.0.0")}
    assert items[("a", "1.0.0")].direct and not items[("b", "2.0.0")].direct


def test_missing_package_json_yields_nothing(repo_root, emit):
    (repo_root / "empty").mkdir()
    assert discover_repo(mk_target(repo=str(repo_root / "empty")), RUN, emit) == []
    assert any("No package.json" in c.args[2] for c in emit.call_args_list)


def test_nonexistent_repo_inside_root(repo_root, emit):
    assert discover_repo(mk_target(repo=str(repo_root / "ghost")), RUN, emit) == []


def test_no_lockfile_and_npm_fails_falls_back_to_direct_deps(repo_root, emit):
    r = write_repo(repo_root / "nolock", {"dependencies": {"lodash": "^4.17.0"}})
    failed = subprocess.CompletedProcess([], 1, stdout="", stderr="E404")
    with patch.object(repo_mod.subprocess, "run", return_value=failed) as run:
        items = discover_repo(mk_target(repo=str(r)), RUN, emit)
    cmd = run.call_args.args[0]
    assert "--ignore-scripts" in cmd and "--package-lock-only" in cmd
    assert run.call_args.kwargs["cwd"] != r  # runs on a temp copy, never in place
    (item,) = items
    assert item.package == "lodash" and item.version is None
    assert item.declared_range == "^4.17.0" and item.confidence == "medium"


def test_npm_missing_falls_back_to_direct_deps(repo_root, emit):
    r = write_repo(repo_root / "nonpm", {"dependencies": {"axios": "1.0.0"}})
    with patch.object(repo_mod.subprocess, "run", side_effect=FileNotFoundError):
        items = discover_repo(mk_target(repo=str(r)), RUN, emit)
    assert [i.package for i in items] == ["axios"]


# Repo path confinement (SECURITY_AUDIT H-2)

@pytest.mark.parametrize("bad", ["/etc", "/", "../../..", "repos/../../outside"])
def test_repo_outside_allowed_roots_is_never_read(repo_root, emit, bad):
    with patch.object(repo_mod, "open", create=True) as op, \
         patch.object(repo_mod.shutil, "copytree") as ct, \
         patch.object(repo_mod.subprocess, "run") as run:
        assert discover_repo(mk_target(repo=bad), RUN, emit) == []
    op.assert_not_called()
    ct.assert_not_called()
    run.assert_not_called()
    assert emit.call_args.args[1] == "error"


def test_symlink_escaping_allowed_root_is_refused(repo_root, tmp_path, emit):
    outside = write_repo(tmp_path / "secret", {"dependencies": {"x": "1"}},
                         {"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}})
    (repo_root / "sneaky").symlink_to(outside, target_is_directory=True)
    assert discover_repo(mk_target(repo=str(repo_root / "sneaky")), RUN, emit) == []


def test_nul_byte_repo_path_is_refused(repo_root, emit):
    assert config.is_repo_path_allowed(str(repo_root) + "/a\x00b") is False


def test_relative_repo_resolves_against_project_root_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert config.resolve_repo_path("demo/juice-shop") == (
        config.PROJECT_ROOT / "demo" / "juice-shop").resolve()


@pytest.mark.parametrize("key,name", [
    ("node_modules/lodash", "lodash"),
    ("node_modules/@babel/core", "@babel/core"),
    ("node_modules/a/node_modules/@scope/b", "@scope/b"),
    ("packages/workspace-a", None),
    ("", None),
])
def test_extract_package_name(key, name):
    assert _extract_package_name(key) == name


# Routing and public-target gating

def test_discover_routes_by_kind(emit):
    with patch("app.discovery.discover_repo", return_value=[]) as dr, \
         patch("app.discovery.discover_public", return_value=[]) as dp:
        discover(mk_target("connected_repo", repo="x"), RUN, emit)
        discover(mk_target("owned_deployment", repo="x"), RUN, emit)
        discover(mk_target("public", domain="example.com"), RUN, emit)
        discover(mk_target("public", repo="/etc"), RUN, emit)  # public never reads repos
        discover(mk_target("connected_repo"), RUN, emit)      # no repo -> nothing
    assert dr.call_count == 2
    assert dp.call_count == 1


def test_public_discovery_only_fetches_https_pages_of_its_domain(emit):
    html = '<div data-reactroot></div><script id="__NEXT_DATA__"></script>' \
           '<app ng-version="12.1.0"></app><p data-v-1a2b3c></p>' \
           '<script src="/js/jquery-3.4.1.min.js"></script>'
    seen = []

    def fake_fetch(url, tid, _emit):
        seen.append(url)
        return (html, {"x-powered-by": "Express"}) if url.endswith(".com/") else (None, {})

    with patch.object(public, "safe_fetch", side_effect=fake_fetch):
        items = public.discover_public(mk_target("public", domain="example.com"), RUN, emit)
    assert seen == ["https://example.com/", "https://example.com/about",
                    "https://example.com/careers"]
    found = {(i.package, i.version) for i in items}
    assert found == {("express", None), ("next", None), ("react", None),
                     ("@angular/core", "12.1.0"), ("vue", None), ("jquery", "3.4.1")}
    assert all(i.status == "inferred" and not i.direct for i in items)


def test_public_discovery_dedupes_across_pages(emit):
    with patch.object(public, "safe_fetch",
                      return_value=('<div data-reactroot></div>', {})):
        items = public.discover_public(mk_target("public", domain="example.com"), RUN, emit)
    assert [i.package for i in items] == ["react"]


@pytest.mark.parametrize("header,expected", [
    ("Express", ("Express", None)), ("Next.js 13", ("Next.js", None)),
    ("PHP/8.1", (None, None)), ("ASP.NET", ("asp.net", None)),
])
def test_parse_powered_by(header, expected):
    assert public._parse_powered_by(header) == expected


# SSRF guard (net.safe_fetch)

@pytest.mark.parametrize("ip,blocked", [
    ("127.0.0.1", True), ("10.1.2.3", True), ("172.16.5.5", True), ("192.168.0.1", True),
    ("169.254.169.254", True), ("100.64.0.1", True), ("0.0.0.0", True), ("224.0.0.1", True),
    ("::1", True), ("::ffff:127.0.0.1", True), ("fe80::1%en0", True), ("fd00::1", True),
    ("not-an-ip", True), ("93.184.216.34", False), ("2606:2800:220:1::", False),
])
def test_is_private_ip(ip, blocked):
    assert net.is_private_ip(ip) is blocked


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "gopher://example.com/", "ftp://example.com/", "http:///nohost",
])
def test_check_url_rejects_non_http_and_hostless(url):
    with patch.object(net, "resolve_and_check", return_value="93.184.216.34"):
        assert net._check_url(url) is not None


def test_hostname_with_any_private_record_is_blocked():
    infos = [(None, None, None, None, ("93.184.216.34", 0)),
             (None, None, None, None, ("127.0.0.1", 0))]
    with patch.object(net.socket, "getaddrinfo", return_value=infos):
        assert net.resolve_and_check("rebind.example") is None


def test_blocked_domain_never_opens_a_connection(tmp_path, monkeypatch, emit):
    monkeypatch.chdir(tmp_path)
    with patch.object(net, "resolve_and_check", return_value=None), \
         patch.object(net.httpx, "Client") as client:
        assert net.safe_fetch("https://internal.corp/", "t_x", emit) == (None, {})
    client.assert_not_called()


def test_redirect_to_private_address_is_blocked(tmp_path, monkeypatch, emit):
    monkeypatch.chdir(tmp_path)
    resp = MagicMock(is_redirect=True, headers={"location": "http://169.254.169.254/latest"})
    resp.url.join.return_value = "http://169.254.169.254/latest"
    stream_cm = MagicMock()
    stream_cm.__enter__.return_value = resp
    client = MagicMock()
    client.__enter__.return_value = client
    client.stream.return_value = stream_cm

    def resolve(host):
        return None if host == "169.254.169.254" else "93.184.216.34"

    with patch.object(net, "resolve_and_check", side_effect=resolve), \
         patch.object(net.httpx, "Client", return_value=client) as ctor:
        assert net.safe_fetch("https://example.com/", "t_x", emit) == (None, {})
    assert ctor.call_args.kwargs["follow_redirects"] is False
    assert client.stream.call_count == 1
    assert any("Blocked redirect" in c.args[2] for c in emit.call_args_list)
