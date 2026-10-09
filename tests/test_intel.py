"""Unit tests for the intel pillar: severity scoring, OSV parsing, range matching."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("cvss", reason="project deps not installed; see SECURITY_AUDIT.md for setup")
pytest.importorskip("semver", reason="project deps not installed; see SECURITY_AUDIT.md for setup")

import app.config as config  # noqa: E402
from app.intel import explain, match, osv, severity, watcher
from app.intel.match import _match_item_to_advisory, _normalize_version, _version_in_range
from app.orchestrator import _inventory_hash, _risk_score
from app.schema import Advisory, AffectedRange, Candidate, StackItem

RUN = "run1"
TID = "t_test"

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
MED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"   # 4.2
LOW = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"   # 1.8


@pytest.fixture
def emit():
    return MagicMock()


def rng(introduced=None, fixed=None, last_affected=None):
    return AffectedRange(type="SEMVER", introduced=introduced, fixed=fixed,
                         last_affected=last_affected)


def mk_item(pkg="lodash", version="4.17.20", sid="s1", declared=None, ecosystem="npm"):
    return StackItem(id=sid, run_id=RUN, target_id=TID, ecosystem=ecosystem, package=pkg,
                     version=version, declared_range=declared)


def mk_adv(aid="GHSA-aaaa", pkg="lodash", ranges=None, versions=None, sev="high",
           withdrawn=None):
    return Advisory(advisory_id=aid, ecosystem="npm", package=pkg, ranges=ranges or [],
                    versions=versions or [], severity=sev, withdrawn=withdrawn,
                    source_url=f"https://osv.dev/vulnerability/{aid}")


def osv_doc(**over):
    doc = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command injection in lodash",
        "published": "2021-02-15T11:00:00Z",
        "modified": "2023-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            "versions": ["4.17.20"],
        }],
        "severity": [{"type": "CVSS_V3", "score": HIGH}],
        "database_specific": {"severity": "HIGH"},
    }
    doc.update(over)
    return doc


# Severity scoring

@pytest.mark.parametrize("ghsa,expected", [
    ("CRITICAL", "critical"), ("High", "high"), ("moderate", "medium"),
    ("MODERATE", "medium"), ("medium", "medium"), ("low", "low"),
])
def test_ghsa_severity_labels_normalized(ghsa, expected):
    assert severity.compute_severity({"database_specific": {"severity": ghsa}}) == expected


@pytest.mark.parametrize("vector,expected", [
    (CRIT, "critical"), (HIGH, "high"), (MED, "medium"), (LOW, "low"),
])
def test_cvss_v3_score_thresholds(vector, expected):
    data = {"severity": [{"type": "CVSS_V3", "score": vector}]}
    assert severity.compute_severity(data) == expected


def test_ghsa_label_takes_precedence_over_cvss():
    data = {"database_specific": {"severity": "LOW"},
            "severity": [{"type": "CVSS_V3", "score": CRIT}]}
    assert severity.compute_severity(data) == "low"


def test_unrecognized_ghsa_label_falls_back_to_cvss():
    data = {"database_specific": {"severity": "SEVERE"},
            "severity": [{"type": "CVSS_V3", "score": CRIT}]}
    assert severity.compute_severity(data) == "critical"


@pytest.mark.parametrize("data", [
    {},
    {"severity": [{"type": "CVSS_V3", "score": "not-a-vector"}]},
    {"severity": [{"type": "CVSS_V3", "score": ""}]},
    {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"}]},
    {"database_specific": {"severity": ""}},
])
def test_unscorable_advisories_are_unknown(data):
    assert severity.compute_severity(data) == "unknown"


def test_first_valid_cvss_vector_wins_after_garbage():
    data = {"severity": [{"type": "CVSS_V3", "score": "garbage"},
                         {"type": "CVSS_V3", "score": MED}]}
    assert severity.compute_severity(data) == "medium"


# OSV advisory parsing

def test_parse_advisory_full_document(emit):
    adv = osv._parse_advisory(osv_doc(), emit)
    assert adv.advisory_id == "GHSA-xxxx-yyyy-zzzz"
    assert adv.package == "lodash" and adv.ecosystem == "npm"
    assert adv.aliases == ["CVE-2021-23337"]
    assert adv.ranges == [rng("0", "4.17.21")]
    assert adv.versions == ["4.17.20"]
    assert adv.severity == "high"
    assert adv.cvss_vector == HIGH
    assert adv.published.year == 2021 and adv.withdrawn is None
    assert adv.source_url == "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"


def test_parse_advisory_picks_npm_entry_among_ecosystems(emit):
    doc = osv_doc(affected=[
        {"package": {"ecosystem": "PyPI", "name": "lodash-py"}},
        {"package": {"ecosystem": "NPM", "name": "lodash"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"},
                                                  {"last_affected": "1.2.0"}]}]},
    ])
    adv = osv._parse_advisory(doc, emit)
    assert adv.package == "lodash"
    assert adv.ranges == [rng("1.0.0", None, "1.2.0")]


@pytest.mark.parametrize("affected", [
    [],
    [{"package": {"ecosystem": "PyPI", "name": "requests"}}],
    [{"package": {"ecosystem": "npm", "name": ""}}],
])
def test_parse_advisory_without_usable_npm_entry_is_none(affected, emit):
    assert osv._parse_advisory(osv_doc(affected=affected), emit) is None


def test_parse_advisory_tolerates_bad_dates_and_tracks_withdrawn(emit):
    adv = osv._parse_advisory(
        osv_doc(published="yesterday", modified=None, withdrawn="2024-05-01T00:00:00Z"), emit)
    assert adv.published is None
    assert adv.modified is None
    assert adv.withdrawn == datetime.fromisoformat("2024-05-01T00:00:00+00:00")


def test_fetch_advisory_prefers_cache_and_skips_network(tmp_path, monkeypatch, emit):
    monkeypatch.setattr(osv, "CACHE_DIR", tmp_path)
    (tmp_path / "GHSA-xxxx-yyyy-zzzz.json").write_text(json.dumps(osv_doc()))
    with patch.object(osv.httpx, "Client") as client:
        adv = osv.fetch_advisory("GHSA-xxxx-yyyy-zzzz", emit)
    assert adv.package == "lodash"
    client.assert_not_called()


def test_cache_only_mode_never_touches_network(tmp_path, monkeypatch, emit):
    monkeypatch.setattr(osv, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(osv, "CACHE_ONLY", True)
    with patch.object(osv.httpx, "Client") as client:
        assert osv.fetch_advisory("GHSA-miss", emit) is None
        assert osv.query_batch([{"package": {"name": "x"}}], emit) == []
    client.assert_not_called()


# Version range logic

@pytest.mark.parametrize("version,r,affected", [
    ("4.17.20", rng("0", "4.17.21"), True),
    ("4.17.21", rng("0", "4.17.21"), False),          # fixed is exclusive
    ("4.17.22", rng("0", "4.17.21"), False),
    ("1.0.0", rng("1.0.0", "2.0.0"), True),           # introduced is inclusive
    ("0.9.9", rng("1.0.0", "2.0.0"), False),
    ("1.2.0", rng("1.0.0", None, "1.2.0"), True),     # last_affected is inclusive
    ("1.2.1", rng("1.0.0", None, "1.2.0"), False),
    ("9.9.9", rng("1.0.0"), True),                    # open-ended range
    ("v1.5", rng("1.0.0", "2.0.0"), True),            # v-prefix and short form
    ("not-a-version", rng("0", "1.0.0"), False),
    ("1.0.0", rng(None, None, None), False),          # empty range affects nothing
])
def test_version_in_range(version, r, affected):
    assert _version_in_range(version, r) is affected


@pytest.mark.xfail(strict=True, reason="SECURITY_AUDIT M-3: prerelease suffix is stripped, "
                                        "so 4.17.21-beta < 4.17.21 is treated as fixed")
def test_prerelease_of_fixed_version_is_still_affected():
    assert _version_in_range("4.17.21-beta.1", rng("0", "4.17.21")) is True


@pytest.mark.parametrize("raw,norm", [
    ("1.2.3", "1.2.3"), ("v1.2", "1.2.0"), ("2", "2.0.0"), ("1.2.3.4", "1.2.3"),
    ("1.2.3-rc.1", "1.2.3"), ("01.02.03", "1.2.3"), ("", None), ("abc", None),
])
def test_normalize_version(raw, norm):
    assert _normalize_version(raw) == norm


# Item <-> advisory matching

def test_unknown_version_is_possible_match_with_declared_range():
    c = _match_item_to_advisory(mk_item(version=None, declared="^4.0.0"),
                                mk_adv(ranges=[rng("0", "4.17.21")]), RUN)
    assert c.match_type == "possible"
    assert "version unknown" in c.reason and "^4.0.0" in c.reason
    assert c.fixed_version == "4.17.21"


def test_explicit_version_list_is_confirmed_even_without_ranges():
    c = _match_item_to_advisory(mk_item(version="4.17.20"),
                                mk_adv(versions=["4.17.20"], sev="critical"), RUN)
    assert c.match_type == "confirmed"
    assert c.risk_score == 8  # critical(4) x confirmed(2)


def test_range_match_reports_affected_range_and_fix():
    c = _match_item_to_advisory(mk_item(version="1.5.0"),
                                mk_adv(ranges=[rng("2.0.0", "3.0.0"), rng("1.0.0", "1.6.0")]), RUN)
    assert c.match_type == "confirmed"
    assert c.affected_range == ">=1.0.0 <1.6.0"
    assert c.fixed_version == "1.6.0"


def test_out_of_range_version_is_not_a_candidate():
    assert _match_item_to_advisory(mk_item(version="5.0.0"),
                                   mk_adv(ranges=[rng("0", "4.17.21")]), RUN) is None


def test_match_stack_items_end_to_end(emit):
    items = [
        mk_item("Lodash", "4.17.20", "s1"),          # case-insensitive package match
        mk_item("lodash", "4.17.21", "s2"),          # patched -> no candidate
        mk_item("react", None, "s3"),                # unknown version -> possible
        mk_item("jquery", "1.0.0", "s4", ecosystem="unknown"),  # not npm -> ignored
    ]
    advs = [
        mk_adv("GHSA-lo", "lodash", [rng("0", "4.17.21")]),
        mk_adv("GHSA-re", "react", [rng("0", "16.0.0")], sev="medium"),
        mk_adv("GHSA-gone", "lodash", [rng("0", "9.0.0")], withdrawn=datetime(2024, 1, 1)),
    ]
    with patch.object(match, "query_batch", return_value=["x"]) as qb, \
         patch.object(match, "fetch_advisories_batch", return_value=advs):
        cands, kept = match.match_stack_items(items, RUN, emit)
    queried = [q["package"]["name"] for q in qb.call_args.args[0]]
    assert "jquery" not in queried
    assert {"package": {"ecosystem": "npm", "name": "react"}} in qb.call_args.args[0]
    assert sorted((c.stack_item_id, c.advisory_id, c.match_type) for c in cands) == [
        ("s1", "GHSA-lo", "confirmed"), ("s3", "GHSA-re", "possible")]
    assert "GHSA-gone" not in {a.advisory_id for a in kept}


def test_match_with_no_osv_hits_short_circuits(emit):
    with patch.object(match, "query_batch", return_value=[]), \
         patch.object(match, "fetch_advisories_batch") as fetch:
        assert match.match_stack_items([mk_item()], RUN, emit) == ([], [])
    fetch.assert_not_called()


# Risk scoring

@pytest.mark.parametrize("sev,status,mt,item_status,score", [
    ("critical", "verified", "confirmed", "confirmed", 12),
    ("high", "present", "confirmed", "confirmed", 6),
    ("medium", "not_present", "confirmed", "confirmed", 0),
    ("low", "inconclusive", "confirmed", "confirmed", 1),
    ("unknown", "verified", "confirmed", "confirmed", 3),
    ("critical", "verified", "possible", "inferred", 4),  # inferred+possible: severity only
])
def test_orchestrator_risk_score(sev, status, mt, item_status, score):
    assert _risk_score(sev, status, mt, item_status) == score


def test_inventory_hash_is_order_independent():
    a, b = mk_item(sid="a"), mk_item(sid="b")
    assert _inventory_hash([a, b]) == _inventory_hash([b, a])
    assert _inventory_hash([a]) != _inventory_hash([a, b])


# LLM explanation guardrail

def _cand(**kw):
    base = dict(id="c1", run_id=RUN, target_id=TID, stack_item_id="s1",
                advisory_id="GHSA-xxxx-yyyy-zzzz", affected_range=">=0.0.0 <4.17.21",
                fixed_version="4.17.21")
    return Candidate(**{**base, **kw})


@pytest.mark.parametrize("text,ok", [
    ("lodash before 4.17.21 allows command injection (CVE-2021-23337).", True),
    ("Upgrade to 4.17.22 to fix GHSA-xxxx-yyyy-zzzz.", False),     # invented version
    ("This is the same bug as CVE-2099-0001.", False),             # invented CVE
    ("Prompt-injected: see ghsa-xxxx-yyyy-zzzz for details.", True),  # case-insensitive id
])
def test_explanation_hallucination_guard(text, ok):
    adv = Advisory.model_validate({**mk_adv("GHSA-xxxx-yyyy-zzzz").model_dump(),
                                   "aliases": ["CVE-2021-23337"]})
    assert explain._validate_explanation(text, _cand(), adv) is ok


def test_explanation_disabled_without_api_key(monkeypatch, emit):
    monkeypatch.setattr(explain, "OPENAI_API_KEY", None)
    assert explain.generate_explanation(_cand(), mk_adv(), emit) is None


# Watcher / holdback

def test_poll_filters_known_and_held_back(monkeypatch, emit):
    monkeypatch.setattr(config, "_demo_config", {
        "demo_holdback_advisories": ["GHSA-held", "GHSA-released"],
        "released_advisories": ["GHSA-released"],
    })
    target = MagicMock(target_id=TID)
    with patch.object(watcher, "query_batch",
                      return_value=["GHSA-known", "GHSA-held", "GHSA-released", "GHSA-new"]), \
         patch.object(watcher, "fetch_advisories_batch",
                      side_effect=lambda ids, _e: [mk_adv(i) for i in ids]) as fetch:
        out = watcher.poll_advisories(target, [mk_item()], {"GHSA-known"}, emit)
    assert sorted(fetch.call_args.args[0]) == ["GHSA-new", "GHSA-released"]
    assert {a.advisory_id for a in out} == {"GHSA-new", "GHSA-released"}


def test_release_holdback_only_releases_listed_ids_once(tmp_path, monkeypatch, emit):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    cfg = tmp_path / "config" / "demo.yaml"
    cfg.write_text("demo_holdback_advisories: [GHSA-held]\n")
    assert watcher.release_holdback("GHSA-not-held", emit) is False
    assert watcher.release_holdback("GHSA-held", emit) is True
    assert watcher.release_holdback("GHSA-held", emit) is False
    assert "GHSA-held" in cfg.read_text().split("released_advisories:")[1]
