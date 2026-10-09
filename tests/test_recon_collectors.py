"""Recon collector parsers and scope guards (no network)."""

from pathlib import Path

import pytest

from app.recon import ct, dns_records, website
from app.recon.domain import in_scope, normalize_domain, registrable
from app.recon.kb import FetchedPage, KnowledgeBase

FIXTURES = Path(__file__).parent / "fixtures" / "recon"


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  HTTPS://Example.COM:8443/about?x=1  ", "example.com"),
    ("http://user:pw@www.example.co.uk/", "www.example.co.uk"),
    ("example.com.", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_normalize_domain_accepts(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "intranet", "10.0.0.1", "http://[::1]/", "printer.local",
    "db.internal", "-bad-.com", "a" * 64 + ".com", "under_score.com", "example.123",
])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_registrable_and_scope():
    assert registrable("www.shop.example.co.uk") == "example.co.uk"
    assert registrable("api.example.com") == "example.com"
    assert in_scope("example.com", "example.com")
    assert in_scope("vpn.EXAMPLE.com.", "example.com")
    assert not in_scope("badexample.com", "example.com")
    assert not in_scope("example.com.evil.io", "example.com")
    assert not in_scope(None, "example.com")


def test_parse_spf():
    spf = dns_records.parse_spf([
        "google-site-verification=abc",
        "v=spf1 include:_spf.google.com include:sendgrid.net ip4:1.2.3.4 ~all",
    ])
    assert spf["all"] == "~all"
    assert spf["includes"] == ["_spf.google.com", "sendgrid.net"]
    assert spf["providers"] == ["Google Workspace", "SendGrid"]
    assert spf["ip_mechanisms"] == 1
    assert dns_records.parse_spf(["v=spf1 +all"])["all"] == "+all"
    assert dns_records.parse_spf(["nothing here"]) is None


def test_parse_dmarc():
    record = "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.com,mailto:b@y.com"
    d = dns_records.parse_dmarc([record])
    assert d["policy"] == "quarantine"
    assert d["subdomain_policy"] == "reject"
    assert d["pct"] == 50
    assert d["rua"] == ["mailto:a@x.com", "mailto:b@y.com"]
    assert dns_records.parse_dmarc(["v=spf1 -all"]) is None


def test_mx_parsing_and_provider():
    mx = dns_records.parse_mx(["10 alt1.aspmx.l.google.com.", "1 aspmx.l.google.com."])
    assert mx[0] == {"priority": 1, "host": "aspmx.l.google.com"}
    assert dns_records.mx_provider([m["host"] for m in mx]) == "Google Workspace"
    assert dns_records.mx_provider(["acme-com.mail.protection.outlook.com"]) == "Microsoft 365"
    assert dns_records.mx_provider(["mx1.acme-com.pphosted.com"]) == "Proofpoint"
    assert dns_records.mx_provider(["mail.acme.example"]) is None


def test_txt_verifications_and_cymru():
    vendors = dns_records.txt_verifications([
        "MS=ms123", "atlassian-domain-verification=x", "v=spf1 -all",
    ])
    assert vendors == ["Microsoft 365", "Atlassian"]
    assert dns_records.parse_cymru_origin("13335 | 104.16.0.0/13 | US | arin | 2014-03-28") == {
        "asn": "13335", "prefix": "104.16.0.0/13", "country": "US"}
    assert dns_records.parse_cymru_asname(
        "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US") == "CLOUDFLARENET, US"
    assert dns_records.hosting_from_org("AMAZON-02, US") == "AWS"


def test_subdomain_flagging_and_cleaning():
    d = "acme.example"
    assert ct.flag_interesting("vpn.acme.example", d) == "remote access"
    assert ct.flag_interesting("owa-eu.acme.example", d) == "mail edge"
    assert ct.flag_interesting("jenkins.build.acme.example", d) == "dev tooling"
    assert ct.flag_interesting("staging-api.acme.example", d) == "non-production"
    assert ct.flag_interesting("contest.acme.example", d) is None
    names = ct.clean_names(
        ["*.acme.example", "www.acme.example\nvpn.acme.example", "acme.example",
         "evil.com", "WWW.ACME.EXAMPLE.", "x@acme.example"], d)
    assert names == ["vpn.acme.example", "www.acme.example"]


def test_company_and_web_extraction():
    html = (FIXTURES / "acme_home.html").read_text()
    parsed = website.parse_html(html)
    assert parsed.title == "Home | Acme Widgets"
    org = website.extract_jsonld_org(parsed.jsonld)
    assert org["name"] == "Acme Widgets"
    assert org["legal_name"] == "Acme Widgets, Inc."
    assert org["location"] == "1 Main St, Austin, TX, US"
    assert org["logo"] == "https://acme.example/logo.png"
    assert org["employees"] == "250"
    assert org["site_name"] == "Acme Widgets Site"

    assert website.clean_title_name("Home | Acme Widgets", "acme.example") == "Acme Widgets"
    assert website.clean_title_name("Welcome - Globex", "initech.com") == "Globex"

    socials = website.extract_socials(parsed.anchors + org["same_as"])
    assert set(socials) == {"github", "linkedin", "x"}
    emails = website.extract_emails(html, parsed.anchors, "acme.example")
    assert emails == ["sales@acme.example", "security@acme.example"]
    assert website.extract_phones(parsed.anchors) == ["+1 (512) 555-0100"]

    page = FetchedPage(url="https://acme.example/", final_url="https://acme.example/",
                       host="acme.example", status=200,
                       headers={"server": "nginx/1.18.0", "x-frame-options": "DENY"},
                       html=html)
    web = website.extract_web(page, parsed, "acme.example")
    assert web["generator"] == "WordPress 6.4.2"
    assert web["server"] == "nginx/1.18.0"
    assert web["security_headers"]["x-frame-options"] == "present"
    assert web["security_headers"]["content-security-policy"] == "missing"
    assert "www.googletagmanager.com" in web["external_hosts"]
    assert "not text" not in website.page_text(html)


def test_robots_and_security_txt():
    robots = website.parse_robots("User-agent: *\nDisallow: /wp-admin/\nDisallow: \n"
                                  "Sitemap: https://acme.example/sitemap.xml\n")
    assert robots["disallow"] == ["/wp-admin/"]
    assert robots["sitemaps"] == ["https://acme.example/sitemap.xml"]
    assert website.parse_robots("<html>soft 404</html>") is None
    sec = website.parse_security_txt("Contact: mailto:security@acme.example\n"
                                     "Expires: 2027-01-01T00:00:00Z\n")
    assert sec["contact"] == ["mailto:security@acme.example"]
    assert website.parse_security_txt("<html>not found</html>") is None
    assert website.cookie_names(["sid=abc; Path=/", "cf_bm=x; HttpOnly", "sid=def"]) == [
        "sid", "cf_bm"]


def test_fetch_in_scope_refuses_off_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(website, "fetch_page", lambda url, *a, **kw: calls.append(url))
    kb = KnowledgeBase(domain="acme.example", run_id="r", target_id="t")

    def emit(*a):
        return None

    for bad in ["https://evil.com/", "file:///etc/passwd", "ftp://acme.example/",
                "https://acme.example.evil.com/", "http://acme.example:8080/", ""]:
        assert website.fetch_in_scope(kb, bad, emit) is None
    assert calls == []
    website.fetch_in_scope(kb, "/about", emit)
    website.fetch_in_scope(kb, "blog.acme.example/post", emit)
    assert calls == ["https://acme.example/about", "https://blog.acme.example/post"]
