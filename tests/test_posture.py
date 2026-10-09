"""Configuration findings from the public-domain knowledge base (no network)."""

from app.intel.posture import posture_findings
from app.recon.kb import KnowledgeBase, Subdomain


def _kb(**sections) -> KnowledgeBase:
    kb = KnowledgeBase(domain="acme.com", run_id="r1", target_id="t1")
    kb.coverage.update({"dns": "ok", "mail": "ok", "website": "ok", "tls": "ok"})
    kb.web.update({"final_url": "https://acme.com/", "security_txt": {"present": True},
                   "security_headers": {"content-security-policy": "present"}})
    kb.dns["caa"] = ["0 issue \"letsencrypt.org\""]
    kb.mail.update({"spf": {"record": "v=spf1 -all", "all": "-all"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "policy": "reject"}})
    kb.infra["tls"] = {"valid": True, "days_left": 80, "issuer": "Let's Encrypt"}
    for name, value in sections.items():
        getattr(kb, name).update(value)
    return kb


def _ids(kb):
    return {h.id: h for h in posture_findings(kb)}


def test_clean_domain_has_no_findings():
    assert _ids(_kb()) == {}


def test_missing_headers_severity_depends_on_which():
    hits = _ids(_kb(web={"security_headers": {
        "content-security-policy": "missing", "x-frame-options": "missing",
        "referrer-policy": "missing"}}))
    h = hits["SW-WEB-HEADERS"]
    assert h.severity == "medium" and "(3)" in h.title and h.fix and h.source == "posture"
    hits = _ids(_kb(web={"security_headers": {"referrer-policy": "missing"}}))
    assert hits["SW-WEB-HEADERS"].severity == "low"


def test_spf_severity_follows_dmarc():
    hits = _ids(_kb(mail={"spf": None}))
    assert hits["SW-MAIL-SPF-MISSING"].severity == "low"
    hits = _ids(_kb(mail={"spf": None, "dmarc": {}}))
    assert hits["SW-MAIL-SPF-MISSING"].severity == "medium"
    assert hits["SW-MAIL-DMARC-MISSING"].severity == "medium"
    hits = _ids(_kb(mail={"spf": {"record": "v=spf1 +all", "all": "+all"}}))
    assert hits["SW-MAIL-SPF-PASSALL"].severity == "high"


def test_dmarc_none_tls_caa_securitytxt_version():
    hits = _ids(_kb(mail={"dmarc": {"record": "v=DMARC1; p=none", "policy": "none"}},
                    infra={"tls": {"valid": True, "days_left": 5, "issuer": "X"}},
                    dns={"caa": []}, web={"security_txt": {"present": False},
                                          "server": "nginx/1.18.0"}))
    assert hits["SW-MAIL-DMARC-NONE"].severity == "low"
    assert hits["SW-TLS-EXPIRY"].severity == "medium"
    assert hits["SW-DNS-CAA"].fix.endswith("(Let's Encrypt).") is False
    assert "SW-WEB-SECURITYTXT" in hits
    assert "nginx/1.18.0" in hits["SW-WEB-VERSION"].detail


def test_mail_rules_skip_when_mail_was_not_collected():
    kb = _kb(mail={"spf": None, "dmarc": {}})
    kb.coverage.pop("mail")
    assert not {"SW-MAIL-SPF-MISSING", "SW-MAIL-DMARC-MISSING"} & set(_ids(kb))


def test_sensitive_subdomains_need_to_resolve():
    kb = _kb()
    kb.subdomains = [
        Subdomain(name="vpn.acme.com", interesting="remote access (vpn)", ips=["1.2.3.4"]),
        Subdomain(name="staging.acme.com", interesting="non-prod (staging)", ips=[]),
    ]
    h = _ids(kb)["SW-SURFACE-SENSITIVE"]
    assert h.severity == "medium" and "vpn.acme.com" in h.detail
    assert "staging" not in h.detail
