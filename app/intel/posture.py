"""Configuration findings derived from the public-domain knowledge base.

Every rule reads evidence recon already collected passively (response headers, DNS, mail
records, the TLS certificate, certificate-transparency names) and states what was observed,
why it matters and how to fix it. Severity reflects context: a missing SPF record matters less
when DMARC already rejects unauthenticated mail.
"""

from app.recon.kb import IntelHit, KnowledgeBase

HEADER_LABEL = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
# Subdomain flags from app/recon/ct.py that are worth a finding when they resolve publicly.
SENSITIVE_FLAGS = ("remote access", "admin", "dev tooling", "non-prod", "identity", "mail edge")


def posture_findings(kb: KnowledgeBase) -> list[IntelHit]:
    hits: list[IntelHit] = []
    site = kb.web.get("final_url") or f"https://{kb.domain}/"
    for rule in (_headers, _server_version, _spf, _dmarc, _tls, _caa, _security_txt,
                 _subdomains):
        hit = rule(kb, site)
        if hit:
            hits.append(hit)
    return hits


def _hit(rule: str, area: str, severity: str, title: str, detail: str, fix: str,
         evidence: str, url: str) -> IntelHit:
    return IntelHit(source="posture", id=rule, title=title, tech=area, severity=severity,
                    match="confirmed", url=url, detail=detail, fix=fix, evidence=evidence)


def _headers(kb: KnowledgeBase, site: str) -> IntelHit | None:
    sh = kb.web.get("security_headers") or {}
    missing = [h for h, v in sh.items() if v != "present"]
    if not missing:
        return None
    names = [HEADER_LABEL.get(h, h) for h in missing]
    key = {"content-security-policy", "x-frame-options", "strict-transport-security"}
    severity = "medium" if len(key & set(missing)) >= 2 else "low"
    return _hit(
        "SW-WEB-HEADERS", "website", severity,
        f"Missing browser security headers ({len(missing)})",
        f"The home page does not send {', '.join(names)}. These headers tell browsers to block "
        "clickjacking, MIME sniffing and injected scripts, and to stay on HTTPS.",
        "Set the missing headers at the CDN or web server, starting with "
        "Content-Security-Policy and X-Frame-Options (or CSP frame-ancestors).",
        "Response headers of " + site + ": " + ", ".join(names) + " absent", site)


def _server_version(kb: KnowledgeBase, site: str) -> IntelHit | None:
    banner = " ".join(str(kb.web.get(k) or "") for k in ("server", "powered_by")).strip()
    if not any(ch.isdigit() for ch in banner) or "/" not in banner:
        return None
    return _hit(
        "SW-WEB-VERSION", "website", "low", "Server software version is disclosed",
        f"Response headers advertise '{banner}'. Exact versions let an attacker match the "
        "server to known vulnerabilities without probing it.",
        "Remove version details from the Server and X-Powered-By headers.",
        f"Server/X-Powered-By: {banner}", site)


def _spf(kb: KnowledgeBase, site: str) -> IntelHit | None:
    if not kb.coverage.get("mail"):
        return None
    spf = kb.mail.get("spf") or {}
    dmarc_policy = (kb.mail.get("dmarc") or {}).get("policy")
    record = spf.get("record")
    qualifier = spf.get("all")
    if record and qualifier == "+all":
        return _hit(
            "SW-MAIL-SPF-PASSALL", "email", "high", "SPF authorizes every sender (+all)",
            f"The SPF record ends in +all, so any server on the internet passes SPF when "
            f"sending as {kb.domain}.",
            "Replace +all with -all after listing the real senders.",
            f"TXT {kb.domain}: {record}", f"dns:TXT {kb.domain}")
    if record:
        return None
    sends_mail = bool(kb.mail.get("mx_hosts") or kb.dns.get("mx"))
    severity = "low" if dmarc_policy in ("reject", "quarantine") else "medium"
    why = ("DMARC is set to reject, which limits the damage, but receivers that do not "
           "enforce DMARC can still be fooled." if severity == "low" else
           "Without SPF or an enforcing DMARC policy, mail spoofing this domain is likely to "
           "be delivered.")
    return _hit(
        "SW-MAIL-SPF-MISSING", "email", severity, "No SPF record",
        f"{kb.domain} publishes no SPF record, so receivers cannot tell which servers may send "
        f"its mail. {why}",
        "Publish SPF listing the real senders" + ("" if sends_mail else
                                                   ", or 'v=spf1 -all' if the domain sends "
                                                   "no mail") + ".",
        f"No v=spf1 TXT record on {kb.domain}", f"dns:TXT {kb.domain}")


def _dmarc(kb: KnowledgeBase, site: str) -> IntelHit | None:
    if not kb.coverage.get("mail"):
        return None
    dmarc = kb.mail.get("dmarc") or {}
    policy = dmarc.get("policy")
    if policy in ("reject", "quarantine"):
        return None
    if dmarc.get("record"):
        return _hit(
            "SW-MAIL-DMARC-NONE", "email", "low", "DMARC is monitor-only (p=none)",
            "Spoofed mail is reported to the domain owner but still delivered to recipients.",
            "Move the DMARC policy to quarantine, then reject, once reports look clean.",
            f"_dmarc.{kb.domain}: {dmarc['record']}", f"dns:TXT _dmarc.{kb.domain}")
    return _hit(
        "SW-MAIL-DMARC-MISSING", "email", "medium", "No DMARC policy",
        f"Nothing tells receivers what to do with mail that fails authentication for "
        f"{kb.domain}, so phishing that spoofs it is usually delivered.",
        "Publish a DMARC record, starting at p=none with reporting, then enforce.",
        f"No TXT record at _dmarc.{kb.domain}", f"dns:TXT _dmarc.{kb.domain}")


def _tls(kb: KnowledgeBase, site: str) -> IntelHit | None:
    tls = kb.infra.get("tls") or {}
    days = tls.get("days_left")
    if tls.get("valid") is False:
        return _hit(
            "SW-TLS-INVALID", "tls", "high", "TLS certificate does not validate",
            "Browsers show a security warning, and users who click through can be intercepted.",
            "Install a certificate from a trusted CA that covers this hostname.",
            f"Certificate for {kb.domain}: {tls.get('error') or 'verification failed'}", site)
    if not isinstance(days, int) or days >= 21:
        return None
    severity = "high" if days < 0 else "medium" if days < 7 else "low"
    state = f"expired {-days} days ago" if days < 0 else f"expires in {days} days"
    return _hit(
        "SW-TLS-EXPIRY", "tls", severity, f"TLS certificate {state}",
        f"The certificate issued by {tls.get('issuer') or 'its CA'} {state}. An expired "
        "certificate takes the site down for most visitors.",
        "Renew the certificate and automate renewal.",
        f"notAfter {tls.get('not_after')}", site)


def _caa(kb: KnowledgeBase, site: str) -> IntelHit | None:
    if not kb.coverage.get("dns") or kb.dns.get("caa"):
        return None
    issuer = (kb.infra.get("tls") or {}).get("issuer")
    return _hit(
        "SW-DNS-CAA", "dns", "low", "No CAA record",
        "Any public certificate authority may issue certificates for this domain, which widens "
        "the room for mis-issuance.",
        "Publish CAA records naming the CA in use" + (f" ({issuer})" if issuer else "") + ".",
        f"No CAA records on {kb.domain}", f"dns:CAA {kb.domain}")


def _security_txt(kb: KnowledgeBase, site: str) -> IntelHit | None:
    if (kb.web.get("security_txt") or {}).get("present") is not False:
        return None
    return _hit(
        "SW-WEB-SECURITYTXT", "website", "low", "No security.txt",
        "Researchers who find a problem have no published way to report it.",
        "Publish /.well-known/security.txt with a Contact and an Expires line.",
        f"{site.rstrip('/')}/.well-known/security.txt not found", site)


def _subdomains(kb: KnowledgeBase, site: str) -> IntelHit | None:
    flagged = [s for s in kb.subdomains
               if s.interesting and s.ips and any(f in s.interesting for f in SENSITIVE_FLAGS)]
    if not flagged:
        return None
    remote = [s for s in flagged if "remote access" in (s.interesting or "")]
    severity = "medium" if remote or len(flagged) >= 3 else "low"
    listing = ", ".join(f"{s.name} ({s.interesting})" for s in flagged[:8])
    return _hit(
        "SW-SURFACE-SENSITIVE", "subdomains", severity,
        f"Sensitive-looking hosts are publicly resolvable ({len(flagged)})",
        f"Certificate logs list hosts that suggest remote access, admin or non-production "
        f"systems, and they resolve on the public internet: {listing}.",
        "Confirm each host is meant to be public; put admin, staging and tooling behind "
        "SSO or a VPN, and keep remote-access appliances patched.",
        listing, f"crt.sh {kb.domain}")
