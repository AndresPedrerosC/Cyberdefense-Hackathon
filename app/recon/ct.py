"""Subdomain discovery from certificate transparency (crt.sh, CertSpotter fallback)."""

import json
import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from app.discovery.net import USER_AGENT, is_private_ip
from app.recon.dns_records import lookup
from app.recon.domain import in_scope
from app.recon.kb import KnowledgeBase, Subdomain
from app.schema import Emit

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
MAX_BODY = 20 * 1024 * 1024
RESOLVE_CAP = 40

# First-label token -> why the host matters. Checked against each dash/dot separated token.
INTERESTING = [
    ({"vpn", "sslvpn", "remote", "gp", "globalprotect", "citrix", "ctx", "netscaler", "rdweb",
      "rdp", "rds", "vdi", "horizon", "fortigate", "forti", "anyconnect", "pulse", "ivanti",
      "secure", "access"}, "remote access"),
    ({"owa", "mail", "webmail", "exchange", "autodiscover", "smtp", "imap", "mx"}, "mail edge"),
    ({"admin", "portal", "cpanel", "whm", "plesk", "manage", "panel", "dashboard",
      "backoffice"}, "admin interface"),
    ({"jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana", "sonar",
      "sonarqube", "argocd", "nexus", "artifactory", "harbor", "bitbucket", "prometheus",
      "teamcity", "bamboo"}, "dev tooling"),
    ({"dev", "staging", "stage", "stg", "test", "uat", "qa", "preprod", "sandbox",
      "demo", "beta"}, "non-production"),
    ({"sso", "okta", "adfs", "login", "auth", "idp", "identity", "saml", "id"}, "identity"),
    ({"api", "graphql", "gateway"}, "api"),
    ({"ftp", "sftp", "files", "share", "backup"}, "file transfer"),
]
REASON_ORDER = [reason for _, reason in INTERESTING]
TOKEN_SPLIT = re.compile(r"[.\-_]")


def flag_interesting(name: str, domain: str) -> str | None:
    """Reason a subdomain deserves attention, from tokens left of the apex domain."""
    prefix = name[: -len(domain)].rstrip(".") if name.endswith(domain) else name
    tokens = {t for t in TOKEN_SPLIT.split(prefix.lower()) if t}
    for words, reason in INTERESTING:
        if tokens & words:
            return reason
    return None


def clean_names(raw_names: list[str], domain: str, cap: int = 300) -> list[str]:
    """Dedupe, drop wildcards and out-of-scope names, sort, cap."""
    out = set()
    for raw in raw_names:
        for name in str(raw).split("\n"):
            n = name.strip().lower().rstrip(".")
            if not n or n.startswith("*") or " " in n or "@" in n:
                continue
            if n != domain and in_scope(n, domain):
                out.add(n)
    return sorted(out)[:cap]


def _read_json(client: httpx.Client, url: str, params: dict):
    with client.stream("GET", url, params=params) as resp:
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        body = bytearray()
        for chunk in resp.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_BODY:
                raise RuntimeError("response too large")
    return json.loads(bytes(body))


def _from_crtsh(domain: str) -> list[str]:
    with httpx.Client(timeout=25.0, headers={"User-Agent": USER_AGENT}) as client:
        rows = _read_json(client, CRTSH_URL, {"q": f"%.{domain}", "output": "json"})
    names = []
    for row in rows:
        names.append(row.get("name_value", ""))
        names.append(row.get("common_name", ""))
    return names


def _from_certspotter(domain: str) -> list[str]:
    with httpx.Client(timeout=20.0, headers={"User-Agent": USER_AGENT}) as client:
        rows = _read_json(client, CERTSPOTTER_URL, {
            "domain": domain, "include_subdomains": "true", "expand": "dns_names",
        })
    return [n for row in rows for n in row.get("dns_names", [])]


def collect_subdomains(kb: KnowledgeBase, emit: Emit, cap: int = 300) -> None:
    domain = kb.domain
    names, source = [], None
    for src, fn in (("crt.sh", _from_crtsh), ("certspotter", _from_certspotter)):
        try:
            names = clean_names(fn(domain), domain, cap)
            source = src
            break
        except Exception as e:
            emit("discovery", "warn", f"Subdomains: {src} failed ({e})", None)

    if source is None:
        kb.coverage["subdomains"] = "failed"
        return

    try:
        subs = [Subdomain(name=n, source=source, interesting=flag_interesting(n, domain))
                for n in names]
        # Resolve interesting hosts first, then the rest, up to the cap.
        order = sorted(subs, key=lambda s: (
            REASON_ORDER.index(s.interesting) if s.interesting else len(REASON_ORDER), s.name))
        to_resolve = order[:RESOLVE_CAP]
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(lambda s: lookup(s.name, "A", timeout=3.0), to_resolve))
        for sub, ips in zip(to_resolve, results):
            sub.ips = [ip for ip in ips if not is_private_ip(ip)]
            if ips and not sub.ips:
                kb.add_fact("subdomain", sub.name, "resolves to a private address", "dns:A",
                            "high")

        kb.subdomains = order
        flagged = [s for s in order if s.interesting]
        kb.add_fact("subdomain", "Subdomains in CT logs", str(len(order)), source, "high")
        for s in flagged[:25]:
            kb.add_fact("subdomain", s.name, s.interesting, source, "medium")
        kb.coverage["subdomains"] = "ok" if source == "crt.sh" else "partial"
        emit("discovery", "info",
             f"Subdomains: {len(order)} from {source}, {len(flagged)} flagged", None)
    except Exception as e:
        kb.coverage["subdomains"] = "failed"
        emit("discovery", "warn", f"Subdomain collector failed: {e}", None)
