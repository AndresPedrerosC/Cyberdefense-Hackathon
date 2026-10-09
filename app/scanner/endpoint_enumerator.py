"""Passive endpoint discovery and attack-surface mapping.

All HTTP goes through app.discovery.net.safe_fetch, which enforces SSRF protection
(scheme allowlist + per-hop private-IP checks). Discovery stays on the target host so we
never enumerate third-party assets.

An endpoint is a plain dict:
    {url, path, source, kind, status_code, auth_required, tech_signals, risk_level}
"""

import re
from urllib.parse import urljoin, urlparse

from app.discovery.net import safe_fetch
from app.schema import Emit, Target

MAX_SITEMAP_URLS = 200
MAX_SITEMAP_DEPTH = 3
MAX_FINGERPRINT = 60

API_MARKERS = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/_next/", "/wp-json/")
ADMIN_MARKERS = ("/admin", "/dashboard", "/panel", "/console", "/manage", "/wp-admin")
SENSITIVE_PATHS = (
    "/.env", "/.git/config", "/config.json", "/swagger.json", "/openapi.json",
    "/.aws/credentials", "/.npmrc", "/actuator", "/server-status", "/phpinfo.php",
)

_ATTR_RE = re.compile(r"""\b(?:href|src|action|data-url)\s*=\s*["']([^"'<>\s]+)["']""", re.I)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")


def _base_url(target: Target) -> str | None:
    if target.domain:
        return f"https://{target.domain}"
    if target.deploy_url:
        p = urlparse(target.deploy_url)
        if p.scheme in ("http", "https") and p.hostname:
            return f"{p.scheme}://{p.netloc}"
    return None


def _same_host(url: str, base_host: str) -> bool:
    try:
        return (urlparse(url).hostname or "") == base_host
    except ValueError:
        return False


def _classify_kind(path: str) -> str:
    low = path.lower()
    if any(low == s or low.startswith(s) for s in SENSITIVE_PATHS):
        return "sensitive"
    if any(m in low for m in ADMIN_MARKERS):
        return "admin"
    if any(m in low for m in API_MARKERS):
        return "api"
    return "page"


def _risk_for_kind(kind: str) -> str:
    return {"sensitive": "high", "admin": "high", "api": "medium"}.get(kind, "low")


def _mk_endpoint(url: str, source: str, base_host: str) -> dict | None:
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return None
    if parsed.hostname and parsed.hostname != base_host:
        return None
    path = parsed.path or "/"
    kind = _classify_kind(path)
    return {
        "url": url,
        "path": path,
        "source": source,
        "kind": kind,
        "status_code": None,
        "auth_required": None,
        "tech_signals": {},
        "risk_level": _risk_for_kind(kind),
    }


def enumerate_endpoints(target: Target, run_id: str, emit: Emit) -> list[dict]:
    base = _base_url(target)
    if not base:
        emit("discovery", "warn", "No domain/deploy_url for endpoint enumeration", None)
        return []
    base_host = urlparse(base).hostname or ""
    emit("discovery", "info", f"Enumerating endpoints for {base}", None)

    found: dict[str, dict] = {}

    def add(url: str, source: str) -> None:
        ep = _mk_endpoint(url, source, base_host)
        if ep and ep["url"] not in found:
            found[ep["url"]] = ep

    # robots.txt — Disallow/Allow lines frequently leak hidden paths.
    robots, _ = safe_fetch(f"{base}/robots.txt", target.target_id, emit)
    if robots:
        for line in robots.splitlines():
            m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
            if m and m.group(1) not in ("", "/"):
                add(urljoin(base + "/", m.group(1).lstrip("/")), "robots.txt")

    # sitemap.xml — recursive, capped.
    _walk_sitemap(f"{base}/sitemap.xml", base, base_host, target, emit, add, depth=0)

    # crawl a small set of seed pages for linked endpoints.
    for seed in ("/", "/index.html"):
        html, _ = safe_fetch(urljoin(base + "/", seed.lstrip("/")), target.target_id, emit)
        if not html:
            continue
        for raw in _ATTR_RE.findall(html):
            if raw.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
                continue
            add(urljoin(base + "/", raw), "page")

    # probe well-known sensitive paths directly.
    for sp in SENSITIVE_PATHS:
        add(base + sp, "known-path")

    endpoints = list(found.values())
    emit("discovery", "info", f"Enumerated {len(endpoints)} endpoints", None)
    return endpoints


def _walk_sitemap(url, base, base_host, target, emit, add, depth, budget=None) -> None:
    if depth > MAX_SITEMAP_DEPTH:
        return
    if budget is None:
        budget = [MAX_SITEMAP_URLS]
    if budget[0] <= 0:
        return
    xml, _ = safe_fetch(url, target.target_id, emit)
    if not xml:
        return
    for loc in _LOC_RE.findall(xml):
        if budget[0] <= 0:
            return
        loc = loc.strip()
        if not _same_host(loc, base_host) and urlparse(loc).hostname:
            continue
        if loc.lower().endswith(".xml"):
            _walk_sitemap(loc, base, base_host, target, emit, add, depth + 1, budget)
        else:
            budget[0] -= 1
            add(loc, "sitemap.xml")


def fingerprint_endpoints(endpoints: list[dict], target: Target, emit: Emit) -> list[dict]:
    """Passively GET each endpoint (capped) and enrich with status/tech/auth signals.

    safe_fetch returns (body, headers): body is non-None only on a 200, and headers are
    present for non-200 responses too, so we derive a coarse classification from both.
    """
    enriched: list[dict] = []
    for ep in endpoints[:MAX_FINGERPRINT]:
        try:
            body, headers = safe_fetch(ep["url"], target.target_id, emit)
        except Exception as e:  # one bad endpoint never kills the sweep
            emit("discovery", "warn", f"Fingerprint failed for {ep['url']}: {e}", None)
            enriched.append(ep)
            continue

        headers = {k.lower(): v for k, v in (headers or {}).items()}
        ep["tech_signals"] = {h: headers[h] for h in _TECH_HEADERS if h in headers}

        if body is not None:
            ep["status_code"] = 200
            classified = "public"
        elif "www-authenticate" in headers:
            classified = "authenticated"
        elif "location" in headers:
            classified = "redirect"
        elif headers:
            classified = "error"
        else:
            classified = "error"

        ep["classification"] = classified
        ep["auth_required"] = classified == "authenticated"

        # A sensitive/admin endpoint that answered publicly (200, no auth) is the worst case.
        if ep["kind"] in ("sensitive", "admin") and classified == "public":
            ep["risk_level"] = "critical"
        elif ep["kind"] == "api" and classified == "public" and not ep["auth_required"]:
            ep["risk_level"] = "high"

        enriched.append(ep)

    for ep in endpoints[MAX_FINGERPRINT:]:
        enriched.append(ep)
    emit("discovery", "info", f"Fingerprinted {min(len(endpoints), MAX_FINGERPRINT)} endpoints", None)
    return enriched
