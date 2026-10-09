"""Safe network utilities with SSRF protection."""

import ipaddress
import json
import socket
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.schema import Emit

BLOCKED_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

USER_AGENT = "cyberdefense-hackathon-agent/0.1 (passive)"
TIMEOUT = 10.0
MAX_BODY = 2 * 1024 * 1024
MAX_REDIRECTS = 5
ALLOWED_SCHEMES = ("http", "https")


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP is in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        return any(ip in network for network in BLOCKED_RANGES)
    except ValueError:
        return True  # Invalid IP, block it


def resolve_and_check(hostname: str) -> str | None:
    """Resolve hostname and check if IP is allowed."""
    try:
        # Get all IPs for hostname
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if is_private_ip(ip):
                return None  # Blocked
        return infos[0][4][0] if infos else None
    except socket.gaierror:
        return None


def _check_url(url: str) -> str | None:
    """Return a reason string if the URL must not be fetched, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"scheme {parsed.scheme!r} not allowed"
    if not parsed.hostname:
        return "missing hostname"
    if resolve_and_check(parsed.hostname) is None:
        return f"{parsed.hostname} resolves to private/reserved IP"
    return None


def safe_fetch(url: str, target_id: str, emit: Emit) -> tuple[str | None, dict]:
    """Passive GET with SSRF protection; every redirect hop is re-validated."""
    page = fetch_page(url, target_id, emit)
    if page is None:
        return None, {}
    if page["status"] != 200:
        return None, page["headers"]
    return page["text"], page["headers"]


def fetch_page(
    url: str,
    target_id: str,
    emit: Emit,
    timeout: float = TIMEOUT,
    max_body: int = MAX_BODY,
    use_cache: bool = True,
    allow_host: Callable[[str], bool] | None = None,
) -> dict | None:
    """SSRF-safe GET returning status, headers, cookies, final URL and body for any status.

    Returns None when the URL or a redirect hop is blocked, or the request fails.
    allow_host, when given, additionally restricts every hop (e.g. to the target's own domain).
    """
    reason = _check_url(url)
    if reason:
        emit("discovery", "warn", f"Blocked {_short(url)}: {reason}", None)
        return None

    cache_path = _get_cache_path(target_id, url)
    meta_path = cache_path.with_suffix(".json")
    if use_cache and cache_path.exists() and meta_path.exists():
        emit("discovery", "info", f"Using cached: {url}", None)
        try:
            meta = json.loads(meta_path.read_text())
            return {**meta, "text": cache_path.read_text()}
        except (OSError, ValueError):
            pass

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            current = url
            for _ in range(MAX_REDIRECTS + 1):
                with client.stream("GET", current, headers={"User-Agent": USER_AGENT}) as response:
                    if response.is_redirect:
                        location = response.headers.get("location", "")
                        nxt = str(response.url.join(location))
                        reason = _check_url(nxt)
                        if not reason and allow_host and not allow_host(urlparse(nxt).hostname):
                            reason = "outside the allowed scope"
                        if reason:
                            emit("discovery", "warn",
                                 f"Blocked redirect to {_short(nxt)}: {reason}", None)
                            return None
                        current = nxt
                        continue

                    cookies = response.headers.get_list("set-cookie")
                    headers = {
                        k.lower(): v for k, v in response.headers.items() if k.lower() != "set-cookie"
                    }
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= max_body:
                            break
                    text = bytes(body[:max_body]).decode(response.encoding or "utf-8", "replace")
                    meta = {
                        "url": url,
                        "final_url": str(response.url),
                        "status": response.status_code,
                        "headers": headers,
                        "set_cookies": cookies,
                    }
                    if use_cache:
                        cache_path.parent.mkdir(parents=True, exist_ok=True)
                        cache_path.write_text(text)
                        meta_path.write_text(json.dumps(meta))
                    return {**meta, "text": text}

            emit("discovery", "warn", f"Too many redirects: {url}", None)
            return None

    except Exception as e:
        emit("discovery", "warn", f"Fetch failed: {url} ({e})", None)
        return None


def _short(url: str, limit: int = 160) -> str:
    """Trim long URLs (tokens in query strings) for the event feed."""
    return url if len(url) <= limit else url[:limit] + "..."


def _get_cache_path(target_id: str, url: str) -> Path:
    """Get cache path for a URL."""
    import hashlib
    url_hash = hashlib.sha1(url.encode()).hexdigest()[:12]
    return Path("data/raw") / target_id / f"{url_hash}.html"
