"""Domain normalization, scope checks and registrable-domain heuristics."""

import ipaddress
import re
from urllib.parse import urlsplit

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
BLOCKED_SUFFIXES = (".local", ".internal", ".lan", ".localhost", ".home.arpa", ".corp")

# Common two-level public suffixes; enough for a best-effort registrable domain.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "co.in", "net.in", "org.in",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.tw", "co.za", "co.il", "com.tr", "com.my", "com.ph",
    "co.id", "com.vn", "com.pl", "com.ua", "co.th",
}


def normalize_domain(raw: str) -> str:
    """Turn user input like 'https://Example.com:443/about' into 'example.com' or raise."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Enter a domain, for example example.com")
    if "://" not in text:
        text = "//" + text
    try:
        host = urlsplit(text).hostname or ""
    except ValueError as e:
        raise ValueError(f"Could not parse {raw!r} as a domain") from e
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"Could not find a hostname in {raw!r}")

    if _is_ip(host):
        raise ValueError("Enter a domain name, not an IP address")

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"{raw!r} is not a valid internationalized domain") from e

    if host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
        raise ValueError(f"{host} is a local or internal name, not a public domain")
    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError(f"{host} is a single-label name; enter a full public domain")
    if len(host) > 253:
        raise ValueError("Domain is longer than 253 characters")
    for label in labels:
        if not LABEL.match(label):
            raise ValueError(f"{host} has an invalid label {label!r}")
    if labels[-1].isdigit():
        raise ValueError(f"{host} does not end in a valid top-level domain")
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without a full public suffix list."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def in_scope(host: str | None, domain: str) -> bool:
    """True when host is the domain itself or one of its subdomains."""
    if not host:
        return False
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)
