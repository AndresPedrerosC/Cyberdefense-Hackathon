"""RDAP registration data via rdap.org (redirects to the authoritative registry)."""

import json

import httpx

from app.discovery.net import USER_AGENT
from app.recon.domain import registrable
from app.recon.kb import KnowledgeBase
from app.schema import Emit

RDAP_URL = "https://rdap.org/domain/{domain}"
MAX_BODY = 512 * 1024
REDACTED = ("redacted", "privacy", "withheld", "not disclosed", "data protected", "proxy")


def _vcard_value(entity: dict, field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value).strip() or None
    return None


def parse_rdap(data: dict) -> dict:
    """Extract registrar, dates, status, registrant org and nameservers from an RDAP domain."""
    out: dict = {"status": data.get("status") or []}
    for ev in data.get("events") or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
        elif action == "last changed":
            out["updated"] = date

    def walk(entities: list) -> None:
        for ent in entities or []:
            roles = ent.get("roles") or []
            if "registrar" in roles and "registrar" not in out:
                out["registrar"] = _vcard_value(ent, "fn")
                iana = [p.get("identifier") for p in ent.get("publicIds") or []
                        if p.get("type") == "IANA Registrar ID"]
                if iana:
                    out["registrar_iana_id"] = iana[0]
            if "registrant" in roles and "registrant_org" not in out:
                org = _vcard_value(ent, "org") or _vcard_value(ent, "fn")
                if org and not any(r in org.lower() for r in REDACTED):
                    out["registrant_org"] = org
            walk(ent.get("entities") or [])

    walk(data.get("entities") or [])
    out["nameservers"] = sorted(
        (ns.get("ldhName") or "").lower().rstrip(".")
        for ns in data.get("nameservers") or [] if ns.get("ldhName")
    )
    return {k: v for k, v in out.items() if v}


def collect_rdap(kb: KnowledgeBase, emit: Emit) -> None:
    domain = registrable(kb.domain)
    url = RDAP_URL.format(domain=domain)
    try:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/rdap+json"}
        with (
            httpx.Client(timeout=10.0, follow_redirects=True, headers=headers) as client,
            client.stream("GET", url) as resp,
        ):
            if resp.status_code != 200:
                kb.coverage["rdap"] = "failed"
                emit("discovery", "warn", f"RDAP: HTTP {resp.status_code} for {domain}", None)
                return
            body = bytearray()
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    break
            source = str(resp.url)
        info = parse_rdap(json.loads(bytes(body[:MAX_BODY])))
        for key in ("registrar", "created", "expires", "updated", "registrant_org"):
            if info.get(key):
                kb.infra[key] = info[key]
        if info.get("status"):
            kb.infra["registry_status"] = info["status"]
        if info.get("nameservers"):
            kb.infra["rdap_nameservers"] = info["nameservers"]

        labels = {"registrar": "Registrar", "created": "Registered", "expires": "Expires",
                  "registrant_org": "Registrant organization"}
        for key, label in labels.items():
            if info.get(key):
                kb.add_fact("infra", label, info[key], source, "high")
        if info.get("registrant_org"):
            kb.add_fact("company", "Registrant organization", info["registrant_org"], source,
                        "medium")
        kb.coverage["rdap"] = "ok"
        emit("discovery", "info",
             f"RDAP: registrar={info.get('registrar') or 'unknown'}, "
             f"created={(info.get('created') or '?')[:10]}", None)
    except Exception as e:
        kb.coverage["rdap"] = "failed"
        emit("discovery", "warn", f"RDAP collector failed: {e}", None)
