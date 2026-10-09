"""Senso.ai knowledge base integration.

Each completed public-domain run is rendered as one markdown document and ingested with
POST /org/kb/raw. Questions about a run go to POST /org/search, scoped by content_ids to that
run's document so another domain's documents in the same Senso org can never answer.

Configured by SENSO_API_KEY and SENSO_BASE_URL. With no key every call is a no-op and the
KB records senso.state = "not_configured". The key is only ever sent as the X-API-Key header.
"""

import re
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import get_env
from app.recon.kb import KnowledgeBase
from app.schema import Emit

DEFAULT_BASE_URL = "https://apiv2.senso.ai/api/v1"
TIMEOUT = httpx.Timeout(30.0, connect=5.0)
MAX_DOC_CHARS = 200_000
MAX_SUBDOMAINS = 200
MAX_QUESTION_CHARS = 500
MAX_CITATIONS = 5
SNIPPET_CHARS = 400
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

# Mirrors processing_status on a Senso content node.
_INGESTING = ("pending", "processing")
# Test seam: tests install an httpx.MockTransport here.
_transport: httpx.BaseTransport | None = None


class SensoError(Exception):
    """A Senso call failed. The message is safe to show and never contains the key."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _key() -> str | None:
    return (get_env("SENSO_API_KEY") or "").strip() or None


def is_configured() -> bool:
    return _key() is not None


def _client() -> httpx.Client:
    base = (get_env("SENSO_BASE_URL") or "").strip() or DEFAULT_BASE_URL
    return httpx.Client(
        base_url=base.rstrip("/"),
        headers={"X-API-Key": _key() or "", "Accept": "application/json"},
        timeout=TIMEOUT,
        follow_redirects=False,
        transport=_transport,
    )


_STATUS_MESSAGES = {
    400: "Senso rejected the request",
    401: "Senso rejected the API key",
    402: "the Senso organization is out of credits",
    403: "the Senso API key is not permitted to do this",
    404: "Senso could not find the document",
    409: "Senso already has an identical document",
    429: "Senso rate limit reached, try again shortly",
}


def _request(method: str, path: str, **kwargs) -> dict:
    if not is_configured():
        raise SensoError("Senso is not configured")
    try:
        with _client() as client:
            r = client.request(method, path, **kwargs)
    except httpx.TimeoutException:
        raise SensoError("Senso did not respond in time") from None
    except httpx.HTTPError as e:
        raise SensoError(f"could not reach Senso ({type(e).__name__})") from None
    if r.status_code >= 400:
        detail = ""
        try:
            detail = str(r.json().get("message") or "")[:200]
        except (ValueError, AttributeError):
            pass
        base = _STATUS_MESSAGES.get(r.status_code, f"Senso returned HTTP {r.status_code}")
        raise SensoError(f"{base}: {detail}" if detail else base, r.status_code)
    try:
        data = r.json()
    except ValueError:
        raise SensoError("Senso returned a response that is not JSON", r.status_code) from None
    if not isinstance(data, dict):
        raise SensoError("Senso returned an unexpected response", r.status_code)
    return data


# ---- Document rendering ----


def document_title(kb: KnowledgeBase) -> str:
    return f"{kb.domain} knowledge base, run {kb.run_id}"


def _line(label: str, value: Any) -> str | None:
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v not in (None, ""))
    elif isinstance(value, dict):
        value = ", ".join(f"{k}: {v}" for k, v in value.items() if v not in (None, ""))
    return f"- {label}: {value}" if value else None


def _section(title: str, lines: list[str | None]) -> list[str]:
    body = [x for x in lines if x]
    return [f"## {title}", "", *body, ""] if body else []


def render_document(kb: KnowledgeBase) -> str:
    """Render the KB as one readable markdown document. Every fact keeps its source."""
    c, web, dns, mail, infra = kb.company, kb.web, kb.dns, kb.mail, kb.infra
    tls = infra.get("tls") or {}
    spf = mail.get("spf") or {}
    dmarc = mail.get("dmarc") or {}
    out = [
        f"# {document_title(kb)}",
        "",
        f"Domain: {kb.domain}",
        f"Run: {kb.run_id}",
        (f"Collected: {kb.started_ts.isoformat(timespec='seconds')}Z to "
         f"{kb.updated_ts.isoformat(timespec='seconds')}Z"),
        ("Source: Stackwatch passive public-domain reconnaissance. Facts below come from DNS, "
         "RDAP, TLS, certificate transparency, the public website, and a research agent."),
        "",
    ]
    if kb.agent.profile:
        out += [f"## Profile of {kb.domain}", "",
                f"Written by the research agent ({kb.agent.model or 'unknown model'}).", "",
                kb.agent.profile.strip(), ""]

    out += _section(f"Organization behind {kb.domain}", [
        _line("Name", c.get("name")),
        _line("Legal name", c.get("legal_name")),
        _line("Description", c.get("description") or web.get("description")),
        _line("Industry", c.get("industry")),
        _line("Location", c.get("location")),
        _line("Founded", c.get("founded")),
        _line("Emails", c.get("emails")),
        _line("Phones", c.get("phones")),
        _line("Social profiles", c.get("socials")),
    ])

    facts = [f for f in kb.facts if f.category not in ("stack",)]
    if facts:
        out += [f"## Facts about {kb.domain} with sources", ""]
        for f in facts:
            out.append(f"- [{f.category}] {f.key}: {f.value} (source: {f.source}, "
                       f"{f.confidence} confidence, recorded by {f.by})")
        out.append("")

    stack = [f"- {t.name}{' ' + t.version if t.version else ''} ({t.category}"
             f"{', on ' + t.host if t.host else ''}, {t.confidence} confidence)"
             f"{': ' + t.evidence if t.evidence else ''}"
             f"{' [source: ' + t.source + ']' if t.source else ''}" for t in kb.stack]
    stack += [f"- {f.value} ({f.key}, source: {f.source})"
              for f in kb.facts if f.category == "stack"]
    out += _section(f"Technology stack of {kb.domain}", stack)

    out += _section(f"Website of {kb.domain}", [
        _line("Final URL", web.get("final_url")),
        _line("HTTP status", web.get("status")),
        _line("Title", web.get("title")),
        _line("Server", web.get("server")),
        _line("Security headers", web.get("security_headers")),
        _line("security.txt published", (web.get("security_txt") or {}).get("present")),
        _line("Third-party hosts", web.get("external_hosts")),
    ])

    out += _section(f"DNS of {kb.domain}", [
        _line("Nameservers", dns.get("ns")),
        _line("A", dns.get("a")),
        _line("AAAA", dns.get("aaaa")),
        _line("MX", [m.get("host") if isinstance(m, dict) else m for m in dns.get("mx") or []]),
        _line("CAA", dns.get("caa") or "none published"),
        _line("DNSSEC", "enabled" if dns.get("dnssec") else "not enabled"),
        _line("TXT", dns.get("txt")),
    ]) if dns else []

    out += _section(f"Email security posture of {kb.domain}", [
        _line("Mail provider", mail.get("provider")),
        _line("MX hosts", mail.get("mx_hosts")),
        _line("SPF", spf.get("record") or "missing"),
        _line("SPF all rule", spf.get("all")),
        _line("DMARC", dmarc.get("record") or "missing"),
        _line("DMARC policy", dmarc.get("policy")),
        _line("MTA-STS", mail.get("mta_sts") or "not published"),
        _line("DKIM selectors found", mail.get("dkim_selectors") or "none at common selectors"),
    ]) if mail else []

    ips = [f"{x.get('ip')} AS{x.get('asn')} {x.get('org') or ''} {x.get('country') or ''}".strip()
           for x in infra.get("ips") or [] if isinstance(x, dict)]
    out += _section(f"Hosting, registration and TLS of {kb.domain}", [
        _line("Hosting", infra.get("hosting")),
        _line("CDN", infra.get("cdn")),
        _line("IP addresses", ips),
        _line("Registrar", infra.get("registrar")),
        _line("Registered", infra.get("created")),
        _line("Expires", infra.get("expires")),
        _line("TLS issuer", tls.get("issuer")),
        _line("TLS valid until", tls.get("not_after")),
        _line("TLS days left", tls.get("days_left")),
    ])

    if kb.subdomains:
        notable = [s for s in kb.subdomains if s.interesting]
        rest = [s for s in kb.subdomains if not s.interesting]
        out += [f"## Subdomains of {kb.domain}", "",
                f"{len(kb.subdomains)} hostnames found in certificate transparency logs.", ""]
        out += [f"- {s.name}: {s.interesting}" for s in notable]
        out += [f"- {s.name}" for s in rest[:MAX_SUBDOMAINS]]
        if len(rest) > MAX_SUBDOMAINS:
            out.append(f"- and {len(rest) - MAX_SUBDOMAINS} more")
        out.append("")

    out += [f"## Exposures of {kb.domain}", ""]
    if kb.intel:
        for h in kb.intel:
            extras = [h.severity, "known exploited (CISA KEV)" if h.kev else "",
                      f"EPSS {h.epss:.3f}" if h.epss is not None else "",
                      f"fixed in {h.fixed_version}" if h.fixed_version else ""]
            out.append(f"- {h.id} ({', '.join(x for x in extras if x)}) on "
                       f"{h.tech or 'unattributed'}: {h.title}"
                       f"{'. ' + h.detail if h.detail else ''}"
                       f"{' [source: ' + h.url + ']' if h.url else ''}")
    else:
        out.append("- No known exposures matched the detected technologies.")
    out.append("")
    if kb.agent.brief:
        out += ["## Analyst brief", "", kb.agent.brief.strip(), ""]

    text = "\n".join(out)
    return text if len(text) <= MAX_DOC_CHARS else text[:MAX_DOC_CHARS] + "\n\n[truncated]\n"


# ---- Ingest and search ----


def ingest_text(title: str, text: str, summary: str | None = None) -> dict:
    """POST /org/kb/raw. Returns content_id, kb_node_id and processing_status."""
    body: dict[str, Any] = {"text": text, "title": title}
    if summary:
        body["summary"] = summary
    data = _request("POST", "/org/kb/raw", json=body)
    if not data.get("id"):
        raise SensoError("Senso accepted the document but returned no content id")
    return {
        "content_id": data["id"],
        "kb_node_id": data.get("kb_node_id"),
        "processing_status": data.get("processing_status") or "pending",
    }


def processing_status(kb_node_id: str) -> str:
    """GET /org/kb/nodes/{id}: pending | processing | complete | failed."""
    data = _request("GET", f"/org/kb/nodes/{kb_node_id}")
    return str((data.get("content") or {}).get("processing_status") or "processing")


def search(question: str, content_ids: list[str], max_results: int = MAX_CITATIONS) -> dict:
    """POST /org/search, scoped to content_ids. Returns {answer, citations[]}."""
    data = _request("POST", "/org/search", json={
        "query": question,
        "max_results": max_results,
        "content_ids": content_ids,
        "require_scoped_ids": True,
    })
    citations = []
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        text = str(r.get("chunk_text") or "")
        urls = list(dict.fromkeys(u.rstrip(".,;:") for u in URL_RE.findall(text)))[:3]
        citations.append({
            "title": r.get("title") or "Untitled document",
            "snippet": text[:SNIPPET_CHARS] + ("..." if len(text) > SNIPPET_CHARS else ""),
            "score": r.get("score"),
            "rank": r.get("rank"),
            "content_id": r.get("content_id"),
            "kb_node_id": r.get("kb_node_id"),
            "urls": urls,
        })
    return {"answer": str(data.get("answer") or ""), "citations": citations}


def ingest_kb(kb: KnowledgeBase, emit: Emit) -> None:
    """Ingest a completed run's KB. Records the outcome on kb.senso and kb.coverage["senso"]."""
    if not is_configured():
        kb.coverage["senso"] = "skipped"
        kb.senso = {"state": "not_configured"}
        return
    title = document_title(kb)
    try:
        res = ingest_text(title, render_document(kb),
                          summary=f"Stackwatch reconnaissance of {kb.domain}, run {kb.run_id}")
    except SensoError as e:
        kb.coverage["senso"] = "failed"
        kb.senso = {"state": "failed", "error": str(e), "title": title}
        emit("report", "warn", f"Senso ingest failed: {e}", None)
        return
    status = res["processing_status"]
    kb.coverage["senso"] = "failed" if status == "failed" else "ok"
    kb.senso = {
        "state": "ready" if status == "complete" else "failed" if status == "failed"
        else "ingesting",
        "title": title,
        "content_id": res["content_id"],
        "kb_node_id": res["kb_node_id"],
        "ingested_ts": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    emit("report", "info", f"Ingested into Senso: {title}", None)


def refresh_state(kb: KnowledgeBase) -> bool:
    """Poll Senso while a document is ingesting. Returns True when kb.senso changed."""
    s = kb.senso
    if s.get("state") != "ingesting" or not s.get("kb_node_id") or not is_configured():
        return False
    try:
        status = processing_status(s["kb_node_id"])
    except SensoError:
        return False  # transient; the next poll retries
    if status in _INGESTING:
        return False
    kb.senso = {**s, "state": "ready" if status == "complete" else "failed"}
    if status != "complete":
        kb.senso["error"] = "Senso could not process the document"
        kb.coverage["senso"] = "failed"
    return True
