"""Website collector: passive page fetches, web metadata and company profile extraction."""

import contextlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.discovery.net import fetch_page
from app.recon.domain import in_scope
from app.recon.kb import FetchedPage, KnowledgeBase
from app.schema import Emit

HTML_CAP = 400 * 1024
TEXT_CAP = 64 * 1024
MAX_SUBPAGES = 7
SUBPAGE_GUESSES = ["/about", "/about-us", "/company", "/contact", "/careers"]
SUBPAGE_KEYWORDS = re.compile(
    r"/(about|about-us|company|contact|contact-us|careers|jobs|team|leadership|who-we-are)"
    r"(/|$|\.html?$)", re.IGNORECASE)

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]
ORG_TYPES = {
    "organization", "corporation", "localbusiness", "ngo", "educationalorganization",
    "governmentorganization", "medicalorganization", "onlinebusiness", "onlinestore",
    "store", "professionalservice", "financialservice", "insuranceagency", "bankorcreditunion",
    "airline", "sportsorganization", "newsmediaorganization", "researchorganization",
}
SOCIAL_PATTERNS = [
    ("linkedin", re.compile(r"^https?://([a-z]{2,3}\.)?linkedin\.com/(company|school|showcase)/[^/?#]+", re.IGNORECASE)),
    ("x", re.compile(r"^https?://(www\.)?(twitter|x)\.com/(?!intent|share|home|search|hashtag)[A-Za-z0-9_]{1,15}/?$", re.IGNORECASE)),
    ("github", re.compile(r"^https?://(www\.)?github\.com/[A-Za-z0-9-]+/?$", re.IGNORECASE)),
    ("facebook", re.compile(r"^https?://(www\.)?facebook\.com/(?!sharer|share|dialog|plugins|tr)[^/?#]+/?$", re.IGNORECASE)),
    ("instagram", re.compile(r"^https?://(www\.)?instagram\.com/[A-Za-z0-9_.]+/?$", re.IGNORECASE)),
    ("youtube", re.compile(r"^https?://(www\.)?youtube\.com/(@|c/|channel/|user/)[^/?#]+", re.IGNORECASE)),
    ("crunchbase", re.compile(r"^https?://(www\.)?crunchbase\.com/organization/[^/?#]+", re.IGNORECASE)),
]
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})\b")
TITLE_SPLIT = re.compile(r"\s+[|\-\u2013\u2014:\u00b7\u2022]\s+")


class _PageParser(HTMLParser):
    """Collects title, metas, links, scripts, JSON-LD blocks and visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.metas: dict[str, str] = {}
        self.anchors: list[str] = []
        self.scripts: list[str] = []
        self.links: list[tuple[str, str]] = []  # (rel, href)
        self.iframes: list[str] = []
        self.jsonld: list[str] = []
        self.text: list[str] = []
        self._in_title = False
        self._in_jsonld = False
        self._skip = 0
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key and "content" in a and key not in self.metas:
                self.metas[key] = a["content"].strip()
        elif tag == "a" and a.get("href"):
            self.anchors.append(a["href"].strip())
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"].strip())
            if "ld+json" in a.get("type", "").lower():
                self._in_jsonld = True
                self._buf = []
            else:
                self._skip += 1
        elif tag == "link" and a.get("href"):
            self.links.append((a.get("rel", "").lower(), a["href"].strip()))
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"].strip())
        elif tag in ("style", "noscript", "svg"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            if self._in_jsonld:
                self.jsonld.append("".join(self._buf))
                self._in_jsonld = False
            elif self._skip:
                self._skip -= 1
        elif tag in ("style", "noscript", "svg") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._in_jsonld:
            self._buf.append(data)
        elif self._in_title:
            self.title += data
        elif not self._skip:
            chunk = data.strip()
            if chunk:
                self.text.append(chunk)


def parse_html(html: str) -> _PageParser:
    p = _PageParser()
    # Malformed markup should never sink a collector; keep whatever was parsed so far.
    with contextlib.suppress(Exception):
        p.feed(html)
        p.close()
    p.title = " ".join(re.sub(r"<[^>]+>", " ", p.title).split())
    return p


def page_text(html: str, limit: int = 6000) -> str:
    """Visible text of a page, whitespace-collapsed and capped (for the agent)."""
    return " ".join(" ".join(parse_html(html).text).split())[:limit]


# ---- pure extractors ----

def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _str(v) -> str | None:
    if isinstance(v, dict):
        v = v.get("url") or v.get("name") or v.get("@id") or v.get("value")
    if v is None:
        return None
    s = " ".join(str(v).split())
    return s or None


def _jsonld_nodes(blocks: list[str]) -> list[dict]:
    nodes = []
    for raw in blocks:
        try:
            data = json.loads(raw.strip())
        except ValueError:
            continue
        stack = _as_list(data)
        while stack:
            node = stack.pop(0)
            if not isinstance(node, dict):
                continue
            nodes.append(node)
            stack.extend(_as_list(node.get("@graph")))
    return nodes


def _types(node: dict) -> set[str]:
    return {str(t).lower().split("/")[-1] for t in _as_list(node.get("@type"))}


def _address(v) -> str | None:
    for addr in _as_list(v):
        if isinstance(addr, str):
            return _str(addr)
        if isinstance(addr, dict):
            country = addr.get("addressCountry")
            parts = [addr.get("streetAddress"), addr.get("addressLocality"),
                     addr.get("addressRegion"), addr.get("postalCode"),
                     _str(country) if country else None]
            text = ", ".join(_str(p) for p in parts if p and _str(p))
            if text:
                return text
    return None


def extract_jsonld_org(blocks: list[str]) -> dict:
    """Organization-like JSON-LD node -> company fields."""
    nodes = _jsonld_nodes(blocks)
    org = next((n for n in nodes if _types(n) & ORG_TYPES), None)
    out: dict = {}
    if org:
        employees = org.get("numberOfEmployees")
        if isinstance(employees, dict):
            employees = employees.get("value") or (
                f"{employees.get('minValue')}-{employees.get('maxValue')}"
                if employees.get("minValue") else None)
        out = {
            "name": _str(org.get("name")),
            "legal_name": _str(org.get("legalName")),
            "description": _str(org.get("description")),
            "logo": _str(org.get("logo")),
            "founded": _str(org.get("foundingDate")),
            "location": _address(org.get("address")),
            "same_as": [s for s in (_str(x) for x in _as_list(org.get("sameAs"))) if s][:20],
            "employees": _str(employees),
            "email": _str(org.get("email")),
            "telephone": _str(org.get("telephone")),
            "founders": [f for f in (_str(x) for x in _as_list(org.get("founder"))) if f][:5],
        }
    site = next((n for n in nodes if "website" in _types(n)), None)
    if site and site.get("name"):
        out["site_name"] = _str(site.get("name"))
    return {k: v for k, v in out.items() if v}


def clean_title_name(title: str, domain: str) -> str | None:
    """'Home | Acme Corp' -> 'Acme Corp', preferring the segment matching the domain label."""
    if not title:
        return None
    parts = [p.strip() for p in TITLE_SPLIT.split(title) if p.strip()]
    if not parts:
        return None
    label = domain.split(".")[0].replace("-", "").lower()
    for p in parts:
        if label and label in p.replace(" ", "").replace("-", "").lower():
            return p[:120]
    generic = {"home", "homepage", "welcome", "official site", "official website"}
    for p in parts:
        if p.lower() not in generic:
            return p[:120]
    return parts[0][:120]


def extract_socials(urls: list[str]) -> dict[str, str]:
    socials: dict[str, str] = {}
    for u in urls:
        for name, pattern in SOCIAL_PATTERNS:
            if name not in socials and pattern.match(u):
                socials[name] = u.split("?")[0].rstrip("/")
    return socials


def extract_emails(html: str, anchors: list[str], domain: str, cap: int = 10) -> list[str]:
    """In-scope addresses only, from mailto links and page text."""
    found: list[str] = []
    candidates = [a[7:].split("?")[0] for a in anchors if a.lower().startswith("mailto:")]
    candidates += [m.group(0) for m in EMAIL_RE.finditer(html)]
    for c in candidates:
        e = c.strip().lower()
        host = e.rsplit("@", 1)[-1] if "@" in e else ""
        if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js)$", e):
            continue
        if in_scope(host, domain) and e not in found:
            found.append(e)
        if len(found) >= cap:
            break
    return found


def extract_phones(anchors: list[str], cap: int = 5) -> list[str]:
    out = []
    for a in anchors:
        if a.lower().startswith("tel:"):
            num = re.sub(r"[^\d+()\- .]", "", a[4:]).strip()
            if len(re.sub(r"\D", "", num)) >= 7 and num not in out:
                out.append(num)
        if len(out) >= cap:
            break
    return out


def extract_web(page: FetchedPage, parsed: _PageParser, domain: str) -> dict:
    """Web metadata from the home page response."""
    headers = page.headers
    scripts = [urljoin(page.final_url, s) for s in parsed.scripts][:60]
    refs = scripts + [urljoin(page.final_url, h) for _, h in parsed.links]
    refs += [urljoin(page.final_url, s) for s in parsed.iframes]
    external = []
    for r in refs:
        host = urlsplit(r).hostname
        if host and not in_scope(host, domain) and host not in external:
            external.append(host)
    return {
        "final_url": page.final_url,
        "status": page.status,
        "title": parsed.title or None,
        "description": parsed.metas.get("description") or parsed.metas.get("og:description"),
        "generator": parsed.metas.get("generator"),
        "og_site_name": parsed.metas.get("og:site_name"),
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "headers": {k: v[:300] for k, v in headers.items()},
        "security_headers": {
            h: ("present" if h in headers else "missing") for h in SECURITY_HEADERS
        },
        "scripts": scripts,
        "external_hosts": external[:40],
    }


def cookie_names(set_cookies: list[str]) -> list[str]:
    names = []
    for c in set_cookies:
        name = c.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def parse_robots(text: str) -> dict | None:
    if "user-agent" not in text.lower():
        return None
    disallow, sitemaps = [], []
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.split("#")[0].strip()
        if key == "disallow" and value and value not in disallow:
            disallow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return {"present": True, "disallow": disallow[:30], "sitemaps": sitemaps[:5]}


def parse_security_txt(text: str) -> dict | None:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    fields: dict[str, list[str]] = {}
    for ln in lines:
        key, sep, value = ln.partition(":")
        if sep and not key.startswith("#") and " " not in key.strip():
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    if "contact" not in fields:
        return None
    return {
        "present": True,
        "contact": fields["contact"][:3],
        "expires": (fields.get("expires") or [None])[0],
        "policy": (fields.get("policy") or [None])[0],
    }


# ---- fetching ----

def _to_page(raw: dict) -> FetchedPage:
    return FetchedPage(
        url=raw["url"],
        final_url=raw["final_url"],
        host=urlsplit(raw["final_url"]).hostname or "",
        status=raw["status"],
        headers=raw.get("headers") or {},
        set_cookies=raw.get("set_cookies") or [],
        html=(raw.get("text") or "")[:HTML_CAP],
    )


def _fetch(kb: KnowledgeBase, url: str, emit: Emit, **kw) -> FetchedPage | None:
    raw = fetch_page(url, kb.target_id, emit, **kw)
    return _to_page(raw) if raw else None


def _home(kb: KnowledgeBase, emit: Emit) -> FetchedPage | None:
    fallback = None
    for url in (f"https://{kb.domain}/", f"https://www.{kb.domain}/", f"http://{kb.domain}/"):
        page = _fetch(kb, url, emit)
        if page is None:
            continue
        if page.status == 200:
            return page
        fallback = fallback or page
    return fallback


def _subpage_urls(home: FetchedPage, parsed: _PageParser, domain: str) -> list[str]:
    base = home.final_url if in_scope(home.host, domain) else f"https://{domain}/"
    seen = {home.final_url.rstrip("/")}
    urls = []
    for href in parsed.anchors:
        u = urljoin(base, href).split("#")[0]
        host = urlsplit(u).hostname
        keyword = SUBPAGE_KEYWORDS.search(urlsplit(u).path or "")
        if in_scope(host, domain) and keyword and u.rstrip("/") not in seen:
            seen.add(u.rstrip("/"))
            urls.append(u)
        if len(urls) >= 4:
            break
    for path in SUBPAGE_GUESSES:
        u = urljoin(base, path)
        if u.rstrip("/") not in seen:
            seen.add(u.rstrip("/"))
            urls.append(u)
    return urls[:MAX_SUBPAGES]


def collect_website(kb: KnowledgeBase, emit: Emit) -> list[FetchedPage]:
    domain = kb.domain
    try:
        home = _home(kb, emit)
        if home is None:
            kb.coverage["website"] = "failed"
            emit("discovery", "warn", f"Website: no response from {domain}", None)
            return []

        parsed = parse_html(home.html)
        kb.web.update(extract_web(home, parsed, domain))
        if not in_scope(home.host, domain):
            kb.web["redirects_to"] = home.host
            kb.add_fact("web", "Website redirects to", home.final_url, home.url, "high")

        pages = [home]
        subpages: list[FetchedPage] = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            sub_f = [pool.submit(_fetch, kb, u, emit) for u in _subpage_urls(home, parsed, domain)]
            base = home.final_url if in_scope(home.host, domain) else f"https://{domain}/"
            wk = {
                "robots": pool.submit(_fetch, kb, urljoin(base, "/robots.txt"), emit,
                                      max_body=64 * 1024),
                "security_txt": pool.submit(_fetch, kb, urljoin(base, "/.well-known/security.txt"),
                                            emit, max_body=32 * 1024),
                "sitemap": pool.submit(_fetch, kb, urljoin(base, "/sitemap.xml"), emit,
                                       max_body=256 * 1024),
            }
            finals = {home.final_url.rstrip("/")}
            for f in sub_f:
                p = f.result()
                fresh = p and p.final_url.rstrip("/") not in finals
                if fresh and p.status == 200 and in_scope(p.host, domain):
                    finals.add(p.final_url.rstrip("/"))
                    subpages.append(p)
            wk_pages = {k: f.result() for k, f in wk.items()}
        pages += subpages

        _record_well_known(kb, wk_pages)

        cookies: list[str] = []
        for p in pages:
            cookies += [c for c in cookie_names(p.set_cookies) if c not in cookies]
        kb.web["cookies"] = cookies[:30]
        kb.web["pages"] = [{"url": p.final_url, "status": p.status} for p in pages]

        _extract_company(kb, pages, home, parsed)
        _web_facts(kb, home)

        kb.coverage["website"] = "ok" if home.status == 200 else "partial"
        emit("discovery", "info",
             f"Website: {len(pages)} pages, title={kb.web.get('title')!r}, "
             f"company={kb.company.get('name')!r}", None)
        return pages
    except Exception as e:
        kb.coverage["website"] = "failed"
        emit("discovery", "warn", f"Website collector failed: {e}", None)
        return []


def _record_well_known(kb: KnowledgeBase, wk: dict[str, FetchedPage | None]) -> None:
    robots = wk.get("robots")
    info = parse_robots(robots.html) if robots and robots.status == 200 else None
    kb.web["robots"] = info or {"present": False}
    if info and info["disallow"]:
        kb.add_fact("web", "robots.txt disallows", ", ".join(info["disallow"][:12]),
                    robots.final_url, "high")

    sec = wk.get("security_txt")
    info = parse_security_txt(sec.html) if sec and sec.status == 200 else None
    kb.web["security_txt"] = info or {"present": False}
    kb.add_fact("posture", "security.txt",
                f"published ({', '.join(info['contact'])})" if info else "missing",
                sec.final_url if sec else f"https://{kb.domain}/.well-known/security.txt", "high")

    sm = wk.get("sitemap")
    present = bool(sm and sm.status == 200 and ("<urlset" in sm.html or "<sitemapindex" in sm.html))
    kb.web["sitemap"] = {"present": present,
                         "url_count": sm.html.count("<loc>") if present and sm else 0}


def _extract_company(kb: KnowledgeBase, pages: list[FetchedPage], home: FetchedPage,
                     home_parsed: _PageParser) -> None:
    domain = kb.domain
    org: dict = {}
    anchors: list[str] = []
    for p in pages:
        parsed = home_parsed if p is home else parse_html(p.html)
        for k, v in extract_jsonld_org(parsed.jsonld).items():
            org.setdefault(k, v)
        anchors += [urljoin(p.final_url, a) if not a.lower().startswith(("mailto:", "tel:"))
                    else a for a in parsed.anchors]

    name = (org.get("name") or home_parsed.metas.get("og:site_name") or org.get("site_name")
            or clean_title_name(home_parsed.title, domain))
    description = (org.get("description") or home_parsed.metas.get("description")
                   or home_parsed.metas.get("og:description"))
    socials = extract_socials(anchors + org.get("same_as", []))
    emails = extract_emails(" ".join(p.html for p in pages), anchors, domain)
    if org.get("email") and org["email"].lower().replace("mailto:", "") not in emails:
        emails.insert(0, org["email"].lower().replace("mailto:", ""))
    phones = extract_phones(anchors)
    if org.get("telephone") and org["telephone"] not in phones:
        phones.insert(0, org["telephone"])

    company = {
        "name": name,
        "legal_name": org.get("legal_name"),
        "description": description[:600] if description else None,
        "logo": org.get("logo"),
        "founded": org.get("founded"),
        "location": org.get("location"),
        "employees": org.get("employees"),
        "founders": org.get("founders"),
        "socials": socials,
        "emails": emails,
        "phones": phones[:5],
        "same_as": org.get("same_as", []),
    }
    for k, v in company.items():
        if v and not kb.company.get(k):
            kb.company[k] = v

    src = home.final_url
    conf = "high" if org.get("name") else "medium"
    labels = [("name", "Name", conf), ("legal_name", "Legal name", "high"),
              ("description", "Description", "medium"), ("founded", "Founded", "high"),
              ("location", "Location", "high"), ("employees", "Employees", "medium")]
    for key, label, c in labels:
        if company.get(key):
            kb.add_fact("company", label, company[key], src, c)
    for net, url in socials.items():
        kb.add_fact("company", f"Social: {net}", url, src, "high")
    for e in emails[:5]:
        kb.add_fact("company", "Email", e, src, "high")


def _web_facts(kb: KnowledgeBase, home: FetchedPage) -> None:
    src = home.final_url
    w = kb.web
    if w.get("title"):
        kb.add_fact("web", "Title", w["title"], src, "high")
    for key, label in (("server", "Server header"), ("powered_by", "X-Powered-By"),
                       ("generator", "Generator meta")):
        if w.get(key):
            kb.add_fact("web", label, w[key], src, "high")
    missing = [h for h, s in w.get("security_headers", {}).items() if s == "missing"]
    if missing:
        kb.add_fact("posture", "Missing security headers", ", ".join(missing), src, "high")
    if w.get("cookies"):
        kb.add_fact("web", "Cookies set", ", ".join(w["cookies"][:12]), src, "high")
    if w.get("external_hosts"):
        kb.add_fact("web", "Third-party hosts", ", ".join(w["external_hosts"][:12]), src, "high")


def probe_subdomains(kb: KnowledgeBase, emit: Emit, limit: int = 8) -> list[FetchedPage]:
    """GET / on resolved, flagged subdomains to fingerprint edge appliances and portals."""
    targets = [s for s in kb.subdomains if s.interesting and s.ips
               and in_scope(s.name, kb.domain)][:limit]
    if not targets:
        return []

    def probe(sub):
        return sub, _fetch(kb, f"https://{sub.name}/", emit, timeout=6.0, max_body=512 * 1024,
                           allow_host=lambda h: in_scope(h, kb.domain))

    pages = []
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for sub, page in pool.map(probe, targets):
                if page is None:
                    continue
                parsed = parse_html(page.html)
                sub.title = parsed.title[:160] or f"HTTP {page.status}"
                pages.append(page)
                kb.add_fact("subdomain", sub.name, f"{sub.interesting}: {sub.title}",
                            page.final_url, "medium")
        emit("discovery", "info",
             f"Probed {len(targets)} flagged subdomains, {len(pages)} responded", None)
    except Exception as e:
        emit("discovery", "warn", f"Subdomain probe failed: {e}", None)
    return pages


def fetch_in_scope(kb: KnowledgeBase, url_or_path: str, emit: Emit) -> FetchedPage | None:
    """Fetch a path or URL on the target domain only. Refuses anything off-scope."""
    raw = (url_or_path or "").strip()
    if not raw:
        return None
    if raw.startswith("/"):
        base = kb.web.get("final_url")
        if not base or not in_scope(urlsplit(base).hostname, kb.domain):
            base = f"https://{kb.domain}/"
        url = urljoin(base, raw)
    elif "://" not in raw:
        url = "https://" + raw
    else:
        url = raw
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not in_scope(parts.hostname, kb.domain):
        emit("discovery", "warn", f"Refused out-of-scope fetch: {raw[:200]}", None)
        return None
    if parts.port not in (None, 80, 443):
        emit("discovery", "warn", f"Refused non-standard port: {raw[:200]}", None)
        return None
    return _fetch(kb, url, emit, timeout=8.0, allow_host=lambda h: in_scope(h, kb.domain))
