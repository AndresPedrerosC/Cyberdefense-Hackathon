"""Reads single-page apps whose HTML is an empty shell.

Sites built with Vite, CRA or similar ship an almost empty index.html and keep every word of
copy inside the JS bundle. When the homepage has no visible text, fetch the site's own bundles
(same host, size-capped, SSRF-safe) and pull out what a visitor would read: copy strings,
in-app routes, outbound links and contact addresses.
"""

import re
from urllib.parse import urljoin, urlsplit

from app.discovery.net import fetch_page
from app.recon.domain import in_scope
from app.recon.kb import FetchedPage, KnowledgeBase
from app.schema import Emit

THIN_TEXT = 200  # visible characters below which a page is treated as an app shell
MAX_BUNDLES = 4
BUNDLE_CAP = 4 * 1024 * 1024
COPY_CAP = 12000

# A quoted JS string literal; copy is mined from these only, never from code.
STRING_LIT = re.compile(r'"((?:[^"\\\n]|\\.){12,600})"|\'((?:[^\'\\\n]|\\.){12,600})\''
                        r'|`((?:[^`\\]|\\.){12,600})`')
ROUTE_LIT = re.compile(r'["\'`](/[a-z0-9][a-z0-9\-_/]{1,60})["\'`]', re.IGNORECASE)
URL_LIT = re.compile(r'https?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:/[^\s"\'`<>\\)]*)?')
EMAIL_LIT = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
CODEISH = re.compile(r"[{};=<>]|=>|\b(function|return|const|var|let|null|undefined|"
                     r"prototype|webpack|__|\.js|\.css|rgba?\(|#[0-9a-f]{3,8}\b)|\d(px|rem|em|ms|vh|vw)\b",
                     re.IGNORECASE)
# Library and framework messages that look like prose; site copy rarely uses these words.
DEV_WORDS = re.compile(
    r"\b(react|gsap|vue|svelte|angular|route|routes|plugin|listener|render|rendering|props?|"
    r"component|hooks?|children|child|element|attribute|warning|error|invalid|undefined|null|"
    r"deprecated|polyfill|browser|window|document|dom|node|function|callback|instance|"
    r"keydown|keyup|mouse\w*|focus\w*|wheel|scroll\w*|trigger|tween|timeline|selector|"
    r"minified|stack|super\(\)|initiali[sz]ed|snapshot|hydrat\w*|suspense|context|"
    r"canvas|webgl|shader|buffer|texture|percent|segment|decoded|encoded)\b",
    re.IGNORECASE)
NOISE_HOSTS = ("w3.org", "reactjs.org", "react.dev", "vitejs.dev", "schema.org", "mozilla.org",
               "github.com/facebook", "fb.me", "googleapis.com", "gstatic.com")
FRAMEWORK_HINTS = [
    ("React", re.compile(r"react-dom|__reactFiber|createRoot\(|react\.element")),
    ("Vue", re.compile(r"__vue_app__|createApp\(|vue\.runtime")),
    ("Svelte", re.compile(r"svelte-[a-z0-9]{6}|\$\$props")),
    ("Angular", re.compile(r"ng-version|ɵcmp|platformBrowser")),
    ("Preact", re.compile(r"preact")),
    ("Three.js", re.compile(r"WebGLRenderer|THREE\.")),
    ("Framer Motion", re.compile(r"framer-motion|useAnimation\(")),
    ("GSAP", re.compile(r"gsap\.|ScrollTrigger")),
]
BUILD_HINTS = [
    ("Vite", re.compile(r"/assets/[\w-]+-[A-Za-z0-9_-]{8}\.js$")),
    ("Create React App", re.compile(r"/static/js/main\.[0-9a-f]{8}\.js$")),
    ("Next.js", re.compile(r"/_next/static/")),
    ("Nuxt", re.compile(r"/_nuxt/")),
    ("Gatsby", re.compile(r"/(app|framework)-[0-9a-f]{20}\.js$")),
]


def is_shell(visible_text: str, scripts: list[str]) -> bool:
    return len(visible_text) < THIN_TEXT and bool(scripts)


def bundle_urls(home: FetchedPage, scripts: list[str], domain: str) -> list[str]:
    """Same-site script URLs, app bundles first."""
    urls = []
    for src in scripts:
        u = urljoin(home.final_url, src)
        if in_scope(urlsplit(u).hostname, domain) and u not in urls:
            urls.append(u)
    urls.sort(key=lambda u: 0 if re.search(r"(index|main|app)[.-]", u) else 1)
    return urls[:MAX_BUNDLES]


def mine_bundle(js: str) -> dict:
    """Human-readable copy, routes, outbound links and emails found in a JS bundle."""
    copy: list[str] = []
    seen = set()
    for m in STRING_LIT.finditer(js):
        s = next(g for g in m.groups() if g is not None)
        s = s.encode().decode("unicode_escape", "ignore") if "\\u" in s else s
        s = " ".join(s.replace("\\n", " ").split())
        if not _is_copy(s) or s.lower() in seen:
            continue
        seen.add(s.lower())
        copy.append(s)
    routes = sorted({r for r in ROUTE_LIT.findall(js)
                     if not re.search(r"\.(js|css|png|jpe?g|svg|webp|ico|woff2?|json)$", r)
                     and not r.startswith(("/assets", "/static", "/node_modules", "/src"))})[:40]
    links = []
    for u in URL_LIT.findall(js):
        u = u.rstrip(".,;")
        if not any(n in u for n in NOISE_HOSTS) and u not in links:
            links.append(u)
    emails = sorted({e for e in EMAIL_LIT.findall(js) if not e.lower().endswith((".png", ".js"))})
    return {"copy": copy, "routes": routes, "links": links[:60], "emails": emails[:10]}


def _is_copy(s: str) -> bool:
    """Heuristic: does this string read like text a visitor would see?"""
    if len(s) < 12 or len(s.split()) < 3 or CODEISH.search(s) or DEV_WORDS.search(s):
        return False
    if not (s[0].isupper() or s[0].isdigit()):
        return False
    if any(t in s for t in ("(", ")", "&&", "||", "`", "\\", "?.", "...")):
        return False
    return sum(c.isalpha() or c.isspace() for c in s) >= len(s) * 0.85


def read_spa(kb: KnowledgeBase, home: FetchedPage, scripts: list[str], emit: Emit) -> str:
    """Fetch and mine the bundles. Records kb.web['spa'] and returns the copy text for the agent."""
    urls = bundle_urls(home, scripts, kb.domain)
    if not urls:
        return ""
    emit("discovery", "info",
         f"Homepage is an app shell with no text; reading {len(urls)} JS bundle(s)", None)
    copy: list[str] = []
    routes: list[str] = []
    links: list[str] = []
    emails: list[str] = []
    frameworks: list[str] = []
    read = []
    for url in urls:
        raw = fetch_page(url, kb.target_id, emit, max_body=BUNDLE_CAP,
                         allow_host=lambda h: in_scope(h, kb.domain))
        if not raw or raw.get("status") != 200 or not raw.get("text"):
            continue
        js = raw["text"]
        mined = mine_bundle(js)
        read.append({"url": url, "bytes": len(js)})
        copy += [c for c in mined["copy"] if c not in copy]
        routes += [r for r in mined["routes"] if r not in routes]
        links += [u for u in mined["links"] if u not in links]
        emails += [e for e in mined["emails"] if e not in emails]
        frameworks += [n for n, rx in FRAMEWORK_HINTS if rx.search(js) and n not in frameworks]
    builds = [n for n, rx in BUILD_HINTS if any(rx.search(u) for u in urls)]

    text = "\n".join(copy)[:COPY_CAP]
    kb.web["spa"] = {"bundles": read, "routes": routes[:40], "links": links[:60],
                     "emails": emails, "frameworks": frameworks, "build": builds,
                     "copy": text.split("\n")}
    emit("discovery", "info",
         f"App bundle: {len(copy)} text strings, {len(routes)} routes, {len(links)} links"
         + (f", built with {', '.join(builds + frameworks)}" if builds or frameworks else ""),
         None)
    return text
