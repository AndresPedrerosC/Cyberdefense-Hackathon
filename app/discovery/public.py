"""Public-inference discovery (passive only)."""

import re
from pathlib import Path

from app.schema import Target, StackItem, Emit
from app.ids import stack_item_id
from app.discovery.net import safe_fetch
from app.discovery.aliases import resolve_alias


# Patterns for extracting tech from public pages
VERSION_IN_URL = re.compile(r'[@/-](\d+\.\d+\.\d+)(?:[.-]|$|min\.js)')
NEXT_DATA = re.compile(r'<script[^>]*id="__NEXT_DATA__"')
REACT_ROOT = re.compile(r'data-reactroot')
NG_VERSION = re.compile(r'ng-version="([^"]+)"')
VUE_APP = re.compile(r'data-v-[a-f0-9]+')
JQUERY_VERSION = re.compile(r'jquery[.-]?(\d+\.\d+\.\d+)')


def discover_public(target: Target, run_id: str, emit: Emit) -> list[StackItem]:
    """Discover stack from public pages (passive only)."""
    if not target.domain:
        emit("discovery", "warn", "No domain for public discovery", None)
        return []

    emit("discovery", "info", f"Public discovery for {target.domain}", None)

    items = []
    seen_packages = set()

    # Seed pages
    pages = [
        f"https://{target.domain}/",
        f"https://{target.domain}/about",
        f"https://{target.domain}/careers",
    ]

    for url in pages:
        try:
            text, headers = safe_fetch(url, target.target_id, emit)
            if not text:
                continue

            # Extract from headers
            items.extend(_extract_from_headers(target, run_id, headers, url, seen_packages))

            # Extract from page content
            items.extend(_extract_from_content(target, run_id, text, url, seen_packages))

        except Exception as e:
            emit("discovery", "warn", f"Failed to fetch {url}: {e}", None)

    emit("discovery", "info", f"Public discovery found {len(items)} items", None)
    return items


def _extract_from_headers(
    target: Target, run_id: str, headers: dict, url: str, seen: set
) -> list[StackItem]:
    """Extract tech from HTTP headers."""
    items = []

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        pkg, version = _parse_powered_by(powered_by)
        if pkg and pkg not in seen:
            seen.add(pkg)
            package = resolve_alias(pkg)
            ecosystem = "npm" if package else "unknown"
            sid = stack_item_id(target.target_id, ecosystem, package or pkg, version or "")
            items.append(StackItem(
                id=sid,
                run_id=run_id,
                target_id=target.target_id,
                ecosystem=ecosystem,
                package=package,
                name=pkg,
                version=version,
                direct=False,
                confidence="medium",
                status="inferred",
                source_url=url,
                evidence=f"X-Powered-By: {powered_by}",
            ))

    return items


def _extract_from_content(
    target: Target, run_id: str, text: str, url: str, seen: set
) -> list[StackItem]:
    """Extract tech from page content."""
    items = []

    # Check for frameworks
    if NEXT_DATA.search(text) and "next" not in seen:
        seen.add("next")
        items.append(_make_item(target, run_id, "Next.js", "next", None, url, "Found __NEXT_DATA__ script tag", seen))

    if REACT_ROOT.search(text) and "react" not in seen:
        seen.add("react")
        items.append(_make_item(target, run_id, "React", "react", None, url, "Found data-reactroot attribute", seen))

    ng_match = NG_VERSION.search(text)
    if ng_match and "angular" not in seen:
        seen.add("angular")
        items.append(_make_item(target, run_id, "Angular", "@angular/core", ng_match.group(1), url, f"ng-version=\"{ng_match.group(1)}\"", seen))

    if VUE_APP.search(text) and "vue" not in seen:
        seen.add("vue")
        items.append(_make_item(target, run_id, "Vue.js", "vue", None, url, "Found Vue.js data attributes", seen))

    # Check for versioned JS files
    jquery_match = JQUERY_VERSION.search(text.lower())
    if jquery_match and "jquery" not in seen:
        seen.add("jquery")
        items.append(_make_item(target, run_id, "jQuery", "jquery", jquery_match.group(1), url, f"jquery-{jquery_match.group(1)}", seen))

    return [i for i in items if i is not None]


def _make_item(
    target: Target, run_id: str, name: str, package: str, version: str | None,
    url: str, evidence: str, seen: set
) -> StackItem | None:
    """Create a StackItem for public discovery."""
    sid = stack_item_id(target.target_id, "npm", package, version or "")
    return StackItem(
        id=sid,
        run_id=run_id,
        target_id=target.target_id,
        ecosystem="npm",
        package=package,
        name=name,
        version=version,
        direct=False,
        confidence="medium" if version else "low",
        status="inferred",
        source_url=url,
        evidence=evidence,
    )


def _parse_powered_by(header: str) -> tuple[str | None, str | None]:
    """Parse X-Powered-By header."""
    header = header.lower()
    if "express" in header:
        return "Express", None
    if "next.js" in header:
        return "Next.js", None
    if "php" in header:
        return None, None  # Not npm
    return header, None
