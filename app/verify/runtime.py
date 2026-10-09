"""Runtime verification checks (GET only, authorized hosts only)."""

from urllib.parse import urlparse

import httpx

from app.schema import Candidate, Emit

ALLOWED_SCHEMES = ("http", "https")


def deploy_url_refusal(deploy_url: str, allowed_hosts: list[str]) -> str | None:
    """Return why deploy_url must not be contacted, or None if it is in scope."""
    try:
        parsed = urlparse(deploy_url)
        port = parsed.port
    except ValueError:
        return "Deploy URL is malformed"
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"Deploy URL scheme {parsed.scheme!r} not allowed"
    if not parsed.hostname:
        return "Deploy URL has no hostname"
    if parsed.username is not None or parsed.password is not None:
        return "Deploy URL must not carry credentials"
    host_port = f"{parsed.hostname}:{port}" if port else parsed.hostname
    if host_port not in allowed_hosts and parsed.hostname not in allowed_hosts:
        return f"Deploy host {host_port} not in allowed_hosts"
    return None


def check_runtime(
    candidates: list[Candidate],
    deploy_url: str,
    allowed_hosts: list[str],
    emit: Emit,
) -> dict[str, dict]:
    """Run non-destructive runtime checks against authorized deployment."""
    results = {}

    refusal = deploy_url_refusal(deploy_url, allowed_hosts)
    if refusal:
        emit("verification", "error", refusal, None)
        return results

    emit("verification", "info", f"Runtime checks against {deploy_url}", None)

    try:
        # Redirects could leave the allowlisted host, so never follow them.
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            response = client.get(deploy_url)

            server = response.headers.get("server", "")
            powered_by = response.headers.get("x-powered-by", "")

            if server or powered_by:
                emit("verification", "info", f"Server: {server}, X-Powered-By: {powered_by}", None)

    except Exception as e:
        emit("verification", "warn", f"Runtime check failed: {e}", None)

    return results
