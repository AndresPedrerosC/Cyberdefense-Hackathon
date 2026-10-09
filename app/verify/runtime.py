"""Runtime verification checks (GET only, authorized hosts only)."""

from urllib.parse import urlparse

import httpx

from app.schema import Candidate, Emit


def check_runtime(
    candidates: list[Candidate],
    deploy_url: str,
    allowed_hosts: list[str],
    emit: Emit,
) -> dict[str, dict]:
    """Run non-destructive runtime checks against authorized deployment."""
    results = {}

    # Parse and validate deploy URL
    parsed = urlparse(deploy_url)
    host_port = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname

    if host_port not in allowed_hosts and parsed.hostname not in allowed_hosts:
        emit("verification", "error", f"Deploy host {host_port} not in allowed_hosts", None)
        return results

    emit("verification", "info", f"Runtime checks against {deploy_url}", None)

    # Basic connectivity check
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(deploy_url)

            # Check for version headers
            server = response.headers.get("server", "")
            powered_by = response.headers.get("x-powered-by", "")

            if server or powered_by:
                emit("verification", "info", f"Server: {server}, X-Powered-By: {powered_by}", None)

    except Exception as e:
        emit("verification", "warn", f"Runtime check failed: {e}", None)

    return results
