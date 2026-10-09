"""TLS certificate collector for the apex domain."""

import socket
import ssl
from datetime import UTC, datetime

from app.discovery.net import resolve_and_check
from app.recon.kb import KnowledgeBase
from app.schema import Emit

TIMEOUT = 6.0


def _name(rdns) -> dict:
    """ssl getpeercert() name tuple -> {key: value}."""
    out = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out[key] = value
    return out


def parse_peercert(cert: dict) -> dict:
    """Normalize ssl.getpeercert() output."""
    issuer, subject = _name(cert.get("issuer")), _name(cert.get("subject"))
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    out = {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "subject": subject.get("commonName"),
        "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:100],
    }
    if not_before:
        out["not_before"] = _iso(ssl.cert_time_to_seconds(not_before))
    if not_after:
        expiry = ssl.cert_time_to_seconds(not_after)
        out["not_after"] = _iso(expiry)
        out["days_left"] = int((expiry - datetime.now(UTC).timestamp()) // 86400)
    return out


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat()


def _parse_der(der: bytes) -> dict:
    """Parse an unverified cert with `cryptography` when available."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return {}
    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else None

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = sans.value.get_values_for_type(x509.DNSName)[:100]
    except x509.ExtensionNotFound:
        dns_names = []
    not_after = cert.not_valid_after_utc
    return {
        "issuer": attr(cert.issuer, NameOID.ORGANIZATION_NAME)
        or attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_cn": attr(cert.issuer, NameOID.COMMON_NAME),
        "subject": attr(cert.subject, NameOID.COMMON_NAME),
        "sans": dns_names,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(UTC)).days,
    }


def _handshake(host: str, ip: str, verify: bool) -> tuple[dict, str | None, bytes | None]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((ip, 443), timeout=TIMEOUT) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls,
    ):
        return tls.getpeercert() or {}, tls.version(), tls.getpeercert(binary_form=True)


def collect_tls(kb: KnowledgeBase, emit: Emit) -> None:
    host = kb.domain
    ip = resolve_and_check(host)
    if ip is None:
        kb.coverage["tls"] = "skipped"
        emit("discovery", "warn", f"TLS: {host} did not resolve to a public address", None)
        return
    source = f"tls://{host}:443"
    try:
        try:
            cert, version, _ = _handshake(host, ip, verify=True)
            info = parse_peercert(cert)
            info["valid"] = True
        except ssl.SSLCertVerificationError as e:
            kb.add_fact("posture", "TLS certificate", f"fails validation: {e.verify_message}",
                        source, "high")
            _, version, der = _handshake(host, ip, verify=False)
            info = _parse_der(der) if der else {}
            info["valid"] = False
            info["error"] = e.verify_message
        info["version"] = version
        kb.infra["tls"] = info

        if info.get("issuer"):
            kb.add_fact("infra", "TLS issuer", info["issuer"], source, "high")
        if info.get("not_after"):
            kb.add_fact("infra", "TLS expires",
                        f"{info['not_after'][:10]} ({info.get('days_left')} days)", source, "high")
        if version:
            kb.add_fact("infra", "TLS version", version, source, "high")
        sans = [s for s in info.get("sans", []) if s != host and not s.startswith("*.")]
        if sans:
            kb.add_fact("infra", "Certificate SANs", ", ".join(sans[:12]), source, "high")
        kb.coverage["tls"] = "ok" if info.get("valid") else "partial"
        emit("discovery", "info",
             f"TLS: {version}, issuer={info.get('issuer') or '?'}, "
             f"{info.get('days_left', '?')} days left", None)
    except Exception as e:
        kb.coverage["tls"] = "failed"
        emit("discovery", "warn", f"TLS collector failed: {e}", None)
