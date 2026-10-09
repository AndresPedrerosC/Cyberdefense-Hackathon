"""Summarize what recon observed into kb.stack, so the knowledge base lists the services in use.

This only restates evidence the collectors already recorded (ASN owner, nameservers, MX, TLS
issuer, response headers, app bundle, third-party hosts). It does not probe anything.
"""

from app.recon.kb import KnowledgeBase, Tech

NS_PROVIDERS = [
    ("cloudflare.com", "Cloudflare DNS"), ("awsdns", "Amazon Route 53"),
    ("domaincontrol.com", "GoDaddy DNS"), ("googledomains.com", "Google Domains DNS"),
    ("google.com", "Google Cloud DNS"), ("azure-dns", "Azure DNS"), ("nsone.net", "NS1"),
    ("dnsimple", "DNSimple"), ("vercel-dns.com", "Vercel DNS"), ("netlify", "Netlify DNS"),
    ("registrar-servers.com", "Namecheap DNS"), ("digitalocean.com", "DigitalOcean DNS"),
    ("ultradns", "UltraDNS"), ("dynect.net", "Oracle Dyn"), ("akam.net", "Akamai Edge DNS"),
    ("wixdns.net", "Wix DNS"), ("squarespacedns", "Squarespace DNS"), ("hostgator", "HostGator"),
]
# Headers whose presence identifies the edge or platform serving the site.
HEADER_PLATFORMS = [
    ("x-vercel-id", "Vercel", "hosting"), ("x-nf-request-id", "Netlify", "hosting"),
    ("cf-ray", "Cloudflare", "cdn"), ("x-amz-cf-id", "Amazon CloudFront", "cdn"),
    ("x-served-by", "Fastly", "cdn"), ("x-github-request-id", "GitHub Pages", "hosting"),
    ("x-azure-ref", "Azure Front Door", "cdn"), ("x-shopify-stage", "Shopify", "ecommerce"),
    ("x-wix-request-id", "Wix", "hosting"), ("fly-request-id", "Fly.io", "hosting"),
    ("x-render-origin-server", "Render", "hosting"), ("x-railway-request-id", "Railway",
                                                         "hosting"),
]
THIRD_PARTY = [
    ("fonts.googleapis.com", "Google Fonts", "saas"), ("fonts.gstatic.com", "Google Fonts",
                                                        "saas"),
    ("googletagmanager.com", "Google Tag Manager", "analytics"),
    ("google-analytics.com", "Google Analytics", "analytics"),
    ("cdn.segment.com", "Segment", "analytics"), ("static.hotjar.com", "Hotjar", "analytics"),
    ("js.stripe.com", "Stripe", "saas"), ("widget.intercom.io", "Intercom", "saas"),
    ("js.hs-scripts.com", "HubSpot", "saas"), ("cdn.jsdelivr.net", "jsDelivr", "cdn"),
    ("unpkg.com", "unpkg", "cdn"), ("cdnjs.cloudflare.com", "cdnjs", "cdn"),
    ("www.google.com/recaptcha", "reCAPTCHA", "security"),
    ("challenges.cloudflare.com", "Cloudflare Turnstile", "security"),
    ("plausible.io", "Plausible Analytics", "analytics"), ("cdn.vercel-insights.com",
                                                           "Vercel Analytics", "analytics"),
    ("calendly.com", "Calendly", "saas"), ("typeform.com", "Typeform", "saas"),
]


def derive_stack(kb: KnowledgeBase) -> None:
    site = kb.web.get("final_url") or f"https://{kb.domain}/"
    add = lambda name, cat, ev, src, conf="high", ver=None: kb.add_tech(Tech(
        name=name, category=cat, version=ver, confidence=conf, evidence=ev, source=src))

    if kb.infra.get("hosting"):
        asns = ", ".join(sorted({f"AS{i.get('asn')}" for i in kb.infra.get("ips") or []
                                 if i.get("asn")}))
        add(kb.infra["hosting"], "hosting", f"IP space announced by {asns or 'its ASN'}",
            "Team Cymru IP-to-ASN")
    for ns in kb.dns.get("ns") or []:
        hit = next((name for frag, name in NS_PROVIDERS if frag in ns.lower()), None)
        if hit:
            add(hit, "dns", f"Nameserver {ns}", "dns:NS")
            break
    if kb.mail.get("provider"):
        add(kb.mail["provider"], "mail", "MX records point to this provider", "dns:MX")
    for p in (kb.mail.get("spf") or {}).get("providers") or []:
        if p != kb.mail.get("provider"):
            add(p, "mail", "Authorized to send mail in SPF", "dns:TXT", "medium")
    tls = kb.infra.get("tls") or {}
    if tls.get("issuer"):
        add(tls["issuer"], "certificate", "Issued the site's TLS certificate", f"tls:{kb.domain}")
    if kb.infra.get("registrar"):
        add(kb.infra["registrar"], "registrar", "Registrar of record", "rdap")

    headers = kb.web.get("headers") or {}
    for header, name, cat in HEADER_PLATFORMS:
        if header in headers:
            add(name, cat, f"{header}: {str(headers[header])[:80]}", site)
    platforms = {t.name.lower().split()[0] for t in kb.stack}
    server = str(kb.web.get("server") or "")
    if server and server.split("/")[0].split(".")[0].lower() not in platforms:
        name, _, ver = str(kb.web["server"]).partition("/")
        add(name.strip() or kb.web["server"], "web-server", f"Server: {kb.web['server']}", site,
            "high", ver.split()[0] if ver else None)
    if kb.web.get("powered_by"):
        add(str(kb.web["powered_by"]), "framework", f"X-Powered-By: {kb.web['powered_by']}",
            site, "medium")
    if kb.web.get("generator"):
        add(str(kb.web["generator"]), "cms", f"Generator meta: {kb.web['generator']}", site)

    spa = kb.web.get("spa") or {}
    bundle = (spa.get("bundles") or [{}])[0].get("url", site)
    for name in spa.get("build") or []:
        add(name, "framework", "Asset naming in the app bundle", bundle, "medium")
    for name in spa.get("frameworks") or []:
        add(name, "js-library", "Library code found in the app bundle", bundle, "medium")

    refs = (kb.web.get("external_hosts") or []) + (kb.web.get("scripts") or [])
    for frag, name, cat in THIRD_PARTY:
        hit = next((r for r in refs if frag in str(r)), None)
        if hit:
            add(name, cat, f"Loads {str(hit)[:100]}", site)
    for f in kb.facts:
        if f.category == "stack" and f.by == "recon" and "verification" in f.key.lower():
            for name in [v.strip() for v in f.value.split(",") if v.strip()][:12]:
                add(name, "saas", "Domain ownership verified in DNS TXT", "dns:TXT", "medium")
