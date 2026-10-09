"""DNS, mail-authentication and ASN collectors (dnspython against public resolvers)."""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from app.recon.kb import KnowledgeBase
from app.schema import Emit

RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# SPF include/redirect domain fragment -> provider
SPF_PROVIDERS = [
    ("_spf.google.com", "Google Workspace"),
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("servers.mcsv.net", "Mailchimp"),
    ("spf.mandrillapp.com", "Mandrill (Mailchimp)"),
    ("sendgrid.net", "SendGrid"),
    ("amazonses.com", "Amazon SES"),
    ("mailgun.org", "Mailgun"),
    ("_spf.salesforce.com", "Salesforce"),
    ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("zendesk.com", "Zendesk"),
    ("hubspotemail.net", "HubSpot"),
    ("_spf.hubspot", "HubSpot"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("mktomail.com", "Marketo"),
    ("spf.mtasv.net", "Postmark"),
    ("sparkpostmail.com", "SparkPost"),
    ("zoho.com", "Zoho Mail"),
    ("freshdesk.com", "Freshdesk"),
    ("helpscoutemail.com", "Help Scout"),
    ("intercom.io", "Intercom"),
    ("atlassian.net", "Atlassian"),
    ("mailjet.com", "Mailjet"),
    ("cust-spf.exacttarget.com", "Salesforce Marketing Cloud"),
    ("emsd1.com", "Emarsys"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("barracudanetworks.com", "Barracuda"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("icloud.com", "iCloud Mail"),
    ("secureserver.net", "GoDaddy"),
]

# MX host fragment -> provider
MX_PROVIDERS = [
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("iphmx.com", "Cisco Secure Email"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("amazonaws.com", "Amazon SES / WorkMail"),
    ("mailgun.org", "Mailgun"),
    ("secureserver.net", "GoDaddy"),
    ("emailsrvr.com", "Rackspace Email"),
    ("icloud.com", "iCloud Mail"),
    ("fastmail.com", "Fastmail"),
    ("messagingengine.com", "Fastmail"),
    ("protonmail.ch", "Proton Mail"),
    ("yandex.net", "Yandex Mail"),
    ("qq.com", "Tencent Mail"),
    ("cloudflare.net", "Cloudflare Email Routing"),
    ("cf-emailsecurity.net", "Cloudflare Email Security"),
    ("area1security.com", "Cloudflare Email Security"),
    ("trendmicro.com", "Trend Micro Email Security"),
    ("sophos.com", "Sophos Email"),
    ("forcepoint.com", "Forcepoint Email Security"),
    ("hornetsecurity.com", "Hornetsecurity"),
    ("antispamcloud.com", "SpamExperts"),
]

# TXT verification token prefix -> SaaS vendor
TXT_VERIFICATIONS = [
    ("google-site-verification=", "Google (Search Console / Workspace)"),
    ("ms=", "Microsoft 365"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("facebook-domain-verification=", "Meta (Facebook)"),
    ("docusign=", "DocuSign"),
    ("stripe-verification=", "Stripe"),
    ("apple-domain-verification=", "Apple"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("adobe-sign-verification=", "Adobe Sign"),
    ("zoom-domain-verification", "Zoom"),
    ("slack-domain-verification=", "Slack"),
    ("hubspot-developer-verification=", "HubSpot"),
    ("dropbox-domain-verification=", "Dropbox"),
    ("onetrust-domain-verification=", "OneTrust"),
    ("cisco-ci-domain-verification=", "Cisco Webex"),
    ("webexdomainverification", "Cisco Webex"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("_globalsign-domain-verification=", "GlobalSign"),
    ("amazonses:", "Amazon SES"),
    ("mailchimp=", "Mailchimp"),
    ("miro-verification=", "Miro"),
    ("notion-domain-verification=", "Notion"),
    ("openai-domain-verification=", "OpenAI"),
    ("anthropic-domain-verification", "Anthropic"),
    ("figma-domain-verification=", "Figma"),
    ("github-verification", "GitHub"),
    ("gitlab-pages-verification", "GitLab"),
    ("okta-verification", "Okta"),
    ("duo_sso_verification", "Cisco Duo"),
    ("salesforce", "Salesforce"),
    ("zendeskverification", "Zendesk"),
    ("pardot", "Salesforce Pardot"),
    ("klaviyo-site-verification", "Klaviyo"),
    ("canva-site-verification", "Canva"),
    ("airtable-verification", "Airtable"),
    ("asv=", "Asana"),
    ("loom-site-verification", "Loom"),
    ("wiz-domain-verification", "Wiz"),
    ("knowbe4-site-verification", "KnowBe4"),
    ("logmein-verification-code", "LogMeIn"),
    ("teamviewer-sso-verification", "TeamViewer"),
    ("yandex-verification", "Yandex"),
    ("have-i-been-pwned-verification", "Have I Been Pwned"),
    ("brave-ledger-verification", "Brave"),
    ("twilio-domain-verification", "Twilio"),
    ("intercom-verification", "Intercom"),
    ("1password-site-verification", "1Password"),
    ("lastpass-verification-code", "LastPass"),
    ("citrix-verification-code", "Citrix"),
    ("box-domain-verification", "Box"),
    ("smartsheet-site-validation", "Smartsheet"),
    ("status-page-domain-verification", "Atlassian Statuspage"),
]

DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "default", "s1", "s2", "mandrill", "mxvault",
]

HOSTING_ORGS = [
    ("amazon", "AWS"),
    ("aws", "AWS"),
    ("cloudflare", "Cloudflare"),
    ("google", "Google Cloud"),
    ("microsoft", "Microsoft Azure"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("digitalocean", "DigitalOcean"),
    ("ovh", "OVHcloud"),
    ("hetzner", "Hetzner"),
    ("linode", "Akamai (Linode)"),
    ("vultr", "Vultr"),
    ("choopa", "Vultr"),
    ("oracle", "Oracle Cloud"),
    ("alibaba", "Alibaba Cloud"),
    ("incapsula", "Imperva"),
    ("imperva", "Imperva"),
    ("automattic", "WordPress.com (Automattic)"),
    ("github", "GitHub"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
    ("shopify", "Shopify"),
    ("squarespace", "Squarespace"),
    ("wix", "Wix"),
    ("godaddy", "GoDaddy"),
    ("leaseweb", "Leaseweb"),
    ("rackspace", "Rackspace"),
    ("ibm", "IBM Cloud"),
    ("edgecast", "Edgio"),
    ("stackpath", "StackPath"),
]

SPF_MECH = re.compile(r"^([+\-~?]?)(all|include|redirect|a|mx|ip4|ip6|ptr|exists)(?:[:=](\S+))?$")


def _resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(RESOLVERS)
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def lookup(name: str, rtype: str, timeout: float = 4.0) -> list[str]:
    """Resolve name/rtype via public resolvers; text form, [] on NXDOMAIN, no answer or timeout."""
    try:
        answer = _resolver(timeout).resolve(name, rtype.upper(), raise_on_no_answer=False)
    except (dns.exception.DNSException, ValueError):
        return []
    if answer.rrset is None:
        return []
    out = []
    for rdata in answer:
        if rtype.upper() == "TXT":
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        else:
            out.append(rdata.to_text())
    return out


# ---- pure parsers ----

def parse_mx(records: list[str]) -> list[dict]:
    """'10 aspmx.l.google.com.' -> [{priority, host}] sorted by priority."""
    out = []
    for rec in records:
        parts = rec.split()
        if len(parts) == 2 and parts[0].isdigit():
            out.append({"priority": int(parts[0]), "host": parts[1].rstrip(".").lower()})
    return sorted(out, key=lambda m: (m["priority"], m["host"]))


def mx_provider(hosts: list[str]) -> str | None:
    for host in hosts:
        h = host.lower().rstrip(".")
        for frag, provider in MX_PROVIDERS:
            if h == frag or h.endswith("." + frag):
                return provider
    return None


def parse_spf(txt_records: list[str]) -> dict | None:
    """Parse the v=spf1 record: includes, redirect, all qualifier, inferred providers."""
    records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not records:
        return None
    record = records[0]
    includes, ip_count, all_q, redirect = [], 0, None, None
    for term in record.split()[1:]:
        m = SPF_MECH.match(term.lower())
        if not m:
            continue
        qual, mech, value = m.groups()
        if mech == "include" and value:
            includes.append(value)
        elif mech == "redirect" and value:
            redirect = value
        elif mech in ("ip4", "ip6"):
            ip_count += 1
        elif mech == "all":
            all_q = (qual or "+") + "all"
    providers = []
    for inc in includes + ([redirect] if redirect else []):
        for frag, provider in SPF_PROVIDERS:
            if frag in inc and provider not in providers:
                providers.append(provider)
    return {
        "record": record,
        "includes": includes,
        "redirect": redirect,
        "ip_mechanisms": ip_count,
        "all": all_q,
        "providers": providers,
        "multiple_records": len(records) > 1,
    }


def parse_dmarc(txt_records: list[str]) -> dict | None:
    records = [t for t in txt_records if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not records:
        return None
    record = records[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    pct = tags.get("pct")
    return {
        "record": record,
        "policy": tags.get("p", "").lower() or None,
        "subdomain_policy": tags.get("sp", "").lower() or None,
        "pct": int(pct) if pct and pct.isdigit() else 100,
        "rua": rua,
    }


def txt_verifications(txt_records: list[str]) -> list[str]:
    """SaaS vendors that the domain has verified ownership with."""
    vendors = []
    for txt in txt_records:
        t = txt.lower().strip()
        for prefix, vendor in TXT_VERIFICATIONS:
            if t.startswith(prefix) and vendor not in vendors:
                vendors.append(vendor)
    return vendors


def parse_cymru_origin(txt: str) -> dict | None:
    """'13335 | 104.16.0.0/13 | US | arin | 2014-03-28' -> {asn, prefix, country}."""
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 3 or not parts[0]:
        return None
    return {"asn": parts[0].split()[0], "prefix": parts[1], "country": parts[2]}


def parse_cymru_asname(txt: str) -> str | None:
    """'13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US' -> 'CLOUDFLARENET, US'."""
    parts = [p.strip() for p in txt.split("|")]
    return parts[4] if len(parts) >= 5 and parts[4] else None


def hosting_from_org(org: str | None) -> str | None:
    if not org:
        return None
    o = org.lower()
    for frag, name in HOSTING_ORGS:
        if frag in o:
            return name
    return None


# ---- collectors ----

def _dnssec(domain: str) -> bool | None:
    """True when the resolver validates the zone (AD flag), None when it cannot tell."""
    try:
        q = dns.message.make_query(domain, dns.rdatatype.SOA, want_dnssec=True)
        q.flags |= dns.flags.AD
        resp = dns.query.udp(q, RESOLVERS[0], timeout=4.0)
        return bool(resp.flags & dns.flags.AD)
    except Exception:
        return None


def collect_dns(kb: KnowledgeBase, emit: Emit) -> None:
    domain = kb.domain
    try:
        queries = {
            "a": (domain, "A"), "aaaa": (domain, "AAAA"), "ns": (domain, "NS"),
            "mx": (domain, "MX"), "txt": (domain, "TXT"), "caa": (domain, "CAA"),
            "soa": (domain, "SOA"), "cname": (domain, "CNAME"),
            "www_a": (f"www.{domain}", "A"), "www_cname": (f"www.{domain}", "CNAME"),
            "dnskey": (domain, "DNSKEY"),
        }
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {k: pool.submit(lookup, n, t) for k, (n, t) in queries.items()}
            res = {k: f.result() for k, f in futures.items()}

        mx = parse_mx(res["mx"])
        kb.dns.update({
            "a": res["a"],
            "aaaa": res["aaaa"],
            "ns": sorted(n.rstrip(".").lower() for n in res["ns"]),
            "mx": mx,
            "txt": res["txt"][:40],
            "caa": res["caa"],
            "soa": res["soa"][0] if res["soa"] else None,
            "cname": res["cname"][0].rstrip(".") if res["cname"] else None,
            "www": {
                "a": res["www_a"],
                "cname": res["www_cname"][0].rstrip(".") if res["www_cname"] else None,
            },
            "dnskey": bool(res["dnskey"]),
            "dnssec": _dnssec(domain) if res["dnskey"] else False,
        })

        src = "dns"
        for ip in res["a"]:
            kb.add_fact("dns", "A", ip, f"{src}:A", "high")
        for ns in kb.dns["ns"]:
            kb.add_fact("dns", "NS", ns, f"{src}:NS", "high")
        for m in mx:
            kb.add_fact("dns", "MX", f"{m['priority']} {m['host']}", f"{src}:MX", "high")
        if kb.dns["www"]["cname"]:
            kb.add_fact("dns", "www CNAME", kb.dns["www"]["cname"], f"{src}:CNAME", "high")
        if res["caa"]:
            kb.add_fact("dns", "CAA", ", ".join(res["caa"][:4]), f"{src}:CAA", "high")
        kb.add_fact("dns", "DNSSEC", "signed" if kb.dns["dnssec"] else "not validated",
                    f"{src}:DNSKEY", "medium")

        if not res["a"] and not res["aaaa"] and not res["ns"]:
            kb.coverage["dns"] = "failed"
            emit("discovery", "warn", f"DNS: no records found for {domain}", None)
        else:
            kb.coverage["dns"] = "ok"
            emit("discovery", "info",
                 f"DNS: {len(res['a'])} A, {len(kb.dns['ns'])} NS, {len(mx)} MX, "
                 f"{len(res['txt'])} TXT", None)
    except Exception as e:
        kb.coverage["dns"] = "failed"
        emit("discovery", "warn", f"DNS collector failed: {e}", None)


def collect_mail(kb: KnowledgeBase, emit: Emit) -> None:
    domain = kb.domain
    try:
        txt = kb.dns.get("txt") or lookup(domain, "TXT")
        mx = kb.dns.get("mx") or parse_mx(lookup(domain, "MX"))
        with ThreadPoolExecutor(max_workers=8) as pool:
            dmarc_f = pool.submit(lookup, f"_dmarc.{domain}", "TXT")
            sts_f = pool.submit(lookup, f"_mta-sts.{domain}", "TXT")
            bimi_f = pool.submit(lookup, f"default._bimi.{domain}", "TXT")
            dkim_f = {s: pool.submit(lookup, f"{s}._domainkey.{domain}", "TXT")
                      for s in DKIM_SELECTORS}
            dmarc_txt, sts, bimi = dmarc_f.result(), sts_f.result(), bimi_f.result()
            dkim = [s for s, f in dkim_f.items()
                    if any("p=" in r.lower() or "v=dkim1" in r.lower() for r in f.result())]

        spf = parse_spf(txt)
        dmarc = parse_dmarc(dmarc_txt)
        provider = mx_provider([m["host"] for m in mx])
        kb.mail.update({
            "provider": provider,
            "mx_hosts": [m["host"] for m in mx],
            "spf": spf,
            "dmarc": dmarc,
            "mta_sts": sts[0] if sts else None,
            "bimi": bimi[0] if bimi else None,
            "dkim_selectors": dkim,
            "null_mx": any(m["host"] in ("", ".") for m in mx),
        })

        if provider:
            kb.add_fact("mail", "Mail provider", provider, "dns:MX", "high")
        elif mx:
            kb.add_fact("mail", "Mail provider", f"self-hosted or unknown ({mx[0]['host']})",
                        "dns:MX", "low")
        else:
            kb.add_fact("mail", "Mail provider", "no MX records", "dns:MX", "high")
        if spf:
            kb.add_fact("mail", "SPF", spf["record"], "dns:TXT", "high")
            for p in spf["providers"]:
                kb.add_fact("mail", "Authorized sender", p, "dns:TXT (SPF include)", "high")
        else:
            kb.add_fact("mail", "SPF", "missing", "dns:TXT", "high")
        if dmarc:
            kb.add_fact("mail", "DMARC policy", dmarc["policy"] or "none", f"dns:_dmarc.{domain}",
                        "high")
        else:
            kb.add_fact("mail", "DMARC", "missing", f"dns:_dmarc.{domain}", "high")
        if sts:
            kb.add_fact("mail", "MTA-STS", "published", f"dns:_mta-sts.{domain}", "high")
        if dkim:
            kb.add_fact("mail", "DKIM selectors", ", ".join(dkim), "dns:_domainkey", "high")

        for vendor in txt_verifications(txt):
            kb.add_fact("stack", "SaaS (DNS verification)", vendor, "dns:TXT", "medium")

        kb.coverage["mail"] = "ok"
        emit("discovery", "info",
             f"Mail: provider={provider or 'unknown'}, SPF={'yes' if spf else 'no'}, "
             f"DMARC={dmarc['policy'] if dmarc else 'missing'}", None)
    except Exception as e:
        kb.coverage["mail"] = "failed"
        emit("discovery", "warn", f"Mail collector failed: {e}", None)


def _asn_for_ip(ip: str) -> dict | None:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = addr.exploded.replace(":", "")
        rev = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    origin = lookup(rev, "TXT")
    if not origin:
        return None
    info = parse_cymru_origin(origin[0])
    if not info:
        return None
    names = lookup(f"AS{info['asn']}.asn.cymru.com", "TXT")
    info["org"] = parse_cymru_asname(names[0]) if names else None
    return {"ip": ip, **info}


def collect_asn(kb: KnowledgeBase, emit: Emit) -> None:
    try:
        ips = (kb.dns.get("a") or lookup(kb.domain, "A"))[:4]
        if not ips:
            kb.coverage["asn"] = "skipped"
            return
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = [r for r in pool.map(_asn_for_ip, ips) if r]
        kb.infra["ips"] = rows
        hosting = next((h for h in (hosting_from_org(r.get("org")) for r in rows) if h), None)
        if hosting:
            kb.infra["hosting"] = hosting
        for r in rows:
            kb.add_fact("infra", f"ASN for {r['ip']}",
                        f"AS{r['asn']} {r.get('org') or ''} ({r['country']})".strip(),
                        "team-cymru", "high")
        if hosting:
            kb.add_fact("infra", "Hosting", hosting, "team-cymru", "medium")
        kb.coverage["asn"] = "ok" if len(rows) == len(ips) else "partial"
        emit("discovery", "info", f"ASN: {', '.join('AS' + r['asn'] for r in rows) or 'none'}"
             f"{f' ({hosting})' if hosting else ''}", None)
    except Exception as e:
        kb.coverage["asn"] = "failed"
        emit("discovery", "warn", f"ASN collector failed: {e}", None)
