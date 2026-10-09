"""Knowledge base contract for public-domain recon.

One KnowledgeBase per run. Collectors fill their section, the fingerprinter fills `stack`,
the agent appends `facts` and `agent.steps`, and the cross-reference fills `intel`.
Snapshots are persisted as JSON so the UI can watch the KB grow during a run.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Confidence = Literal["high", "medium", "low"]
KBStatus = Literal["building", "enriching", "cross-referencing", "complete", "failed"]
CollectorStatus = Literal["ok", "partial", "failed", "skipped"]
FactCategory = Literal[
    "company", "web", "dns", "mail", "infra", "stack", "subdomain", "posture", "intel"
]
IntelSource = Literal["cisa-kev", "nvd", "osv", "epss", "posture"]


class Fact(BaseModel):
    """A single sourced statement about the company or its infrastructure."""

    category: FactCategory
    key: str
    value: str
    source: str  # URL, "dns:MX", "rdap", "crt.sh", or "agent"
    confidence: Confidence = "medium"
    by: Literal["recon", "agent"] = "recon"
    ts: datetime = Field(default_factory=datetime.utcnow)


class Tech(BaseModel):
    """A detected technology. vendor/product follow CPE 2.3 naming so KEV/NVD can match."""

    name: str
    category: str  # e.g. "web-server", "cdn", "cms", "js-library", "mail", "edge-appliance"
    version: str | None = None
    vendor: str | None = None  # CPE vendor, e.g. "nginx", "f5", "microsoft"
    product: str | None = None  # CPE product, e.g. "nginx", "exchange_server"
    npm: str | None = None  # npm package when the tech is a JS library (routed to OSV)
    confidence: Confidence = "medium"
    evidence: str = ""
    source: str = ""  # URL or record the evidence came from
    host: str | None = None  # host it was seen on, when not the apex


class Subdomain(BaseModel):
    name: str
    source: str = "crt.sh"
    ips: list[str] = Field(default_factory=list)
    interesting: str | None = None  # why it matters, e.g. "remote access (vpn)"
    title: str | None = None  # landing page title when probed


class IntelHit(BaseModel):
    """A threat intel cross-reference result, mirrored into candidates for the findings board."""

    source: IntelSource
    id: str  # CVE id, GHSA id, or posture rule id (e.g. "SW-DMARC-MISSING")
    title: str
    tech: str | None = None  # Tech.name it was matched against
    severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    kev: bool = False
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    match: Literal["confirmed", "possible"] = "possible"
    url: str | None = None
    detail: str = ""
    fixed_version: str | None = None


class AgentStep(BaseModel):
    step: int
    kind: Literal["thought", "plan", "read", "extract", "tool_call", "tool_result",
                  "final", "error"]
    name: str | None = None  # tool name for tool_call / tool_result
    content: str
    ts: datetime = Field(default_factory=datetime.utcnow)


class AgentState(BaseModel):
    model: str | None = None
    available: bool = False
    steps: list[AgentStep] = Field(default_factory=list)
    profile: str | None = None  # company profile written after recon
    brief: str | None = None  # analyst brief written after cross-reference


class FetchedPage(BaseModel):
    """A fetched page handed to the fingerprinter and agent. Never persisted in the KB doc."""

    url: str
    final_url: str
    host: str
    status: int
    headers: dict[str, str] = Field(default_factory=dict)  # lowercased names
    set_cookies: list[str] = Field(default_factory=list)  # raw Set-Cookie values
    html: str = ""


class KnowledgeBase(BaseModel):
    domain: str
    run_id: str
    target_id: str
    status: KBStatus = "building"
    started_ts: datetime = Field(default_factory=datetime.utcnow)
    updated_ts: datetime = Field(default_factory=datetime.utcnow)

    # name, legal_name, description, industry, location, founded, logo, socials{}, emails[],
    # phones[], same_as[]
    company: dict[str, Any] = Field(default_factory=dict)
    # final_url, status, title, description, generator, server, headers{}, cookies[],
    # security_headers{name: present|missing}, robots, security_txt, sitemap, scripts[], links[]
    web: dict[str, Any] = Field(default_factory=dict)
    # a[], aaaa[], ns[], mx[{priority, host}], txt[], caa[], soa, cname, dnssec
    dns: dict[str, Any] = Field(default_factory=dict)
    # provider, spf{record, includes[], all, providers[]}, dmarc{record, policy, rua[]},
    # mta_sts, bimi, dkim_selectors[]
    mail: dict[str, Any] = Field(default_factory=dict)
    # ips[{ip, asn, org, country, prefix}], hosting, cdn, registrar, created, expires,
    # registrant_org, tls{issuer, subject, not_before, not_after, days_left, sans[], version}
    infra: dict[str, Any] = Field(default_factory=dict)
    subdomains: list[Subdomain] = Field(default_factory=list)
    stack: list[Tech] = Field(default_factory=list)
    facts: list[Fact] = Field(default_factory=list)
    intel: list[IntelHit] = Field(default_factory=list)
    agent: AgentState = Field(default_factory=AgentState)
    coverage: dict[str, CollectorStatus] = Field(default_factory=dict)

    def add_fact(self, category: FactCategory, key: str, value: Any, source: str,
                 confidence: Confidence = "medium", by: str = "recon") -> None:
        text = value if isinstance(value, str) else str(value)
        text = text.strip()
        if not text:
            return
        for f in self.facts:
            if f.category == category and f.key == key and f.value == text:
                return
        self.facts.append(Fact(category=category, key=key, value=text[:500], source=source,
                               confidence=confidence, by=by))

    def add_tech(self, tech: Tech) -> None:
        """Merge by (name, host); keep the entry with a version or higher confidence."""
        rank = {"high": 3, "medium": 2, "low": 1}
        for i, t in enumerate(self.stack):
            if t.name.lower() == tech.name.lower() and t.host == tech.host:
                better = (tech.version and not t.version) or (
                    bool(tech.version) == bool(t.version)
                    and rank[tech.confidence] > rank[t.confidence]
                )
                if better:
                    self.stack[i] = tech
                return
        self.stack.append(tech)

    def touch(self) -> None:
        self.updated_ts = datetime.utcnow()
