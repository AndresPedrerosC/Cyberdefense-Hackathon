"""
Data contract models per spec section 6 (v1.1).
Single source of truth for all pillars.
"""

from datetime import datetime
from typing import Literal, Callable
from pydantic import BaseModel, Field
import uuid

# Type aliases
TargetKind = Literal["public", "connected_repo", "owned_deployment"]
# cpe: server software matched via CISA KEV / NVD; config: posture findings for a domain.
Ecosystem = Literal["npm", "cpe", "config", "unknown"]
Confidence = Literal["high", "medium", "low"]
StackItemStatus = Literal["inferred", "confirmed"]
MatchType = Literal["confirmed", "possible"]
Severity = Literal["critical", "high", "medium", "low", "unknown"]
VerificationStatus = Literal["verified", "present", "not_present", "inconclusive"]
EvidenceKind = Literal["dependency-present", "semgrep", "runtime", "not-authorized", "error"]
RunState = Literal["queued", "discovering", "matching", "verifying", "reporting", "complete", "failed"]
RunTrigger = Literal["manual", "advisory", "stack_change", "schedule"]
EventStage = Literal["discovery", "intel", "verification", "monitor", "report", "system"]
EventLevel = Literal["info", "warn", "error"]

# Emit callback type for live feed
Emit = Callable[[str, str, str, str | None], None]  # (stage, level, message, ref_id)


class Target(BaseModel):
    target_id: str
    kind: TargetKind
    name: str
    domain: str | None = None
    repo: str | None = None
    deploy_url: str | None = None
    created_ts: datetime = Field(default_factory=datetime.utcnow)


class StackItem(BaseModel):
    id: str
    run_id: str
    target_id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    ecosystem: Ecosystem
    package: str | None = None
    name: str | None = None
    version: str | None = None
    declared_range: str | None = None
    direct: bool = False
    confidence: Confidence = "medium"
    status: StackItemStatus = "inferred"
    source_url: str | None = None
    evidence: str | None = None


class AffectedRange(BaseModel):
    type: str  # SEMVER or ECOSYSTEM
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class Advisory(BaseModel):
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    ecosystem: Ecosystem
    package: str
    ranges: list[AffectedRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    severity: Severity = "unknown"
    cvss_vector: str | None = None
    summary: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    withdrawn: datetime | None = None
    source: str = "osv"
    source_url: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    replayed: bool = False


class Candidate(BaseModel):
    id: str
    run_id: str
    target_id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    stack_item_id: str
    advisory_id: str
    advisory_url: str | None = None
    affected_range: str | None = None
    fixed_version: str | None = None
    match_type: MatchType = "possible"
    reason: str | None = None
    explanation: str | None = None
    severity_hint: Severity = "unknown"
    risk_score: int = 0


class Evidence(BaseModel):
    kind: EvidenceKind
    detail: str
    source_url: str | None = None


class Verification(BaseModel):
    id: str
    run_id: str
    target_id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    candidate_id: str
    status: VerificationStatus = "inconclusive"
    evidence: list[Evidence] = Field(default_factory=list)
    checks_performed: list[str] = Field(default_factory=list)
    suggested_fix: str | None = None
    target: str | None = None  # connected-repo or owned-authorized


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str | None = None
    target_id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    stage: EventStage
    level: EventLevel = "info"
    message: str
    ref_id: str | None = None


class Run(BaseModel):
    run_id: str
    target_id: str
    trigger: RunTrigger = "manual"
    state: RunState = "queued"
    verification_authorized: bool = False
    authorization_reason: str | None = None
    inventory_hash: str | None = None
    started_ts: datetime = Field(default_factory=datetime.utcnow)
    finished_ts: datetime | None = None
    error: str | None = None
