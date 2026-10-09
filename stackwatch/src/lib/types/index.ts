export type VersionKind = 'installed' | 'declared_range' | 'observed' | 'unknown';
export type Confidence = 'inferred' | 'confirmed_in_repo' | 'confirmed_in_runtime';
export type MatchStatus = 'confirmed_affected_version' | 'possible_match' | 'not_affected_version' | 'needs_review';
export type VerificationOutcome = 'exposure_verified' | 'affected_component_found' | 'not_reproduced' | 'inconclusive' | 'not_run';
export type EventType =
  | 'discovery_started'
  | 'observation_added'
  | 'advisory_ingested'
  | 'match_found'
  | 'verification_run'
  | 'report_updated'
  | 'monitor_heartbeat'
  | 'error';
export type RunTrigger = 'manual' | 'monitor' | 'advisory' | 'stack_change';
export type RunState = 'queued' | 'running' | 'complete' | 'failed';

export interface Scope {
  allowed_hosts: string[];
  allowed_paths: string[];
  repo_path?: string;
}

export interface Target {
  id: string;
  company_name: string;
  canonical_url: string;
  repo_ref?: string;
  scope: Scope;
  monitoring_enabled: boolean;
  created_at: string;
}

export interface Evidence {
  id: string;
  target_id: string;
  source_url_or_artifact: string;
  observed_at: string;
  content_hash: string;
  excerpt: string;
  commit_sha?: string;
  schema_version: string;
}

export interface TechnologyObservation {
  id: string;
  target_id: string;
  run_id: string;
  ecosystem?: string;
  name: string;
  version?: string;
  version_kind: VersionKind;
  confidence: Confidence;
  evidence_ids: string[];
  component_fingerprint: string;
  schema_version: string;
}

export interface AffectedRange {
  type: string;
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  /** Original source range, preserved verbatim. */
  original: string;
}

export interface Advisory {
  id: string;
  aliases: string[];
  ecosystem: string;
  package_name: string;
  affected_ranges: AffectedRange[];
  patched_versions: string[];
  severity?: string;
  source_url: string;
  source_updated_at: string;
  revision_hash: string;
  withdrawn: boolean;
  summary?: string;
  schema_version: string;
}

export interface VulnerabilityMatch {
  id: string;
  target_id: string;
  run_id: string;
  technology_id: string;
  advisory_id: string;
  status: MatchStatus;
  reason: string;
  inventory_fingerprint: string;
  advisory_revision: string;
  schema_version: string;
}

export interface VerificationResult {
  id: string;
  target_id: string;
  run_id: string;
  match_id: string;
  check_id: string;
  check_version: string;
  environment_id: string;
  outcome: VerificationOutcome;
  evidence_ids: string[];
  started_at: string;
  completed_at: string;
  summary: string;
  schema_version: string;
}

export interface AgentEvent {
  event_id: string;
  target_id: string;
  run_id: string;
  entity_key: string;
  event_type: EventType;
  occurred_at: string;
  entity_revision: number;
  advisory_id?: string;
  component_fingerprint?: string;
  outcome?: VerificationOutcome;
  evidence_ref?: string;
  payload_json: string;
}

export interface Run {
  id: string;
  target_id: string;
  trigger: RunTrigger;
  state: RunState;
  started_at: string;
  completed_at?: string;
  error?: string;
}

export interface Report {
  target_id: string;
  run_id: string;
  generated_at: string;
  observations: TechnologyObservation[];
  matches: VulnerabilityMatch[];
  verifications: VerificationResult[];
}

export interface VerificationJob {
  id: string;
  match_id: string;
  check_id: string;
  target: Target;
  match: VulnerabilityMatch;
  advisory: Advisory;
  observation: TechnologyObservation;
}

export interface DiscoveryAdapter {
  discover(target: Target): Promise<TechnologyObservation[]>;
}

export interface IntelAdapter {
  refreshAdvisories(cursor: string | null): Promise<{ advisories: Advisory[]; nextCursor: string | null }>;
  match(inventory: TechnologyObservation[], advisories: Advisory[]): Promise<VulnerabilityMatch[]>;
}

export interface VerificationAdapter {
  planChecks(matches: VulnerabilityMatch[], scope: Scope): Promise<VerificationJob[]>;
  verify(job: VerificationJob): Promise<VerificationResult>;
}
