export const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    repo_ref TEXT,
    scope_json TEXT NOT NULL,
    monitoring_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id),
    trigger TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT
  );

  CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source_url_or_artifact TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    commit_sha TEXT,
    schema_version TEXT NOT NULL DEFAULT '1'
  );

  CREATE TABLE IF NOT EXISTS technology_observations (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ecosystem TEXT,
    name TEXT NOT NULL,
    version TEXT,
    version_kind TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    component_fingerprint TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1'
  );

  CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    aliases_json TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    affected_ranges_json TEXT NOT NULL,
    patched_versions_json TEXT NOT NULL,
    severity TEXT,
    source_url TEXT NOT NULL,
    source_updated_at TEXT NOT NULL,
    revision_hash TEXT NOT NULL,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    summary TEXT,
    schema_version TEXT NOT NULL DEFAULT '1'
  );

  CREATE TABLE IF NOT EXISTS vulnerability_matches (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    technology_id TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    inventory_fingerprint TEXT NOT NULL,
    advisory_revision TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1'
  );

  CREATE TABLE IF NOT EXISTS verification_results (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    match_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    check_version TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    summary TEXT NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL DEFAULT '1'
  );

  CREATE TABLE IF NOT EXISTS event_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    entity_revision INTEGER NOT NULL,
    advisory_id TEXT,
    component_fingerprint TEXT,
    outcome TEXT,
    evidence_ref TEXT,
    payload_json TEXT NOT NULL,
    exported INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_id);
  CREATE INDEX IF NOT EXISTS idx_observations_target_run ON technology_observations(target_id, run_id);
  CREATE INDEX IF NOT EXISTS idx_matches_target ON vulnerability_matches(target_id);
  CREATE INDEX IF NOT EXISTS idx_verifications_match ON verification_results(match_id);
  CREATE INDEX IF NOT EXISTS idx_outbox_unexported ON event_outbox(exported) WHERE exported = 0;
`;
