CREATE DATABASE IF NOT EXISTS cyberdefense;

CREATE TABLE IF NOT EXISTS cyberdefense.targets (
  target_id String,
  kind LowCardinality(String),
  name String,
  domain String,
  repo String,
  deploy_url String,
  created_ts DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(created_ts) ORDER BY target_id;

CREATE TABLE IF NOT EXISTS cyberdefense.runs (
  run_id String,
  target_id String,
  trigger LowCardinality(String),
  state LowCardinality(String),
  verification_authorized UInt8,
  authorization_reason String,
  inventory_hash String,
  started_ts DateTime64(3, 'UTC'),
  finished_ts Nullable(DateTime64(3, 'UTC')),
  error Nullable(String),
  ts DateTime64(3, 'UTC')
) ENGINE = MergeTree ORDER BY (target_id, started_ts, ts);

CREATE TABLE IF NOT EXISTS cyberdefense.stack_items (
  id String,
  run_id String,
  target_id String,
  ts DateTime64(3, 'UTC'),
  ecosystem LowCardinality(String),
  package String,
  name String,
  version Nullable(String),
  declared_range Nullable(String),
  direct UInt8,
  confidence LowCardinality(String),
  status LowCardinality(String),
  source_url String,
  evidence String
) ENGINE = MergeTree ORDER BY (target_id, run_id, id);

CREATE TABLE IF NOT EXISTS cyberdefense.advisories (
  advisory_id String,
  aliases String,
  ecosystem LowCardinality(String),
  package String,
  ranges String,
  versions String,
  severity LowCardinality(String),
  cvss_vector String,
  summary String,
  published DateTime64(3, 'UTC'),
  modified DateTime64(3, 'UTC'),
  withdrawn Nullable(DateTime64(3, 'UTC')),
  source LowCardinality(String),
  source_url String,
  first_seen DateTime64(3, 'UTC'),
  replayed UInt8
) ENGINE = ReplacingMergeTree(modified) ORDER BY (ecosystem, package, advisory_id);

CREATE TABLE IF NOT EXISTS cyberdefense.candidates (
  id String,
  run_id String,
  target_id String,
  ts DateTime64(3, 'UTC'),
  stack_item_id String,
  advisory_id String,
  advisory_url String,
  affected_range String,
  fixed_version Nullable(String),
  match_type LowCardinality(String),
  reason String,
  explanation Nullable(String),
  severity_hint LowCardinality(String),
  risk_score UInt16
) ENGINE = MergeTree ORDER BY (target_id, run_id, id);

CREATE TABLE IF NOT EXISTS cyberdefense.verifications (
  id String,
  run_id String,
  target_id String,
  ts DateTime64(3, 'UTC'),
  candidate_id String,
  status LowCardinality(String),
  evidence String,
  checks_performed String,
  suggested_fix String,
  target LowCardinality(String)
) ENGINE = MergeTree ORDER BY (target_id, run_id, candidate_id);

CREATE TABLE IF NOT EXISTS cyberdefense.events (
  event_id UUID,
  run_id Nullable(String),
  target_id String,
  ts DateTime64(3, 'UTC'),
  stage LowCardinality(String),
  level LowCardinality(String),
  message String,
  ref_id Nullable(String)
) ENGINE = MergeTree ORDER BY (target_id, ts);

-- Runtime user with limited privileges
CREATE USER IF NOT EXISTS cyberdefense_app IDENTIFIED BY 'hackathon2026';
GRANT INSERT, SELECT ON cyberdefense.* TO cyberdefense_app;
