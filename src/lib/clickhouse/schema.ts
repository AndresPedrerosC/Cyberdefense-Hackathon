export const CLICKHOUSE_DDL = `
CREATE TABLE IF NOT EXISTS agent_events (
  event_id String,
  target_id String,
  run_id String,
  entity_key String,
  event_type LowCardinality(String),
  occurred_at DateTime64(3, 'UTC'),
  entity_revision UInt32,
  advisory_id Nullable(String),
  component_fingerprint Nullable(String),
  outcome LowCardinality(Nullable(String)),
  evidence_ref Nullable(String),
  payload_json String
) ENGINE = MergeTree()
ORDER BY (target_id, event_type, entity_key, occurred_at, event_id);
`;
