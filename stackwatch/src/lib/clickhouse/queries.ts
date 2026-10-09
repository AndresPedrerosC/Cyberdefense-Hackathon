// Advisory/component revisions with no completed evaluation.
export const NEW_ADVISORY_REVISIONS = `
SELECT
  argMax(advisory_id, entity_revision) AS advisory_id,
  argMax(component_fingerprint, entity_revision) AS component_fingerprint,
  max(entity_revision) AS latest_revision
FROM agent_events
WHERE target_id = {target_id: String}
  AND event_type = 'advisory_ingested'
  AND entity_key NOT IN (
    SELECT entity_key FROM agent_events
    WHERE target_id = {target_id: String}
      AND event_type = 'verification_run'
  )
GROUP BY entity_key
`;

// Added/removed/changed fingerprints between two runs. Missing side is coalesced to '' so NULLs don't drop rows.
export const CHANGED_COMPONENTS = `
SELECT
  entity_key,
  ifNull(argMaxIf(component_fingerprint, entity_revision, run_id = {previous_run: String}), '') AS prev_fingerprint,
  ifNull(argMaxIf(component_fingerprint, entity_revision, run_id = {current_run: String}), '') AS curr_fingerprint
FROM agent_events
WHERE target_id = {target_id: String}
  AND event_type = 'observation_added'
  AND run_id IN ({previous_run: String}, {current_run: String})
GROUP BY entity_key
HAVING prev_fingerprint != curr_fingerprint OR prev_fingerprint = '' OR curr_fingerprint = ''
`;

// Supported findings with missing, expired (>24h), or invalidated checks.
export const VERIFICATION_DUE = `
SELECT
  entity_key AS match_key,
  argMax(advisory_id, entity_revision) AS advisory_id,
  argMax(component_fingerprint, entity_revision) AS fingerprint,
  max(entity_revision) AS revision
FROM agent_events
WHERE target_id = {target_id: String}
  AND event_type = 'match_found'
GROUP BY entity_key
HAVING match_key NOT IN (
  SELECT entity_key FROM agent_events
  WHERE target_id = {target_id: String}
    AND event_type = 'verification_run'
    AND occurred_at > {now: DateTime64(3)} - INTERVAL 24 HOUR
)
`;

// Verified outcomes and later revisions.
export const EXPOSURE_TIMELINE = `
SELECT
  occurred_at,
  entity_key,
  argMax(outcome, entity_revision) AS outcome,
  argMax(advisory_id, entity_revision) AS advisory_id,
  argMax(component_fingerprint, entity_revision) AS fingerprint,
  max(entity_revision) AS revision
FROM agent_events
WHERE target_id = {target_id: String}
  AND event_type = 'verification_run'
  AND occurred_at >= {since: DateTime64(3)}
GROUP BY occurred_at, entity_key
ORDER BY occurred_at DESC
`;

export const QUERIES = {
  new_advisory_revisions: NEW_ADVISORY_REVISIONS,
  changed_components: CHANGED_COMPONENTS,
  verification_due: VERIFICATION_DUE,
  exposure_timeline: EXPOSURE_TIMELINE,
} as const;

export type QueryName = keyof typeof QUERIES;
