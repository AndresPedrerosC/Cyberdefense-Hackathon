import { NextResponse } from 'next/server';
import { getDb } from '@/lib/db/client';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const targetId = new URL(req.url).searchParams.get('target_id');
  if (!targetId) return NextResponse.json({ error: 'target_id required' }, { status: 400 });
  const db = getDb();

  const latestRun = db
    .prepare("SELECT id FROM runs WHERE target_id = ? AND state = 'complete' ORDER BY started_at DESC LIMIT 1")
    .get(targetId) as { id: string } | undefined;
  const runId = latestRun?.id ?? null;

  const observations = runId
    ? db
        .prepare(
          `SELECT id, ecosystem, name, version, version_kind, confidence, component_fingerprint
           FROM technology_observations WHERE target_id = ? AND run_id = ? ORDER BY name`,
        )
        .all(targetId, runId)
    : [];

  const findings = runId
    ? db
        .prepare(
          `SELECT m.id, m.status, m.reason, m.advisory_id, a.severity, a.summary, a.source_url,
                  o.name AS package_name, o.version AS package_version,
                  v.outcome, v.completed_at AS verified_at
           FROM vulnerability_matches m
           LEFT JOIN advisories a ON a.id = m.advisory_id
           LEFT JOIN technology_observations o ON o.id = m.technology_id
           LEFT JOIN verification_results v ON v.id = (
             SELECT id FROM verification_results WHERE match_id = m.id ORDER BY completed_at DESC LIMIT 1
           )
           WHERE m.target_id = ? AND m.run_id = ?`,
        )
        .all(targetId, runId)
    : [];

  return NextResponse.json({ run_id: runId, observations, findings });
}
