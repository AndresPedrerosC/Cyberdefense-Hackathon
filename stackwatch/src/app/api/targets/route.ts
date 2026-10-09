import { randomUUID } from 'crypto';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/lib/db/client';
import type { Scope, Target } from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CreateTarget = z.object({
  company_name: z.string().min(1),
  canonical_url: z.string().url(),
  repo_ref: z.string().optional(),
  scope: z.object({
    allowed_hosts: z.array(z.string()),
    allowed_paths: z.array(z.string()),
    repo_path: z.string().optional(),
  }),
  monitoring_enabled: z.boolean().default(false),
});

interface TargetRow {
  id: string;
  company_name: string;
  canonical_url: string;
  repo_ref: string | null;
  scope_json: string;
  monitoring_enabled: number;
  created_at: string;
}

function rowToTarget(r: TargetRow): Target {
  return {
    id: r.id,
    company_name: r.company_name,
    canonical_url: r.canonical_url,
    repo_ref: r.repo_ref ?? undefined,
    scope: JSON.parse(r.scope_json) as Scope,
    monitoring_enabled: r.monitoring_enabled === 1,
    created_at: r.created_at,
  };
}

export async function GET() {
  const rows = getDb().prepare('SELECT * FROM targets ORDER BY created_at DESC').all() as TargetRow[];
  return NextResponse.json(rows.map(rowToTarget));
}

export async function POST(req: Request) {
  const parsed = CreateTarget.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  const t: Target = { id: randomUUID(), created_at: new Date().toISOString(), ...parsed.data };
  getDb()
    .prepare(
      `INSERT INTO targets (id, company_name, canonical_url, repo_ref, scope_json, monitoring_enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(t.id, t.company_name, t.canonical_url, t.repo_ref ?? null, JSON.stringify(t.scope), t.monitoring_enabled ? 1 : 0, t.created_at);
  return NextResponse.json(t, { status: 201 });
}
