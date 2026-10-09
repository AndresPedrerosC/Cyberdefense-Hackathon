import { randomUUID } from 'crypto';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/lib/db/client';
import type { Run } from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CreateRun = z.object({
  target_id: z.string().min(1),
  trigger: z.enum(['manual', 'monitor', 'advisory', 'stack_change']).default('manual'),
});

export async function GET(req: Request) {
  const targetId = new URL(req.url).searchParams.get('target_id');
  const db = getDb();
  const rows = targetId
    ? db.prepare('SELECT * FROM runs WHERE target_id = ? ORDER BY started_at DESC').all(targetId)
    : db.prepare('SELECT * FROM runs ORDER BY started_at DESC LIMIT 100').all();
  return NextResponse.json(rows as Run[]);
}

export async function POST(req: Request) {
  const parsed = CreateRun.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  const db = getDb();
  if (!db.prepare('SELECT 1 FROM targets WHERE id = ?').get(parsed.data.target_id)) {
    return NextResponse.json({ error: 'target not found' }, { status: 404 });
  }
  const run: Run = {
    id: randomUUID(),
    target_id: parsed.data.target_id,
    trigger: parsed.data.trigger,
    state: 'queued',
    started_at: new Date().toISOString(),
  };
  db.prepare('INSERT INTO runs (id, target_id, trigger, state, started_at) VALUES (?, ?, ?, ?, ?)').run(
    run.id, run.target_id, run.trigger, run.state, run.started_at,
  );
  return NextResponse.json(run, { status: 201 });
}
