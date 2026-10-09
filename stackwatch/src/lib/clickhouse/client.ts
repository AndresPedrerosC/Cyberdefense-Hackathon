import { createClient, type ClickHouseClient } from '@clickhouse/client';
import type { AgentEvent } from '@/lib/types';
import { CLICKHOUSE_DDL } from './schema';
import { QUERIES, type QueryName } from './queries';

let _client: ClickHouseClient | null = null;

export function isClickHouseConfigured(): boolean {
  return Boolean(process.env.CLICKHOUSE_HOST);
}

export function getClickHouse(): ClickHouseClient {
  if (!_client) {
    const host = process.env.CLICKHOUSE_HOST;
    if (!host) throw new Error('CLICKHOUSE_HOST is not set');
    const url = /^https?:\/\//.test(host) ? host : `https://${host}:${process.env.CLICKHOUSE_PORT || '8443'}`;
    _client = createClient({
      url,
      username: process.env.CLICKHOUSE_USER || 'default',
      password: process.env.CLICKHOUSE_PASSWORD || '',
      database: process.env.CLICKHOUSE_DATABASE || 'stackwatch',
    });
  }
  return _client;
}

export async function ensureClickHouseSchema(): Promise<void> {
  await getClickHouse().command({ query: CLICKHOUSE_DDL });
}

export async function insertAgentEvents(events: AgentEvent[]): Promise<void> {
  if (events.length === 0) return;
  // ClickHouse DateTime64 JSON input rejects the trailing 'Z' / 'T' of ISO strings.
  const rows = events.map((e) => ({ ...e, occurred_at: e.occurred_at.replace('T', ' ').replace('Z', '') }));
  await getClickHouse().insert({ table: 'agent_events', values: rows, format: 'JSONEachRow' });
}

export async function runNamedQuery<T = Record<string, unknown>>(
  name: QueryName,
  params: Record<string, string>,
): Promise<T[]> {
  const rs = await getClickHouse().query({ query: QUERIES[name], query_params: params, format: 'JSONEachRow' });
  return rs.json<T>();
}
