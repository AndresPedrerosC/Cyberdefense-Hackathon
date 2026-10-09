'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import type { Run, Target, TechnologyObservation } from '@/lib/types';

interface Finding {
  id: string;
  status: string;
  reason: string;
  advisory_id: string;
  severity: string | null;
  summary: string | null;
  source_url: string | null;
  package_name: string | null;
  package_version: string | null;
  outcome: string | null;
  verified_at: string | null;
}

interface ReportData {
  run_id: string | null;
  observations: Pick<TechnologyObservation, 'id' | 'ecosystem' | 'name' | 'version' | 'version_kind' | 'confidence'>[];
  findings: Finding[];
}

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'content-type': 'application/json' }, cache: 'no-store' });
  const body = await res.json();
  if (!res.ok) throw new Error(typeof body.error === 'string' ? body.error : JSON.stringify(body.error));
  return body as T;
}

const ago = (iso: string) => {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

export default function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [report, setReport] = useState<ReportData | null>(null);
  const [form, setForm] = useState({ company_name: '', canonical_url: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadTargets = useCallback(async () => {
    const t = await api<Target[]>('/api/targets');
    setTargets(t);
    setSelected((cur) => cur ?? t[0]?.id ?? null);
  }, []);

  const loadTarget = useCallback(async (id: string) => {
    const [r, rep] = await Promise.all([
      api<Run[]>(`/api/runs?target_id=${encodeURIComponent(id)}`),
      api<ReportData>(`/api/report?target_id=${encodeURIComponent(id)}`),
    ]);
    setRuns(r);
    setReport(rep);
  }, []);

  useEffect(() => {
    loadTargets().catch((e: Error) => setError(e.message));
  }, [loadTargets]);

  useEffect(() => {
    if (!selected) return;
    loadTarget(selected).catch((e: Error) => setError(e.message));
    const t = setInterval(() => loadTarget(selected).catch(() => {}), 5000);
    return () => clearInterval(t);
  }, [selected, loadTarget]);

  async function addTarget(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const host = new URL(form.canonical_url).hostname;
      const t = await api<Target>('/api/targets', {
        method: 'POST',
        body: JSON.stringify({ ...form, scope: { allowed_hosts: [host], allowed_paths: ['/'] } }),
      });
      setForm({ company_name: '', canonical_url: '' });
      await loadTargets();
      setSelected(t.id);
    } catch (err) {
      setError(err instanceof TypeError ? 'Enter a full URL, e.g. https://example.com' : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function startRun() {
    if (!selected) return;
    setError(null);
    try {
      await api<Run>('/api/runs', { method: 'POST', body: JSON.stringify({ target_id: selected, trigger: 'manual' }) });
      await loadTarget(selected);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const target = targets.find((t) => t.id === selected) ?? null;
  const findings = report?.findings ?? [];
  const verified = findings.filter((f) => f.outcome === 'exposure_verified').length;
  const critical = findings.filter((f) => /critical|high/i.test(f.severity ?? '')).length;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-dot" />Stackwatch</div>

        <div>
          <div className="label">Targets</div>
          <div className="target-list">
            {targets.length === 0 && <div className="empty" style={{ padding: 8 }}>No targets yet</div>}
            {targets.map((t) => (
              <button key={t.id} className={`target-item ${t.id === selected ? 'active' : ''}`} onClick={() => setSelected(t.id)}>
                {t.company_name}
                <small>{t.canonical_url}</small>
              </button>
            ))}
          </div>
        </div>

        <form className="add" onSubmit={addTarget}>
          <div className="label">Add target</div>
          <input placeholder="Company name" value={form.company_name} required
            onChange={(e) => setForm({ ...form, company_name: e.target.value })} />
          <input placeholder="https://example.com" value={form.canonical_url} required
            onChange={(e) => setForm({ ...form, canonical_url: e.target.value })} />
          <button className="btn" disabled={busy}>Add</button>
          {error && <div className="error">{error}</div>}
        </form>
      </aside>

      <main className="main">
        {!target ? (
          <div className="panel"><div className="empty">Add a target on the left to start monitoring.</div></div>
        ) : (
          <>
            <div className="header">
              <div>
                <h1>{target.company_name}</h1>
                <a href={target.canonical_url} target="_blank" rel="noreferrer">{target.canonical_url}</a>
              </div>
              <button className="btn" onClick={startRun}>Run scan</button>
            </div>

            <div className="kpis">
              <div className="kpi"><b>{report?.observations.length ?? 0}</b><span>Components</span></div>
              <div className="kpi"><b>{findings.length}</b><span>Advisory matches</span></div>
              <div className="kpi"><b style={{ color: critical ? 'var(--crit)' : undefined }}>{critical}</b><span>High / critical</span></div>
              <div className="kpi"><b style={{ color: verified ? 'var(--gold)' : undefined }}>{verified}</b><span>Exposure verified</span></div>
            </div>

            <div className="panel">
              <div className="panel-head">Findings</div>
              {findings.length === 0 ? (
                <div className="empty">{report?.run_id ? 'No advisory matches in the latest run.' : 'No completed runs yet.'}</div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Match</th><th>Verification</th><th>Summary</th></tr></thead>
                    <tbody>
                      {findings.map((f) => (
                        <tr key={f.id}>
                          <td><span className={`pill ${(f.severity ?? '').toLowerCase()}`}>{f.severity ?? 'unknown'}</span></td>
                          <td className="mono">{f.package_name}@{f.package_version ?? '?'}</td>
                          <td className="mono">{f.source_url ? <a href={f.source_url} target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>{f.advisory_id}</a> : f.advisory_id}</td>
                          <td><span className="pill">{f.status.replace(/_/g, ' ')}</span></td>
                          <td><span className={`pill ${f.outcome ?? ''}`}>{(f.outcome ?? 'not_run').replace(/_/g, ' ')}</span></td>
                          <td className="wrap">{f.summary ?? f.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="grid-2">
              <div className="panel">
                <div className="panel-head">Inventory</div>
                {(report?.observations.length ?? 0) === 0 ? (
                  <div className="empty">No components discovered yet.</div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Component</th><th>Version</th><th>Ecosystem</th><th>Confidence</th></tr></thead>
                      <tbody>
                        {report!.observations.map((o) => (
                          <tr key={o.id}>
                            <td className="mono">{o.name}</td>
                            <td className="mono">{o.version ?? '-'}</td>
                            <td>{o.ecosystem ?? '-'}</td>
                            <td>{o.confidence.replace(/_/g, ' ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="panel">
                <div className="panel-head">Runs</div>
                {runs.length === 0 ? (
                  <div className="empty">No runs yet. Hit Run scan.</div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>State</th><th>Trigger</th><th>Started</th></tr></thead>
                      <tbody>
                        {runs.map((r) => (
                          <tr key={r.id} title={r.error ?? r.id}>
                            <td><span className={`pill ${r.state}`}>{r.state}</span></td>
                            <td>{r.trigger}</td>
                            <td>{ago(r.started_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
