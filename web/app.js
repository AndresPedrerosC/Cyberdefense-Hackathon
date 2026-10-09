'use strict';

// Page state. One scan at a time; the report is fetched once when the run completes.
let kind = 'repo';
let targetId = null;
let runId = null;
let runActive = false;
let runStartedAt = null;
let lastRun = null;
let report = null;
let filter = 'all';
let selected = null;
let lastEventTs = null;
let eventCount = 0;
let feedTimer = null;
let elapsedTimer = null;

const $ = id => document.getElementById(id);

const STAGES = [
  { key: 'discovering', label: 'Discover', desc: 'List every installed package and version from the lockfile.' },
  { key: 'matching', label: 'Match', desc: 'Compare installed versions with advisory affected ranges.' },
  { key: 'verifying', label: 'Verify', desc: 'Run Semgrep rules to check if the vulnerable code is called.' },
  { key: 'reporting', label: 'Report', desc: 'Rank by severity and verification strength.' },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

// Verification outcomes in plain language. Raw enum values stay in the evidence chain.
const VSTATUS = {
  verified: { label: 'Reachable', cls: 'o-exposed' },
  present: { label: 'Installed', cls: 'o-found' },
  not_present: { label: 'Not present', cls: 'o-clear' },
  inconclusive: { label: 'Inconclusive', cls: 'o-gray' },
};

const FILTERS = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'reachable', label: 'Reachable', title: 'A Semgrep rule found the vulnerable call in the code', test: f => f.verification_status === 'verified' },
  { key: 'direct', label: 'Direct deps', test: f => f.direct },
];

const TARGET_TITLE = {
  repo: 'Local path to a repository with a package-lock.json',
  public: 'A domain you own or are authorized to test. Public scans infer technologies and skip code checks.',
};

// ---- Target type + scan ----

document.querySelectorAll('#scan-form .seg button').forEach(btn => {
  btn.addEventListener('click', () => {
    kind = btn.dataset.kind;
    document.querySelectorAll('#scan-form .seg button').forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
    const input = $('target-input');
    input.placeholder = kind === 'repo' ? 'demo/juice-shop' : 'example.com';
    input.value = kind === 'repo' ? 'demo/juice-shop' : '';
    input.title = TARGET_TITLE[kind];
    input.focus();
  });
});

$('scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  const val = $('target-input').value.trim();
  if (!val || runActive) return;

  resetRun();
  setBusy(true);
  $('crumb-target').textContent = val;
  $('nav-target').textContent = val;
  try {
    const t = await post('/api/targets', {
      kind: kind === 'repo' ? 'connected_repo' : 'public',
      name: val,
      repo: kind === 'repo' ? val : null,
      domain: kind === 'public' ? val : null,
    });
    targetId = t.target_id;
    $('nav-target-id').textContent = targetId;
    renderAuth(t.authorized);

    const r = await post('/api/runs', { target_id: targetId, trigger: 'manual' });
    runId = r.run_id;
    runActive = true;
    runStartedAt = Date.now();
    $('panel-run').textContent = runId;
    renderPipeline({ state: 'queued' });
    startElapsed();
    startFeed();
  } catch (err) {
    showRunError('Could not start the scan (' + err.message + ').');
    setBusy(false);
  }
});

function resetRun() {
  runId = null;
  lastRun = null;
  report = null;
  filter = 'all';
  lastEventTs = null;
  eventCount = 0;
  closeInspector();
  $('term').innerHTML = '<div class="term-empty">$ scan starting</div>';
  setCount('events', 0);
  setCount('changes', 0);
  $('changes').innerHTML = '<div class="term-empty">Changes are computed when the scan completes.</div>';
  $('run-error').hidden = true;
  setCount('findings', 0);
  renderKpis();
  renderFilter();
  renderBoard('Findings appear when the scan completes.');
}

function setBusy(busy) {
  const btn = $('start-btn');
  btn.disabled = busy;
  btn.classList.toggle('busy', busy);
  btn.querySelector('.btn-label').textContent = busy ? 'Scanning' : 'Run scan';
}

function setCount(which, n) {
  const map = { events: ['nav-events', 'tab-events'], changes: ['nav-changes', 'tab-changes'], findings: ['nav-findings'] };
  map[which].forEach(id => { $(id).textContent = fmtNum(n); });
}

function renderAuth(authorized) {
  $('nav-auth').innerHTML = authorized
    ? '<span class="dot green"></span>Enabled'
    : '<span class="dot amber"></span>Skipped, not authorized';
  $('nav-auth').title = authorized
    ? 'Target is on the authorized list, so Semgrep checks run against its code.'
    : 'Target is not on the authorized list. Matching runs, code verification does not.';
}

function showRunError(msg) {
  $('run-error').hidden = false;
  $('run-error').textContent = msg;
}

function startElapsed() {
  if (elapsedTimer) clearInterval(elapsedTimer);
  renderRunMeta();
  elapsedTimer = setInterval(renderRunMeta, 1000);
}

function renderRunMeta() {
  const meta = $('run-meta');
  if (!runId) { meta.textContent = 'No scan yet'; return; }
  let ms = Date.now() - runStartedAt;
  if (lastRun && lastRun.started_ts && lastRun.finished_ts) ms = parseTs(lastRun.finished_ts) - parseTs(lastRun.started_ts);
  const state = lastRun ? lastRun.state : 'queued';
  const word = state === 'complete' ? 'completed in' : state === 'failed' ? 'failed after' : 'running';
  meta.textContent = `${runId} · ${word} ${fmtDuration(ms)}`;
}

// ---- Pipeline ----

function renderPipeline(run) {
  const failedAt = run.state === 'failed' && run.error ? run.error.split(':')[0] : null;
  const idx = STAGES.findIndex(s => s.key === (failedAt || run.state));
  const counts = stageCounts();
  $('strip-sub').hidden = run.state !== 'idle';

  const n = STAGES.length;
  const stepPct = 100 / n;
  // Progress runs through the center of each stage's slice, so the fill lines up
  // with the stage currently in progress rather than stopping short or overshooting.
  let fillPct;
  if (run.state === 'idle') fillPct = 0;
  else if (run.state === 'complete') fillPct = 100;
  else if (idx < 0) fillPct = 0;
  else fillPct = (idx + 0.5) * stepPct;
  const fillEl = $('pipeline-fill');
  fillEl.style.width = `${fillPct}%`;
  // background-size is relative to the fill's own box, so scale it inversely with
  // fillPct to keep the yellow-to-green gradient anchored to the full track width;
  // this way the fill always shows the color that matches how far along it is.
  fillEl.style.backgroundSize = fillPct > 0 ? `${10000 / fillPct}% 100%` : '100% 100%';
  fillEl.classList.toggle('error', run.state === 'failed');

  $('pipeline-steps').innerHTML = STAGES.map((s, i) => {
    let st = 'pending';
    if (run.state === 'complete' || (idx >= 0 && i < idx)) st = 'done';
    else if (i === idx) st = run.state === 'failed' ? 'error' : 'active';
    const c = counts[s.key] || { text: st === 'active' ? 'working' : '' };
    return `<li class="pstep ${st}" title="${esc(c.text)}">
      <span class="plabel">${s.label}</span><span class="pcount${c.hot ? ' hot' : ''}">${esc(c.text)}</span>
    </li>`;
  }).join('');
}

// Per-stage results, available once the report is loaded.
function stageCounts() {
  if (!report) return {};
  const f = report.findings || [];
  const s = report.summary || {};
  const advisories = new Set(f.map(x => x.advisory_id)).size;
  const reachable = f.filter(x => x.verification_status === 'verified').length;
  const verifyText = s.verification_authorized === false
    ? 'Skipped, target not authorized'
    : `${reachable} reachable in code`;
  return {
    discovering: { text: `${fmtNum(s.components)} components` },
    matching: { text: `${fmtNum(f.length)} matches, ${fmtNum(advisories)} advisories` },
    verifying: { text: verifyText, hot: reachable > 0 },
    reporting: { text: `${fmtNum(f.length)} findings ranked` },
  };
}

// ---- Verdict ----

function renderKpis() {
  const f = report ? report.findings || [] : null;
  const s = report ? report.summary || {} : {};
  const v = n => (f ? fmtNum(n) : '--');
  const reachable = f ? f.filter(x => x.verification_status === 'verified').length : 0;
  const critical = f ? f.filter(x => x.severity === 'critical').length : 0;
  const directHits = f ? f.filter(x => x.direct).length : 0;
  const cells = [
    { k: 'Components scanned', v: v(s.components), cls: '', d: f ? `${fmtNum(s.direct_components)} direct, the rest transitive` : 'packages in the lockfile' },
    { k: 'Vulnerable versions', v: v(f && f.length), cls: '', d: f ? `${fmtNum(directHits)} in direct dependencies` : 'installed version inside an advisory range' },
    { k: 'Reachable in code', v: v(reachable), cls: f ? (reachable ? 'red' : 'green') : 'muted', d: 'vulnerable call found by Semgrep' },
    { k: 'Critical severity', v: v(critical), cls: f && critical ? 'red' : f ? '' : 'muted', d: 'severity from the advisory' },
  ];
  $('kpis').innerHTML = cells.map(c =>
    `<div class="kpi" title="${esc(c.d)}"><span class="k">${c.k}</span><span class="v ${c.cls}">${c.v}</span></div>`
  ).join('');
}

// ---- Findings board ----

function renderFilter() {
  const f = report ? report.findings || [] : [];
  $('filter').innerHTML = FILTERS.map(x =>
    `<button type="button" data-filter="${x.key}" aria-pressed="${x.key === filter}"${x.title ? ` title="${x.title}"` : ''}>${x.label}<span class="count">${fmtNum(f.filter(x.test).length)}</span></button>`
  ).join('');
  $('filter').querySelectorAll('button').forEach(b => b.addEventListener('click', () => {
    filter = b.dataset.filter;
    renderFilter();
    renderBoard();
  }));
}

// Within a column: reachable first, then risk, then package name.
function cardOrder(a, b) {
  const r = (b.verification_status === 'verified') - (a.verification_status === 'verified');
  return r || (b.risk_score || 0) - (a.risk_score || 0) || String(a.package).localeCompare(String(b.package));
}

function renderBoard(emptyMsg) {
  const all = report ? report.findings || [] : [];
  const list = all.filter(FILTERS.find(x => x.key === filter).test);
  const bySev = Object.fromEntries(SEVERITIES.map(s => [s, []]));
  list.forEach(f => (bySev[SEVERITIES.includes(f.severity) ? f.severity : 'unknown']).push(f));
  const cols = SEVERITIES.filter(s => s !== 'unknown' || bySev.unknown.length);

  $('board').innerHTML = cols.map(sev => {
    const items = bySev[sev].sort(cardOrder);
    const reach = items.filter(f => f.verification_status === 'verified').length;
    const body = items.length
      ? items.map(cardHtml).join('')
      : `<div class="col-empty">${esc(emptyMsg || (report ? 'None' : 'No scan yet'))}</div>`;
    return `<div class="col sev-${sev}">
      <div class="col-h"><span class="col-name">${cap(sev)}</span><span class="col-count">${reach ? `<b>${reach} reachable</b> · ` : ''}${items.length}</span></div>
      <div class="col-body">${body}</div>
    </div>`;
  }).join('');

  $('board').querySelectorAll('.card').forEach(card => {
    card.addEventListener('click', () => openInspector(card.dataset.id));
  });
}

function cardHtml(f) {
  const vs = VSTATUS[f.verification_status] || VSTATUS.inconclusive;
  const isSel = selected === f.candidate_id;
  const reach = f.verification_status === 'verified';
  return `<button type="button" class="card${reach ? ' reachable' : ''}" data-id="${esc(f.candidate_id)}" aria-pressed="${isSel}" title="${esc(f.advisory_id)}">
    <span class="card-top"><span class="card-pkg">${esc(f.package || '?')}@${esc(f.version || '?')}</span>${reach ? `<span class="tag tag-sm ${vs.cls}">${vs.label}</span>` : ''}</span>
    <span class="card-sum">${esc(f.summary || f.advisory_id)}</span>
  </button>`;
}

// ---- Inspector ----

function openInspector(id) {
  const f = (report && report.findings || []).find(x => x.candidate_id === id);
  if (!f) return;
  selected = id;
  $('board').querySelectorAll('.card').forEach(c => c.setAttribute('aria-pressed', String(c.dataset.id === id)));
  const vs = VSTATUS[f.verification_status] || VSTATUS.inconclusive;
  const sev = f.severity || 'unknown';
  $('insp-body').innerHTML = `
    <div class="insp-pkg">${esc(f.package)}@${esc(f.version || '?')}</div>
    ${f.summary ? `<div class="insp-sum">${esc(f.summary)}</div>` : ''}
    <div class="insp-tags">
      <span class="tag sev-${esc(sev)}">${cap(sev)}</span>
      <span class="tag ${vs.cls}">${vs.label}</span>
      <span class="mono">risk ${f.risk_score ?? '--'} · ${f.direct ? 'direct' : 'transitive'}</span>
    </div>
    ${sourcesList(f)}
    ${reasoning(f)}`;
  $('inspector').hidden = false;
  $('insp-backdrop').hidden = false;
}

function closeInspector() {
  selected = null;
  $('inspector').hidden = true;
  $('insp-backdrop').hidden = true;
  document.querySelectorAll('.card[aria-pressed="true"]').forEach(c => c.setAttribute('aria-pressed', 'false'));
}

$('insp-close').addEventListener('click', closeInspector);
$('insp-backdrop').addEventListener('click', closeInspector);
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('inspector').hidden) closeInspector(); });

// Every input the verdict rests on, in the order it was used. Paths are local, links are external.
function sourcesFor(f) {
  const out = [];
  if (f.source_url) out.push({ node: 'repo', type: 'Lockfile', value: shortPath(f.source_url) });
  if (f.advisory_url) out.push({ node: 'advisory', type: 'Advisory, OSV', value: f.advisory_id, href: f.advisory_url });
  (f.checks_performed || []).filter(c => c.startsWith('semgrep:')).forEach(c => {
    out.push({ node: 'verify', type: 'Semgrep rule', value: 'rules/' + c.slice('semgrep:'.length) });
  });
  (f.evidence || []).filter(e => (e.kind === 'semgrep' || e.kind === 'runtime') && e.source_url).forEach(e => {
    out.push({ node: 'verify', type: e.kind === 'semgrep' ? 'Code match' : 'Runtime check', value: shortPath(e.source_url) });
  });
  return out;
}

function sourcesList(f) {
  const rows = sourcesFor(f);
  if (!rows.length) return '';
  return `<div class="sources">
    <div class="sec-label">Sources <span class="mono">${rows.length}</span></div>
    <ol class="src-list">${rows.map(r => `
      <li><span class="dot ${r.node}"></span><span class="src-type">${esc(r.type)}</span>
        ${r.href
          ? `<a class="src-val" href="${esc(r.href)}" target="_blank" rel="noopener" title="${esc(r.href)}">${esc(r.value)} <span aria-hidden="true">&#8599;</span></a>`
          : `<span class="src-val" title="${esc(r.value)}">${esc(r.value)}</span>`}
      </li>`).join('')}
    </ol>
  </div>`;
}

// What each source established, one short statement per step.
function reasoning(f) {
  const steps = [];
  steps.push({ node: 'repo', title: 'Installed', body: `<div class="quote">"${esc(f.package)}": "${esc(f.version || '?')}"</div>` });
  if (f.reason) {
    steps.push({ node: 'advisory', title: 'Matched', body: `<div class="tsm">${esc(f.reason.replace(/\s*\(source:[^)]*\)\s*$/, ''))}</div>` });
  }
  const hit = (f.evidence || []).find(e => e.kind === 'semgrep');
  let verify;
  if (hit) {
    const m = /matched (\S+?):(\d+): (.*)$/s.exec(hit.detail || '');
    const firstSentence = m ? m[3].split(/(?<=\.)\s/)[0] : hit.detail;
    verify = `${m ? `<div class="codeline">${esc(m[1].replace(/^demo\/[^/]+\//, ''))}:${esc(m[2])}</div>` : ''}<div class="tsm">${esc(firstSentence)}</div>`;
  } else if (f.verification_status === 'present') {
    verify = '<div class="tsm">Affected version confirmed in the lockfile. No code rule exists for this advisory, so reachability was not checked.</div>';
  } else {
    verify = (f.evidence || []).map(e => `<div class="tsm">${esc(e.detail)}</div>`).join('') || '<div class="tsm">No checks recorded.</div>';
  }
  const vs = VSTATUS[f.verification_status] || VSTATUS.inconclusive;
  steps.push({ node: 'verify', title: vs.label, body: verify });
  const fix = f.suggested_fix || (f.fixed_version ? `Upgrade ${f.package} to ${f.fixed_version} or later` : null);
  if (fix) steps.push({ node: 'fixn', title: 'Fix', body: `<div class="fix">${esc(fix)}</div>` });

  return `<div class="sec-label">Reasoning</div><div class="chain">${steps.map((st, i) => `
    <div class="cstep"><div class="crail"><div class="cnode ${st.node}"></div>${i < steps.length - 1 ? '<div class="cline"></div>' : ''}</div>
      <div class="cbody"><h4>${esc(st.title)}</h4>${st.body}</div></div>`).join('')}</div>`;
}

// file:///abs/.../demo/juice-shop/x#L5 -> demo/juice-shop/x:5
function shortPath(url) {
  let p = String(url).replace(/^file:\/\//, '');
  let line = '';
  const h = p.indexOf('#L');
  if (h >= 0) { line = ':' + p.slice(h + 2); p = p.slice(0, h); }
  const i = p.indexOf('/demo/');
  if (i >= 0) p = p.slice(i + 1);
  else if (p.startsWith('/')) p = p.split('/').slice(-3).join('/');
  return p + line;
}

// ---- Polling ----

function startFeed() {
  if (feedTimer) clearInterval(feedTimer);
  feedTimer = setInterval(poll, 2000);
  poll();
}

async function poll() {
  if (!targetId) return;
  try {
    const url = '/api/events?target_id=' + targetId + (lastEventTs ? '&since=' + encodeURIComponent(lastEventTs) : '');
    const evts = await get(url);
    if (evts.length) appendEvents(evts);

    if (runId && runActive) {
      const run = await get('/api/runs/' + runId);
      lastRun = run;
      if (run.state === 'complete' || run.state === 'failed') await finishRun(run);
      renderPipeline(run);
      renderRunMeta();
    }
  } catch (_) { /* transient; the next tick retries */ }
}

// Terminal order: oldest at the top. Follow the tail only if the user is already at the bottom.
function appendEvents(evts) {
  lastEventTs = evts[0].ts;
  const term = $('term');
  const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 24;
  if (!eventCount) term.innerHTML = '';
  const frag = document.createDocumentFragment();
  evts.slice().reverse().forEach(e => {
    const row = document.createElement('div');
    row.className = `tline ${esc(e.level)}`;
    row.innerHTML = `<span class="t">${fmtTime(e.ts)}</span><span class="lv">${esc(String(e.level).toUpperCase())}</span><span class="sg ${esc(e.stage)}">${esc(e.stage)}</span><span class="m">${esc(e.message)}</span>`;
    frag.appendChild(row);
  });
  term.appendChild(frag);
  eventCount += evts.length;
  setCount('events', eventCount);
  if (atBottom || eventCount === evts.length) term.scrollTop = term.scrollHeight;
}

async function finishRun(run) {
  runActive = false;
  if (elapsedTimer) clearInterval(elapsedTimer);
  setBusy(false);
  if (run.state === 'failed') {
    showRunError(run.error || 'The scan failed.');
    renderBoard('Scan failed');
    return;
  }
  try {
    report = await get('/api/runs/' + runId + '/report');
  } catch (err) {
    showRunError('Scan finished but the report could not be loaded (' + err.message + ').');
    return;
  }
  setCount('findings', (report.findings || []).length);
  renderKpis();
  renderFilter();
  renderBoard();
  loadChanges();
  pollStats();
}

async function loadChanges() {
  try {
    const data = await get('/api/targets/' + targetId + '/changes');
    const changes = data.changes || [];
    setCount('changes', changes.length);
    $('changes').innerHTML = changes.length
      ? changes.map(c => `<div class="chg">${esc(c.description)}</div>`).join('')
      : `<div class="term-empty">${data.previous_run_id ? 'Nothing new since the previous scan.' : 'First scan of this target. Run again later to see what changed.'}</div>`;
  } catch (_) { /* optional panel */ }
}

async function pollStats() {
  try {
    const [s, h] = await Promise.all([get('/api/stats'), get('/api/health')]);
    $('corpus-count').textContent = fmtNum(s.advisories_total || 0);
    $('query-latency').textContent = Math.round(s.last_query_latency_ms || 0) + ' ms';
    $('record-count').textContent = fmtNum(s.total_records || 0);
    $('sys-mode').textContent = s.demo_mode ? 'demo' : 'live';
    $('sys-ch').innerHTML = h.clickhouse ? '<span class="dot green"></span>Connected' : '<span class="dot red"></span>Down';
    $('demo-btn').hidden = !s.demo_mode;
  } catch (_) {
    $('sys-ch').innerHTML = '<span class="dot red"></span>API unreachable';
  }
}

// ---- Nav, panel tabs, collapse, resize ----

function showTab(tab) {
  document.querySelectorAll('.panel-tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === tab)));
  $('term').hidden = tab !== 'activity';
  $('changes').hidden = tab !== 'changes';
}

document.querySelectorAll('.panel-tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));

document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => {
  document.querySelectorAll('.nav-item').forEach(i => i.removeAttribute('aria-current'));
  item.setAttribute('aria-current', 'page');
  const view = item.dataset.view;
  if (view === 'findings') { $('board').scrollIntoView({ block: 'nearest' }); return; }
  const shell = $('shell');
  shell.classList.remove('panel-collapsed');
  if (shell.dataset.panelHPrev) {
    shell.style.setProperty('--panel-h', shell.dataset.panelHPrev);
    delete shell.dataset.panelHPrev;
  }
  showTab(view);
}));

$('panel-toggle').addEventListener('click', () => {
  const shell = $('shell');
  const collapsed = shell.classList.toggle('panel-collapsed');
  $('panel-toggle').setAttribute('aria-label', collapsed ? 'Expand panel' : 'Collapse panel');
  if (collapsed) {
    shell.dataset.panelHPrev = shell.style.getPropertyValue('--panel-h');
    shell.style.removeProperty('--panel-h');
  } else if (shell.dataset.panelHPrev) {
    shell.style.setProperty('--panel-h', shell.dataset.panelHPrev);
    delete shell.dataset.panelHPrev;
  }
});

// Drag the top edge of the panel to resize it; the height is remembered per browser.
(function initResize() {
  const shell = $('shell');
  const handle = $('panel-resize');
  try {
    const saved = localStorage.getItem('sw.panelH');
    if (saved) shell.style.setProperty('--panel-h', saved + 'px');
  } catch (_) { /* storage unavailable */ }
  handle.addEventListener('pointerdown', e => {
    e.preventDefault();
    handle.setPointerCapture(e.pointerId);
    handle.classList.add('dragging');
    shell.classList.remove('panel-collapsed');
    const move = ev => {
      const h = Math.min(Math.max(window.innerHeight - ev.clientY, 120), window.innerHeight * 0.7);
      shell.style.setProperty('--panel-h', Math.round(h) + 'px');
    };
    const up = () => {
      handle.classList.remove('dragging');
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      try { localStorage.setItem('sw.panelH', parseInt(shell.style.getPropertyValue('--panel-h'), 10)); } catch (_) { /* ignore */ }
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
  });
})();

// ---- Demo replay ----

$('demo-btn').addEventListener('click', async () => {
  const id = prompt('Advisory ID to replay:');
  if (!id) return;
  try {
    await post('/api/advisories/replay', { advisory_id: id.trim() });
    $('demo-btn').textContent = 'Released, next poll picks it up';
  } catch (err) {
    $('demo-btn').textContent = 'Replay failed (' + err.message + ')';
  }
  setTimeout(() => { $('demo-btn').textContent = 'Replay advisory'; }, 3000);
});

// ---- Helpers ----

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

// The API returns naive UTC timestamps; pin them to UTC before formatting locally.
function parseTs(ts) {
  const s = String(ts);
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + 'Z').getTime();
}

function fmtTime(ts) {
  return new Date(parseTs(ts)).toLocaleTimeString('en-US', { hour12: false });
}

function fmtDuration(ms) {
  const sec = Math.max(0, Math.round(ms / 1000));
  return sec < 60 ? sec + 's' : Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
}

function fmtNum(n) {
  return n == null ? '--' : Number(n).toLocaleString();
}

function cap(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---- Init ----
renderPipeline({ state: 'idle' });
renderKpis();
renderFilter();
renderBoard();
pollStats();
setInterval(pollStats, 15000);
