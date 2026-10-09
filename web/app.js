'use strict';

// Page state. One scan at a time; the report is fetched once when the run completes.
let kind = 'repo';
let targetId = null;
let runId = null;
let runActive = false;
let runStartedAt = null;
let lastRun = null;
let report = null;
let deep = { vulnscan: [], threats: [], endpoints: [] };
let view = 'advisories';
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
  { key: 'reporting', label: 'Report', desc: 'Rank findings, then hunt secrets, misconfig, endpoints and attack chains.' },
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
  deep = { vulnscan: [], threats: [], endpoints: [] };
  closeInspector();
  ['exposures', 'threats', 'endpoints'].forEach(k => setCount(k, 0));
  renderViews();
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
  const map = {
    events: ['nav-events', 'tab-events'], changes: ['nav-changes', 'tab-changes'], findings: ['nav-findings'],
    exposures: ['nav-exposures'], threats: ['nav-threats'], endpoints: ['nav-endpoints'],
  };
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
    reporting: {
      text: `${fmtNum(f.length)} ranked, ${fmtNum(deep.threats.length)} attack chains`,
      hot: deep.threats.some(t => t.remediation_priority === 'immediate'),
    },
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
    {
      k: 'Attack chains', v: v(deep.threats.length),
      cls: f ? (deep.threats.some(t => t.remediation_priority === 'immediate') ? 'red' : deep.threats.length ? '' : 'green') : 'muted',
      d: f && deep.threats.length ? `top score ${Math.max(...deep.threats.map(t => t.score))} / 10` : 'findings correlated into MITRE ATT&CK chains',
    },
  ];
  $('kpis').innerHTML = cells.map(c =>
    `<div class="kpi" title="${esc(c.d)}"><span class="k">${c.k}</span><span class="v ${c.cls}">${c.v}</span></div>`
  ).join('');
}

// ---- Findings board ----

function renderFilter() {
  $('filter').hidden = view !== 'advisories';
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

// Every result type rides the same severity board, cards and evidence inspector.
const threatSev = t => t.score >= 8 ? 'critical' : t.score >= 5 ? 'high' : t.score >= 3 ? 'medium' : 'low';

const VIEWS = {
  advisories: {
    label: 'Advisories', title: 'Findings by severity',
    items: () => (report ? report.findings || [] : []),
    key: f => f.candidate_id, sev: f => f.severity, order: cardOrder,
    hot: f => f.verification_status === 'verified', hotLabel: 'reachable',
    card: cardHtml, detail: advisoryDetail,
  },
  exposures: {
    label: 'Exposures', title: 'Secrets, misconfig and package risks',
    items: () => deep.vulnscan,
    key: x => x.id, sev: x => x.severity, order: (a, b) => String(a.title).localeCompare(String(b.title)),
    hot: x => x.type === 'secret_exposure', hotLabel: 'secrets',
    card: exposureCard, detail: exposureDetail,
  },
  threats: {
    label: 'Attack chains', title: 'Correlated attack chains, MITRE ATT&CK mapped',
    items: () => deep.threats,
    key: t => t.id, sev: threatSev, order: (a, b) => b.score - a.score,
    hot: t => t.remediation_priority === 'immediate', hotLabel: 'fix now',
    card: threatCard, detail: threatDetail,
  },
  endpoints: {
    label: 'Endpoints', title: 'Attack surface by risk',
    items: () => deep.endpoints,
    key: e => e.url, sev: e => e.risk_level, order: (a, b) => String(a.path).localeCompare(String(b.path)),
    hot: e => e.classification === 'public' && (e.kind === 'sensitive' || e.kind === 'admin'), hotLabel: 'exposed',
    card: endpointCard, detail: endpointDetail,
    emptyNote: () => (kind === 'repo' ? 'Endpoint discovery runs on public domain targets' : null),
  },
};

function renderViews() {
  $('board-views').innerHTML = Object.entries(VIEWS).map(([k, v]) =>
    `<button type="button" data-view="${k}" aria-pressed="${k === view}">${v.label}<span class="count">${fmtNum(v.items().length)}</span></button>`
  ).join('');
  $('board-views').querySelectorAll('button').forEach(b => b.addEventListener('click', () => setView(b.dataset.view)));
  $('board-h2').textContent = VIEWS[view].title;
}

const NAV_FOR_VIEW = { advisories: 'findings', exposures: 'exposures', threats: 'threats', endpoints: 'endpoints' };

function setView(v) {
  view = v;
  closeInspector();
  document.querySelectorAll('.nav-item').forEach(i => {
    if (i.dataset.view === NAV_FOR_VIEW[v]) i.setAttribute('aria-current', 'page');
    else i.removeAttribute('aria-current');
  });
  renderViews();
  renderFilter();
  renderBoard();
}

function renderBoard(emptyMsg) {
  const v = VIEWS[view];
  const all = v.items();
  const list = view === 'advisories' ? all.filter(FILTERS.find(x => x.key === filter).test) : all;
  if (!emptyMsg && report && !all.length && v.emptyNote) emptyMsg = v.emptyNote();
  const bySev = Object.fromEntries(SEVERITIES.map(s => [s, []]));
  list.forEach(x => { const s = v.sev(x); bySev[SEVERITIES.includes(s) ? s : 'unknown'].push(x); });
  const cols = SEVERITIES.filter(s => s !== 'unknown' || bySev.unknown.length);

  $('board').innerHTML = cols.map(sev => {
    const items = bySev[sev].sort(v.order);
    const hot = items.filter(v.hot).length;
    const body = items.length
      ? items.map(v.card).join('')
      : `<div class="col-empty">${esc(emptyMsg || (report ? 'None' : 'No scan yet'))}</div>`;
    return `<div class="col sev-${sev}">
      <div class="col-h"><span class="col-name">${cap(sev)}</span><span class="col-count">${hot ? `<b>${hot} ${v.hotLabel}</b> · ` : ''}${items.length}</span></div>
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
  const v = VIEWS[view];
  const x = v.items().find(i => v.key(i) === id);
  if (!x) return;
  selected = id;
  $('board').querySelectorAll('.card').forEach(c => c.setAttribute('aria-pressed', String(c.dataset.id === id)));
  $('insp-body').innerHTML = v.detail(x);
  $('inspector').hidden = false;
  $('insp-backdrop').hidden = false;
}

function advisoryDetail(f) {
  const vs = VSTATUS[f.verification_status] || VSTATUS.inconclusive;
  const sev = f.severity || 'unknown';
  return `
    <div class="insp-pkg">${esc(f.package)}@${esc(f.version || '?')}</div>
    ${f.summary ? `<div class="insp-sum">${esc(f.summary)}</div>` : ''}
    <div class="insp-tags">
      <span class="tag sev-${esc(sev)}">${cap(sev)}</span>
      <span class="tag ${vs.cls}">${vs.label}</span>
      <span class="mono">risk ${f.risk_score ?? '--'} · ${f.direct ? 'direct' : 'transitive'}</span>
    </div>
    ${sourcesList(f)}
    ${reasoning(f)}`;
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
  return srcBlock(sourcesFor(f));
}

function srcBlock(rows) {
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
  return chainHtml('Reasoning', steps);
}

function chainHtml(label, steps) {
  return `<div class="sec-label">${esc(label)}</div><div class="chain">${steps.map((st, i) => `
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

// ---- Deep scan: exposures, attack chains, endpoints ----

const EXPOSURE_TYPE = {
  secret_exposure: ['Secret', 'Anyone with the repo, or a leaked clone, can use this credential.'],
  npmrc_auth_token: ['Registry token', 'A committed registry token can publish packages under your name.'],
  dangerous_install_script: ['Install script', 'Runs automatically on npm install with the installer\'s privileges.'],
  missing_files_field: ['Publish scope', 'Without a files allowlist, npm publish can ship local files and secrets.'],
  forced_install_config: ['Install config', 'Disables dependency checks, which hides incompatible or tampered versions.'],
  typosquatting: ['Typosquat', 'Name sits one or two edits from a popular package, a common malware delivery trick.'],
  suspicious_package_name: ['Package name', 'Very short names are easy to squat or mistype.'],
  dependency_confusion: ['Dep confusion', 'A public package with this internal name would win the install.'],
  dependency_confusion_candidate: ['Dep confusion', 'Internal-looking name could be hijacked by a higher version on the public registry.'],
  version_gap: ['Version gap', 'Installed version trails the registry by a wide margin.'],
  maintainer_takeover: ['Maintainer change', 'A recent maintainer change is a known precursor to malicious releases.'],
};

const exposureType = x => EXPOSURE_TYPE[x.type] || [cap(String(x.type).replace(/_/g, ' ')), ''];
const fileLoc = x => (x.file ? shortPath(x.file) + (x.line ? ':' + x.line : '') : null);

function exposureCard(x) {
  const [label] = exposureType(x);
  const id = VIEWS.exposures.key(x);
  return `<button type="button" class="card${x.type === 'secret_exposure' ? ' reachable' : ''}" data-id="${esc(id)}" aria-pressed="${selected === id}" title="${esc(x.detail)}">
    <span class="card-top"><span class="card-pkg">${esc(x.package || fileLoc(x) || x.title)}</span><span class="tag tag-sm o-neutral">${esc(label)}</span></span>
    <span class="card-sum">${esc(x.title)}</span>
  </button>`;
}

function exposureDetail(x) {
  const [label, why] = exposureType(x);
  const loc = fileLoc(x);
  const rows = [];
  if (loc) rows.push({ node: 'repo', type: 'File', value: loc });
  if (x.package) rows.push({ node: 'advisory', type: 'Package', value: x.package });
  rows.push({ node: 'verify', type: 'Check', value: x.type });
  const steps = [
    { node: 'repo', title: 'Found', body: `${loc ? `<div class="codeline">${esc(loc)}</div>` : ''}<div class="tsm">${esc(x.detail)}</div>` },
  ];
  if (why) steps.push({ node: 'verify', title: 'Why it matters', body: `<div class="tsm">${esc(why)}</div>` });
  if (x.remediation) steps.push({ node: 'fixn', title: 'Fix', body: `<div class="fix">${esc(x.remediation)}</div>` });
  return `
    <div class="insp-pkg">${esc(x.title)}</div>
    <div class="insp-tags">
      <span class="tag sev-${esc(x.severity || 'unknown')}">${cap(x.severity || 'unknown')}</span>
      <span class="tag o-neutral">${esc(label)}</span>
    </div>
    ${srcBlock(rows)}
    ${chainHtml('Reasoning', steps)}`;
}

// T1195.002 -> https://attack.mitre.org/techniques/T1195/002/
const mitreUrl = t => `https://attack.mitre.org/techniques/${String(t).replace('.', '/')}/`;

function threatCard(t) {
  return `<button type="button" class="card${t.remediation_priority === 'immediate' ? ' reachable' : ''}" data-id="${esc(t.id)}" aria-pressed="${selected === t.id}" title="${esc(t.tactic)}">
    <span class="card-top"><span class="card-pkg">${esc(t.name)}</span><span class="tag tag-sm sev-${threatSev(t)}">${esc(t.score)}</span></span>
    <span class="card-sum">${esc((t.mitre_techniques || []).join(' · '))} · ${esc((t.components || []).length)} components</span>
  </button>`;
}

const CHAIN_NODES = ['repo', 'advisory', 'verify', 'exfil'];

function threatDetail(t) {
  const narrative = String(t.narrative || '').replace(/^[^:]*:\s*(?=\(1\))/, '');
  const steps = narrative.split(/\(\d+\)\s*/).map(s => s.trim()).filter(Boolean).map((s, i) => {
    const m = /^([^:]{1,40}):\s*(.*)$/s.exec(s);
    return {
      node: CHAIN_NODES[Math.min(i, CHAIN_NODES.length - 1)],
      title: m ? cap(m[1]) : `Step ${i + 1}`,
      body: `<div class="tsm">${esc(m ? m[2] : s)}</div>`,
    };
  });
  const fix = t.remediation_priority === 'immediate'
    ? 'Fix the components above now. Removing any single link breaks the chain.'
    : 'Patch the highest-severity component first; any single fix breaks the chain.';
  steps.push({ node: 'fixn', title: `Priority: ${cap(t.remediation_priority)}`, body: `<div class="fix">${esc(fix)}</div>` });

  const rows = (t.mitre_techniques || []).map(m => ({ node: 'advisory', type: 'ATT&CK', value: m, href: mitreUrl(m) }))
    .concat((t.components || []).map(c => ({ node: 'repo', type: 'Component', value: c })));
  return `
    <div class="insp-pkg">${esc(t.name)}</div>
    <div class="insp-sum">${esc(t.tactic)}</div>
    <div class="insp-tags">
      <span class="tag sev-${threatSev(t)}">Score ${esc(t.score)} / 10</span>
      <span class="mono">${esc((t.components || []).length)} linked components</span>
    </div>
    ${srcBlock(rows)}
    ${chainHtml('Attack path', steps)}`;
}

const CLASSIFICATION = {
  public: 'Answered 200 with no authentication challenge.',
  authenticated: 'Asked for credentials (WWW-Authenticate).',
  redirect: 'Redirected elsewhere, likely to a login page.',
  error: 'Did not answer with content.',
};

function endpointFix(e) {
  if (e.classification !== 'public') return null;
  if (e.kind === 'sensitive') return 'Block this path at the web server and remove the file from the deploy.';
  if (e.kind === 'admin') return 'Put this route behind authentication and restrict it by network.';
  if (e.kind === 'api') return 'Require authentication on this API route.';
  return null;
}

function endpointCard(e) {
  const id = VIEWS.endpoints.key(e);
  const server = (e.tech_signals || {}).server || (e.tech_signals || {})['x-powered-by'];
  const hot = VIEWS.endpoints.hot(e);
  return `<button type="button" class="card${hot ? ' reachable' : ''}" data-id="${esc(id)}" aria-pressed="${selected === id}" title="${esc(e.url)}">
    <span class="card-top"><span class="card-pkg">${esc(e.path || e.url)}</span><span class="tag tag-sm ${hot ? 'o-exposed' : 'o-neutral'}">${esc(e.kind)}</span></span>
    <span class="card-sum">${esc(e.classification || 'not probed')}${server ? ' · ' + esc(server) : ''} · via ${esc(e.source)}</span>
  </button>`;
}

function endpointDetail(e) {
  const rows = [{ node: 'repo', type: 'Discovered via', value: e.source }]
    .concat(Object.entries(e.tech_signals || {}).map(([h, v]) => ({ node: 'verify', type: h, value: v })));
  const steps = [
    { node: 'repo', title: 'Discovered', body: `<div class="codeline">${esc(e.url)}</div><div class="tsm">Found through ${esc(e.source)}.</div>` },
    { node: 'verify', title: e.classification ? cap(e.classification) : 'Not probed', body: `<div class="tsm">${esc(CLASSIFICATION[e.classification] || 'Outside the fingerprint budget, so it was not requested.')}</div>` },
  ];
  const fix = endpointFix(e);
  if (fix) steps.push({ node: 'fixn', title: 'Fix', body: `<div class="fix">${esc(fix)}</div>` });
  return `
    <div class="insp-pkg">${esc(e.path || e.url)}</div>
    <div class="insp-tags">
      <span class="tag sev-${esc(e.risk_level || 'unknown')}">${cap(e.risk_level || 'unknown')}</span>
      <span class="tag o-neutral">${esc(e.kind)}</span>
      <span class="mono">${e.auth_required ? 'auth required' : e.classification === 'public' ? 'no auth' : ''}</span>
    </div>
    ${srcBlock(rows)}
    ${chainHtml('Reasoning', steps)}`;
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
  // Deep-scan sections are optional; a missing one renders as empty rather than failing the report.
  const [vulnscan, threats, endpoints] = await Promise.all(
    [['vulnscan', 'findings'], ['threats', 'threats'], ['endpoints', 'endpoints']].map(([path, field]) =>
      get(`/api/runs/${runId}/${path}`).then(r => r[field] || []).catch(() => []))
  );
  deep = { vulnscan, threats, endpoints };
  setCount('findings', (report.findings || []).length);
  setCount('exposures', deep.vulnscan.length);
  setCount('threats', deep.threats.length);
  setCount('endpoints', deep.endpoints.length);
  renderViews();
  renderKpis();
  renderFilter();
  renderBoard();
  loadChanges();
  pollStats();

  // Put the strongest finding in front: the top reachable card opens in the inspector.
  const top = (report.findings || []).filter(f => f.verification_status === 'verified').sort(cardOrder)[0];
  if (view === 'advisories' && top && window.innerWidth > 1280) openInspector(top.candidate_id);
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

const VIEW_FOR_NAV = Object.fromEntries(Object.entries(NAV_FOR_VIEW).map(([v, n]) => [n, v]));

document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => {
  const target = item.dataset.view;
  if (VIEW_FOR_NAV[target]) {
    setView(VIEW_FOR_NAV[target]);
    $('board').scrollIntoView({ block: 'nearest' });
    return;
  }
  document.querySelectorAll('.nav-item').forEach(i => i.removeAttribute('aria-current'));
  const shell = $('shell');
  shell.classList.remove('panel-collapsed');
  if (shell.dataset.panelHPrev) {
    shell.style.setProperty('--panel-h', shell.dataset.panelHPrev);
    delete shell.dataset.panelHPrev;
  }
  showTab(target);
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
renderViews();
renderKpis();
renderFilter();
renderBoard();
pollStats();
setInterval(pollStats, 15000);
