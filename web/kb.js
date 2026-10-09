'use strict';

// Knowledgebase reading view. Loaded after app.js and uses its globals ($, esc, cap, fmtNum,
// parseTs, get, runId). Every value in the KB is scraped from the internet or written by a
// model, so nothing is interpolated without esc() and links go through link().

let kb = null;
let kbRunId = null;
let kbRunKind = 'repo';
let kbTab = null;
let kbTimer = null;
let kbLoading = false;
let kbSubsExpanded = false;
// Ask box and Senso ingest status live outside the DOM: kbRender() rewrites innerHTML.
let kbAsk = { q: '', busy: false, asked: '', answer: null, citations: [], error: '' };
let kbSenso = null;
let kbSensoRun = null;
let kbSensoTimer = null;
let kbSensoTries = 0;

const KB_ACTIVE = ['building', 'enriching', 'cross-referencing'];
const KB_SENSO_WAIT = ['waiting', 'pending', 'ingesting'];
const KB_SENSO_MAX_TRIES = 60;
const KB_SUBS_COLLAPSE = 60;
const KB_INTEL_SOURCES = [
  { keys: ['kev', 'cisa-kev'], label: 'CISA known exploited list' },
  { keys: ['nvd'], label: 'NVD CVE database' },
  { keys: ['epss'], label: 'EPSS exploit probability' },
  { keys: ['osv'], label: 'OSV.dev (JavaScript libraries)' },
  { keys: ['posture'], label: 'Configuration posture rules' },
];
const KB_COVERAGE_LABEL = {
  dns: 'DNS records',
  mail: 'Email authentication records',
  tls: 'TLS certificate',
  asn: 'IP ownership (ASN)',
  rdap: 'Domain registration (RDAP)',
  website: 'Website and well-known files',
  subdomains: 'Certificate transparency logs',
  agent: 'Research agent',
  stack: 'Service identification',
  osv: 'OSV.dev (JavaScript libraries)',
  kev: 'CISA known exploited list',
  'cisa-kev': 'CISA known exploited list',
  nvd: 'NVD CVE database',
  epss: 'EPSS exploit probability',
  posture: 'Configuration posture rules',
  senso: 'Senso knowledge base',
};
const KB_SEC_HEADERS = {
  'strict-transport-security': ['HSTS', 'forces browsers to use HTTPS'],
  'content-security-policy': ['Content-Security-Policy', 'limits where scripts and content can load from'],
  'x-frame-options': ['X-Frame-Options', 'stops other sites from framing the page'],
  'x-content-type-options': ['X-Content-Type-Options', 'stops browsers guessing file types'],
  'referrer-policy': ['Referrer-Policy', 'controls what URL data is sent to other sites'],
  'permissions-policy': ['Permissions-Policy', 'restricts browser features such as camera and location'],
};
const KB_STEP_LABEL = { plan: 'Plan', read: 'Read page', extract: 'Extract facts', thought: 'Thought', final: 'Final', error: 'Error', tool_call: 'Tool call', tool_result: 'Tool result' };
const KB_SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

// ---- Small helpers ----

function kbLink(url, text) {
  const t = text == null ? url : text;
  return /^(https?:|mailto:|tel:)/i.test(String(url || ''))
    ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`
    : esc(t);
}

// Answers and citations come from Senso, so only plain http(s) URLs become links.
function kbHttpLink(url, text) {
  return /^https?:\/\//i.test(String(url || '')) ? kbLink(url, text) : esc(text == null ? url : text);
}

function kbList(v) { return Array.isArray(v) ? v : []; }
function kbObj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
function kbPlural(n, one, many) { return `${fmtNum(n)} ${n === 1 ? one : (many || one + 's')}`; }
function kbDate(iso) {
  const t = iso ? parseTs(iso) : NaN;
  return isNaN(t) ? '' : new Date(t).toISOString().slice(0, 10);
}
function kbAge(iso) {
  const t = iso ? parseTs(iso) : NaN;
  if (isNaN(t)) return '';
  const months = Math.max(0, Math.floor((Date.now() - t) / (30.44 * 864e5)));
  if (months < 1) return 'under a month';
  if (months < 24) return kbPlural(months, 'month');
  return kbPlural(Math.floor(months / 12), 'year');
}
function kbCov(name) { return kb && kb.coverage ? kb.coverage[name] : undefined; }
function kbActive() { return !!kb && KB_ACTIVE.includes(kb.status); }

// Collector state for a section: pending | failed | done. A section is pending while the KB is
// still building and none of its collectors have reported.
function kbState(keys) {
  const cs = keys.map(kbCov);
  if (cs.some(c => c === 'ok' || c === 'partial')) return 'done';
  if (cs.every(c => c === undefined)) return kbActive() ? 'pending' : 'done';
  if (cs.some(c => c === undefined) && kbActive()) return 'pending';
  return 'failed';
}

function kbPending(what) {
  return `<div class="kb-pending"><span class="spinner" aria-hidden="true"></span>${esc(what)}</div>`;
}
function kbEmpty(text) { return `<p class="kb-empty">${esc(text)}</p>`; }

// body() returns '' when there is nothing to show; the section then says what was checked.
function kbSection(n, title, keys, collecting, checked, body, count) {
  const state = kbState(keys);
  let inner;
  if (state === 'pending') inner = kbPending(collecting);
  else if (state === 'failed') inner = kbEmpty('Could not be collected this run. ' + checked);
  else inner = body() || kbEmpty(checked);
  const c = count == null ? '' : `<span class="c">${esc(count)}</span>`;
  return `<section class="kb-sec"><div class="kb-sec-h"><span class="n">${esc(n)}</span><h2>${esc(title)}</h2>${c}</div>${inner}</section>`;
}

function kbDl(rows) {
  const r = rows.filter(x => x && x[1] != null && x[1] !== '' && x[1] !== false);
  return r.length ? `<dl class="kb-dl">${r.map(x => `<dt>${esc(x[0])}</dt><dd>${x[1]}</dd>`).join('')}</dl>` : '';
}

function kbCheck(ok, label, hint) {
  return `<li class="${ok ? 'yes' : 'no'}"><span class="mk" aria-hidden="true">${ok ? '+' : '-'}</span><span>${esc(label)}<span class="kb-src"> ${esc(ok ? 'present' : 'missing')}${hint ? ', ' + esc(hint) : ''}</span></span></li>`;
}

function kbFactsBy(cat) { return kbList(kb.facts).filter(f => f.category === cat); }

// ---- Facts derived from the KB ----

function kbHeaderMap() { return kbObj(kbObj(kb.web).security_headers); }
function kbMissingHeaders() {
  const h = kbHeaderMap();
  return Object.keys(h).filter(k => h[k] !== 'present');
}
function kbHeaderName(k) { return (KB_SEC_HEADERS[k] || [k])[0]; }

function kbTech() {
  const out = kbList(kb.stack).map(t => ({
    name: t.name, category: t.category || 'other', version: t.version, confidence: t.confidence,
    evidence: t.evidence, source: t.source, host: t.host,
  }));
  const seen = new Set(out.map(t => String(t.name).toLowerCase()));
  kbFactsBy('stack').forEach(f => {
    if (seen.has(String(f.value).toLowerCase())) return;
    out.push({ name: f.value, category: f.key || 'other', confidence: f.confidence, evidence: '', source: f.source });
  });
  return out;
}

// Configuration observations come from the recon itself, so they show even when intel is empty.
function kbObservations() {
  const out = [];
  const add = (sev, title, detail, source) => out.push({ sev, title, detail, source });
  const web = kbObj(kb.web);
  const mail = kbObj(kb.mail);
  const dns = kbObj(kb.dns);
  const tls = kbObj(kbObj(kb.infra).tls);
  const done = k => ['ok', 'partial'].includes(kbCov(k));

  if (done('website')) {
    const miss = kbMissingHeaders();
    if (miss.length) {
      add(miss.includes('content-security-policy') || miss.includes('strict-transport-security') ? 'medium' : 'low',
        `Missing browser security headers (${miss.length})`,
        `The home page does not send ${miss.map(kbHeaderName).join(', ')}. These headers tell browsers to block common attacks such as clickjacking, content sniffing and script injection.`,
        'website');
    }
  }
  if (done('mail')) {
    if (!mail.spf) {
      add('medium', 'No SPF record',
        kbList(mail.mx_hosts).length
          ? 'Without SPF, receiving servers cannot tell which servers may send mail for this domain, so forged mail is easier to deliver.'
          : 'The domain does not receive mail, but without SPF anyone can still forge mail that appears to come from it. A "v=spf1 -all" record prevents that.',
        'dns:TXT');
    }
    const dm = kbObj(mail.dmarc);
    if (!mail.dmarc) {
      add('medium', 'No DMARC record', 'DMARC tells receivers what to do with mail that fails SPF and DKIM. Without it, spoofed mail from this domain is delivered by default.', 'dns:_dmarc');
    } else if (dm.policy === 'none') {
      add('low', 'DMARC policy is monitor only', 'The policy is p=none, so failing mail is reported but still delivered. Moving to quarantine or reject blocks spoofing.', 'dns:_dmarc');
    }
  }
  if (done('dns') && !kbList(dns.caa).length) {
    add('low', 'No CAA record', 'A CAA record restricts which certificate authorities may issue certificates for the domain. Without one, any authority can.', 'dns:CAA');
  }
  if (done('tls') && typeof tls.days_left === 'number' && tls.days_left <= 21) {
    add(tls.days_left <= 7 ? 'high' : 'medium', `TLS certificate expires in ${kbPlural(Math.max(tls.days_left, 0), 'day')}`,
      'An expired certificate shows browsers a full-page warning and breaks API clients. Confirm that renewal is automated.', 'tls');
  }
  kbFactsBy('posture').forEach(f => {
    if (/security headers/i.test(f.key)) return;
    if (/^security\.txt$/i.test(f.key) && /^missing/i.test(f.value) && !done('website')) return;
    const bad = /missing|absent|none|expired|weak|disabled/i.test(f.value);
    add(bad ? 'low' : 'unknown', `${f.key}: ${f.value}`,
      /security\.txt/i.test(f.key) && bad
        ? 'No security.txt means researchers have no published way to report a vulnerability.' : '', f.source);
  });
  out.sort((a, b) => KB_SEV_RANK[a.sev] - KB_SEV_RANK[b.sev]);
  return out;
}

// ---- Ask the knowledgebase (Senso) ----

function kbAskHtml() {
  const head = '<div class="kb-ask-h"><h2>Ask the knowledgebase</h2><span class="kb-ask-by">Powered by Senso</span></div>';
  const s = kbSenso;
  let note = '';
  let ready = false;
  if (kbActive()) note = kbEmpty('Available when the scan completes. The finished knowledgebase is sent to Senso so you can ask questions about it.');
  else if (!s) note = kbPending('Checking Senso...');
  else if (s.state === 'not_configured') note = kbEmpty('Senso is not configured. Set SENSO_API_KEY on the server and run a new scan to ask questions here.');
  else if (s.state === 'failed') note = `<p class="kb-ask-err">Senso ingest failed${s.error ? ': ' + esc(s.error) : ''}.</p>`;
  else if (KB_SENSO_WAIT.includes(s.state)) note = kbSensoTries >= KB_SENSO_MAX_TRIES
    ? kbEmpty('Senso is still indexing this knowledgebase. Reopen the tab to check again.')
    : kbPending(s.state === 'ingesting' ? 'Senso is indexing this knowledgebase...' : 'Sending this knowledgebase to Senso...');
  else if (s.state === 'ready') ready = true;
  else note = kbEmpty('Senso status unknown.');

  const off = !ready || kbAsk.busy ? ' disabled' : '';
  const form = `<form class="kb-ask-form" data-kb-ask><input class="input" name="q" type="text" maxlength="500" autocomplete="off" placeholder="${esc('Ask about ' + kb.domain + ', e.g. Is DMARC enforced?')}" aria-label="Question about this knowledgebase" value="${esc(kbAsk.q)}"${off}><button class="btn btn-sm btn-primary" type="submit"${off}>Ask</button></form>`;

  let out = '';
  if (kbAsk.busy) out = kbPending('Asking Senso...');
  else if (kbAsk.error) out = `<p class="kb-ask-err">Senso could not answer: ${esc(kbAsk.error)}</p>`;
  else if (kbAsk.answer != null) {
    const cites = kbList(kbAsk.citations);
    out = `<div class="kb-ask-q">${esc(kbAsk.asked)}</div><p class="kb-ask-a">${esc(kbAsk.answer || 'Senso found nothing in this knowledgebase that answers the question.')}</p>` +
      (cites.length ? `<div class="kb-group-h">Citations (${cites.length})</div><ol class="kb-cites">${cites.map(c => `<li><div class="t">${esc(c.title)}${typeof c.score === 'number' ? `<span class="kb-src"> score ${esc(c.score.toFixed(2))}</span>` : ''}</div><div class="d">${esc(c.snippet)}</div>${kbList(c.urls).length ? `<div class="kb-src">${kbList(c.urls).map(u => kbHttpLink(u, u)).join(' ')}</div>` : ''}</li>`).join('')}</ol>` : '');
  }
  return `<section class="kb-ask">${head}${note}${form}${out ? `<div class="kb-ask-out" aria-live="polite">${out}</div>` : ''}</section>`;
}

function kbSensoStop() {
  if (kbSensoTimer) clearTimeout(kbSensoTimer);
  kbSensoTimer = null;
}

// Polls ingest status once the KB is complete, until Senso reports a final state.
async function kbSensoLoad() {
  kbSensoTimer = null;
  const id = kbRunId;
  if (!id || !kb || kbActive()) return;
  try {
    const s = await get('/api/runs/' + id + '/senso');
    if (id !== kbRunId) return;
    const changed = !kbSenso || kbSenso.state !== s.state;
    kbSenso = s;
    kbSensoTries += 1;
    if (changed && kbTab === 'target') kbRender();
  } catch (_) { kbSensoTries += 1; }
  if (id === kbRunId && (!kbSenso || KB_SENSO_WAIT.includes(kbSenso.state)) && kbSensoTries < KB_SENSO_MAX_TRIES) {
    kbSensoTimer = setTimeout(kbSensoLoad, 3000);
  } else if (kbTab === 'target') kbRender();
}

function kbSensoEnsure() {
  if (!kb || kbActive() || !kbRunId || kbSensoRun === kbRunId) return;
  kbSensoRun = kbRunId;
  kbSensoTries = 0;
  kbSensoStop();
  kbSensoLoad();
}

async function kbAskSubmit(q) {
  const id = kbRunId;
  q = String(q || '').trim();
  if (!q || !id || kbAsk.busy) return;
  kbAsk = { q, busy: true, asked: q, answer: null, citations: [], error: '' };
  kbRender();
  try {
    const r = await fetch('/api/runs/' + id + '/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q }),
    });
    const data = await r.json().catch(() => ({}));
    if (id !== kbRunId) return;
    if (!r.ok) {
      const d = data && data.detail;
      kbAsk.error = typeof d === 'string' ? d : `request failed (HTTP ${r.status})`;
    } else {
      kbAsk.answer = String(data.answer || '');
      kbAsk.citations = kbList(data.citations);
    }
  } catch (_) {
    if (id === kbRunId) kbAsk.error = 'the server could not be reached';
  } finally {
    if (id === kbRunId) { kbAsk.busy = false; kbRender(); }
  }
}

// ---- Target tab ----

function kbAgentCallout(text, pendingText, label) {
  const a = kbObj(kb.agent);
  const model = a.model || 'unknown model';
  if (text) {
    return `<div class="kb-agent"><div class="kb-agent-h"><span class="dlabel"><span class="dot"></span>${esc(label)} by ${esc(model)}</span><span>Model-written. Verify before relying on it.</span></div><p>${esc(text)}</p></div>`;
  }
  if (kbActive()) return `<div class="kb-agent pending"><div class="kb-agent-h"><span class="dlabel"><span class="dot"></span>${esc(label)}</span></div><p>${kbPending(pendingText)}</p></div>`;
  if (!a.available) return `<div class="kb-agent pending"><div class="kb-agent-h"><span class="dlabel"><span class="dot"></span>${esc(label)}</span></div><p>The research agent was not available for this run, so no written ${esc(label.toLowerCase())} exists. The records below come from direct checks only.</p></div>`;
  return `<div class="kb-agent pending"><div class="kb-agent-h"><span class="dlabel"><span class="dot"></span>${esc(label)}</span></div><p>The research agent ran but did not write a ${esc(label.toLowerCase())}.</p></div>`;
}

function kbMasthead() {
  const c = kbObj(kb.company);
  const web = kbObj(kb.web);
  const infra = kbObj(kb.infra);
  const name = c.name || kb.domain;
  const desc = c.description || c.what_they_do || web.description;
  const chips = [];
  if (c.location) chips.push(['Location', c.location]);
  if (c.founded) chips.push(['Founded', c.founded]);
  if (infra.created) chips.push(['Domain age', kbAge(infra.created)]);
  if (c.industry) chips.push(['Industry', c.industry]);
  const lede = desc
    ? `<p class="kb-lede">${esc(desc)}</p>`
    : kbActive() ? `<p class="kb-lede">${kbPending('Reading the home page for a description')}</p>`
      : '<p class="kb-lede">The site does not publish a description, so there is no self-reported summary.</p>';
  return `<header class="kb-mast"><div class="kb-eyebrow">Target dossier</div>
    <h1 class="kb-title">${esc(name)}${name !== kb.domain ? `<span class="mono">${esc(kb.domain)}</span>` : ''}</h1>${lede}
    ${chips.length ? `<div class="kb-chips">${chips.map(x => `<span class="kb-chip">${esc(x[0])} <b>${esc(x[1])}</b></span>`).join('')}</div>` : ''}</header>`;
}

function kbGlance() {
  const web = kbObj(kb.web);
  const infra = kbObj(kb.infra);
  const mail = kbObj(kb.mail);
  const tls = kbObj(infra.tls);
  const wait = kbActive();
  const cell = (k, v, s) => {
    const empty = v == null || v === '';
    return `<div><span class="k">${esc(k)}</span><span class="v${empty ? ' muted' : ''}">${empty ? (wait ? 'Collecting' : 'Not found') : esc(v)}</span>${s ? `<span class="s">${esc(s)}</span>` : ''}</div>`;
  };
  let host = '';
  try { host = web.final_url ? new URL(web.final_url).host : ''; } catch (_) { host = ''; }
  const mx = kbList(mail.mx_hosts);
  const emailV = mail.provider || (['ok', 'partial'].includes(kbCov('mail')) ? (mx.length ? 'Self-hosted or unknown' : 'None (no MX)') : '');
  const hosting = infra.cdn && infra.hosting && infra.cdn !== infra.hosting ? `${infra.hosting} via ${infra.cdn}` : (infra.hosting || infra.cdn);
  const nSub = kbList(kb.subdomains).length;
  const regS = infra.created ? `Registered ${kbAge(infra.created)} ago` : '';
  return `<div class="kb-glance">
    ${cell('Website', host, web.status ? `HTTP ${web.status}` : '')}
    ${cell('Hosting', hosting, kbList(infra.ips).length ? kbPlural(kbList(infra.ips).length, 'IP address') : '')}
    ${cell('Email', emailV, '')}
    ${cell('Registrar', infra.registrar, regS)}
    ${cell('TLS issuer', tls.issuer, typeof tls.days_left === 'number' ? `${kbPlural(tls.days_left, 'day')} left` : '')}
    ${cell('Subdomains', ['ok', 'partial'].includes(kbCov('subdomains')) ? fmtNum(nSub) : '', 'from certificate logs')}
    ${cell('Technologies', kbTech().length || (['ok', 'partial'].includes(kbCov('stack')) ? '0' : ''), 'fingerprinted')}
    ${cell('Facts recorded', kbList(kb.facts).length ? fmtNum(kbList(kb.facts).length) : '', 'each with a source')}
  </div>`;
}

function kbOrgSection(n) {
  const c = kbObj(kb.company);
  return kbSection(n, 'Organization', ['website'], 'Reading the site for organization details...',
    'The home page was read and no organization name, location or contact details were published.',
    () => {
      const socials = kbObj(c.socials);
      const emails = kbList(c.emails);
      const phones = kbList(c.phones);
      const bits = [];
      if (c.name) bits.push(`The site presents itself as <b>${esc(c.name)}</b>${c.legal_name && c.legal_name !== c.name ? `, legally <b>${esc(c.legal_name)}</b>` : ''}.`);
      if (c.location) bits.push(`It lists a location of <b>${esc(c.location)}</b>.`);
      if (c.founded) bits.push(`It says it was founded in <b>${esc(c.founded)}</b>.`);
      const rows = kbDl([
        ['Name', c.name ? esc(c.name) : ''],
        ['Legal name', c.legal_name ? esc(c.legal_name) : ''],
        ['Industry', c.industry ? esc(c.industry) : ''],
        ['Location', c.location ? esc(c.location) : ''],
        ['Founded', c.founded ? esc(c.founded) : ''],
        ['Employees', c.employees ? esc(c.employees) : ''],
        ['Email', emails.length ? emails.map(e => kbLink('mailto:' + e, e)).join(', ') : ''],
        ['Phone', phones.length ? phones.map(p => kbLink('tel:' + p, p)).join(', ') : ''],
        ['Social', Object.keys(socials).length ? Object.keys(socials).map(k => kbLink(socials[k], cap(k))).join(', ') : ''],
      ]);
      const af = kbList(kb.facts).filter(f => f.by === 'agent' && f.category !== 'stack');
      const agentRows = af.length
        ? `<div class="kb-group-h">Researched by ${esc(kbObj(kb.agent).model || 'the agent')}</div><dl class="kb-dl">${af.map(f => `<dt>${esc(cap(f.key))}</dt><dd>${esc(f.value)}<span class="sub kb-src">${esc(f.confidence)} confidence, source ${/^https?:/i.test(f.source) ? kbLink(f.source, f.source) : esc(f.source)}</span></dd>`).join('')}</dl>` : '';
      if (!bits.length && !rows && !agentRows) return '';
      return (bits.length ? `<p class="kb-prose">${bits.join(' ')}</p>` : '') + agentRows + (rows ? (agentRows ? '<div class="kb-group-h">From the site</div>' : '') + rows : '');
    });
}

// Empty app shell: the readable text and links come from the JavaScript bundle instead.
function kbSpa(spa) {
  if (!spa || typeof spa !== 'object') return '';
  const fw = kbList(spa.frameworks);
  const build = kbList(spa.build);
  const bundles = kbList(spa.bundles);
  const bytes = bundles.reduce((a, b) => a + (Number(b.bytes) || 0), 0);
  const size = bytes ? (bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(bytes / 1024)) + ' KB') : '';
  const links = kbList(spa.links);
  const copy = kbList(spa.copy);
  let h = `<p class="kb-prose">The home page is a <b>JavaScript app shell</b> with almost no HTML of its own, so the text below was read from its bundle${build.length ? `, built with ${build.map(esc).join(', ')}` : ''}${fw.length ? ` and using ${fw.map(esc).join(', ')}` : ''}${size ? `. The bundle is ${esc(size)} across ${kbPlural(bundles.length, 'file')}` : ''}.</p>`;
  h += kbDl([
    ['Routes', kbList(spa.routes).length ? `<span class="mono">${kbList(spa.routes).map(esc).join('<br>')}</span>` : ''],
    ['Emails', kbList(spa.emails).length ? kbList(spa.emails).map(e => kbLink('mailto:' + e, e)).join(', ') : ''],
    ['Outbound links', links.length ? links.map(u => `<span class="sub">${kbLink(u, u)}</span>`).join('') : ''],
  ]);
  if (copy.length) h += `<details class="kb-details"><summary>Text read from the app bundle (${copy.length})</summary><div class="kb-trace">${copy.map(t => `<div><span class="i"></span><span class="k"></span><span class="c">${esc(t)}</span></div>`).join('')}</div></details>`;
  return h;
}

function kbWebSection(n) {
  const web = kbObj(kb.web);
  return kbSection(n, 'Website', ['website'], 'Fetching the home page, robots.txt, security.txt and sitemap...',
    'The home page could not be fetched, so nothing is known about the web server.',
    () => {
      if (!web.final_url && !web.status) return '';
      const sh = kbHeaderMap();
      const keys = Object.keys(sh);
      const miss = kbMissingHeaders();
      const sec = kbObj(web.security_txt);
      const rob = kbObj(web.robots);
      const sm = kbObj(web.sitemap);
      const hosts = kbList(web.external_hosts);
      let prose = `The home page ${web.final_url ? `at <b>${esc(web.final_url)}</b> ` : ''}answered with HTTP <b>${esc(web.status)}</b>`;
      prose += web.server ? ` and identifies its server as <b>${esc(web.server)}</b>.` : ' and does not reveal its server software.';
      if (keys.length) {
        prose += miss.length
          ? ` It is missing <span class="warn">${miss.length} of ${keys.length}</span> common security headers.`
          : ` It sends all ${keys.length} common security headers.`;
      }
      const checks = keys.length
        ? `<ul class="kb-checks">${keys.map(k => kbCheck(sh[k] === 'present', kbHeaderName(k), (KB_SEC_HEADERS[k] || [])[1])).join('')}</ul>` : '';
      const rows = kbDl([
        ['Title', web.title ? esc(web.title) : ''],
        ['Powered by', web.powered_by ? esc(web.powered_by) : ''],
        ['Generator', web.generator ? esc(web.generator) : ''],
        ['security.txt', sec.present
          ? `Published${kbList(sec.contact).length ? ', contact ' + kbList(sec.contact).map(c => kbLink(c, c)).join(', ') : ''}${sec.expires ? `<span class="sub">Expires ${esc(sec.expires)}</span>` : ''}`
          : 'Not published. Researchers have no standard way to report a vulnerability.'],
        ['robots.txt', rob.present ? `Present${kbList(rob.disallow).length ? `, hides ${kbPlural(kbList(rob.disallow).length, 'path')}` : ''}` : 'Not published'],
        ['Sitemap', sm.present ? `${kbPlural(sm.url_count || 0, 'URL')} listed` : 'Not published'],
        ['Third-party hosts', hosts.length ? `<span class="mono">${hosts.map(esc).join(', ')}</span><span class="sub">Content loaded from outside this domain.</span>` : 'None. The page loads nothing from other hosts.'],
        ['Cookies', kbList(web.cookies).length ? kbPlural(kbList(web.cookies).length, 'cookie') + ' set' : 'None set'],
      ]);
      return `<p class="kb-prose">${prose}</p>${kbSpa(web.spa)}${checks}${rows}`;
    });
}

function kbMailSection(n) {
  const m = kbObj(kb.mail);
  return kbSection(n, 'Email', ['mail'], 'Looking up MX, SPF, DMARC, MTA-STS and DKIM records...',
    'DNS was queried for mail records and none were found.',
    () => {
      const mx = kbList(m.mx_hosts);
      const spf = kbObj(m.spf);
      const dm = kbObj(m.dmarc);
      const hasSpf = !!m.spf;
      const out = [];
      if (m.null_mx) out.push('The domain publishes a null MX, which says explicitly that it <b>does not accept mail</b>.');
      else if (m.provider) out.push(`Mail is handled by <b>${esc(m.provider)}</b>${mx.length ? ` (${kbPlural(mx.length, 'mail server')})` : ''}.`);
      else if (mx.length) out.push(`Mail goes to <b>${esc(mx[0])}</b>, which is not a recognized provider, so it may be self-hosted.`);
      else out.push('The domain has <b>no MX records</b>, so it does not receive email.');

      if (hasSpf) {
        const q = spf.all === '-all' ? 'rejects mail from any server not listed' : spf.all === '~all' ? 'marks mail from unlisted servers as suspicious but still accepts it' : spf.all === '?all' ? 'takes no position on unlisted servers' : spf.all === '+all' ? '<span class="bad">allows any server to send as this domain</span>' : 'does not end with an all rule';
        out.push(`<b>SPF</b> lists who may send for the domain and ${q}${kbList(spf.providers).length ? `. Authorized senders include ${kbList(spf.providers).map(esc).join(', ')}` : ''}.`);
      } else {
        out.push('<b>SPF</b> is <span class="warn">missing</span>, so receivers cannot check which servers may send for this domain.');
      }
      if (m.dmarc) {
        const pol = dm.policy;
        const meaning = pol === 'reject' ? 'tells receivers to <span class="ok">reject</span> mail that fails authentication'
          : pol === 'quarantine' ? 'tells receivers to send failing mail to spam'
            : pol === 'none' ? '<span class="warn">only monitors</span>; failing mail is still delivered' : 'has no recognizable policy';
        out.push(`<b>DMARC</b> ${meaning}${kbList(dm.rua).length ? `, with reports going to ${kbList(dm.rua).map(r => esc(String(r).replace(/^mailto:/i, ''))).join(', ')}` : ''}.`);
      } else {
        out.push('<b>DMARC</b> is <span class="warn">missing</span>, so forged mail from this domain is delivered by default.');
      }
      out.push(m.mta_sts ? '<b>MTA-STS</b> is published, so sending servers are told to require encrypted delivery.'
        : '<b>MTA-STS</b> is not published, so encrypted delivery is opportunistic.');
      out.push(kbList(m.dkim_selectors).length
        ? `<b>DKIM</b> signing keys were found for ${kbList(m.dkim_selectors).map(s => esc(s)).join(', ')}.`
        : '<b>DKIM</b> keys were not found at common selector names. This does not prove they are absent, since selectors are not discoverable.');
      const rows = kbDl([
        ['MX', mx.length ? `<span class="mono">${mx.map(esc).join('<br>')}</span>` : ''],
        ['SPF record', m.spf ? `<span class="mono">${esc(spf.record)}</span>` : ''],
        ['DMARC record', m.dmarc ? `<span class="mono">${esc(dm.record)}</span>` : ''],
        ['MTA-STS', m.mta_sts ? `<span class="mono">${esc(m.mta_sts)}</span>` : ''],
        ['BIMI', m.bimi ? `<span class="mono">${esc(m.bimi)}</span>` : ''],
      ]);
      return `<p class="kb-prose">${out.join(' ')}</p>${rows}`;
    });
}

function kbDnsSection(n) {
  const d = kbObj(kb.dns);
  const i = kbObj(kb.infra);
  return kbSection(n, 'Domain and DNS', ['dns', 'rdap'], 'Querying DNS and the registration database (RDAP)...',
    'DNS and registration lookups returned no records for this domain.',
    () => {
      const mono = a => kbList(a).length ? `<span class="mono">${kbList(a).map(esc).join('<br>')}</span>` : '';
      const txt = kbList(d.txt);
      const prose = [];
      if (i.registrar) prose.push(`The domain is registered through <b>${esc(i.registrar)}</b>${i.created ? `, ${kbAge(i.created)} ago (${esc(kbDate(i.created))})` : ''}${i.expires ? ` and paid through ${esc(kbDate(i.expires))}` : ''}.`);
      if (kbList(d.ns).length) prose.push(`DNS is served by ${kbList(d.ns).map(esc).join(' and ')}.`);
      prose.push(d.dnssec ? 'DNSSEC is enabled, so DNS answers are cryptographically signed.' : 'DNSSEC is not enabled, so DNS answers are not cryptographically signed.');
      if (!kbList(d.caa).length) prose.push('No CAA record limits which authorities may issue certificates.');
      const rows = kbDl([
        ['Registrar', i.registrar ? esc(i.registrar) : ''],
        ['Registered', i.created ? esc(kbDate(i.created)) : ''],
        ['Expires', i.expires ? esc(kbDate(i.expires)) : ''],
        ['Last changed', i.updated ? esc(kbDate(i.updated)) : ''],
        ['Registry locks', kbList(i.registry_status).length ? kbList(i.registry_status).map(esc).join(', ') : ''],
        ['Nameservers', mono(d.ns)],
        ['A', mono(d.a)],
        ['AAAA', mono(d.aaaa)],
        ['MX', kbList(d.mx).length ? `<span class="mono">${kbList(d.mx).map(m => esc(typeof m === 'string' ? m : `${m.priority} ${m.host}`)).join('<br>')}</span>` : ''],
        ['CAA', mono(d.caa)],
        ['CNAME', d.cname ? `<span class="mono">${esc(d.cname)}</span>` : ''],
        ['www', kbObj(d.www).cname ? `<span class="mono">CNAME ${esc(kbObj(d.www).cname)}</span>` : ''],
        ['SOA', d.soa ? `<span class="mono">${esc(d.soa)}</span>` : ''],
      ]);
      const txtBlock = `<details class="kb-details"><summary>TXT records (${txt.length})</summary>${txt.length ? `<div class="kb-trace">${txt.map(t => `<div><span class="i"></span><span class="k"></span><span class="c">${esc(t)}</span></div>`).join('')}</div>` : kbEmpty('No TXT records are published.')}</details>`;
      return `<p class="kb-prose">${prose.join(' ')}</p>${rows}${txtBlock}`;
    });
}

function kbHostingSection(n) {
  const i = kbObj(kb.infra);
  const tls = kbObj(i.tls);
  return kbSection(n, 'Hosting and network', ['asn', 'tls'], 'Resolving IP ownership and reading the TLS certificate...',
    'No IP ownership or certificate data was collected.',
    () => {
      const ips = kbList(i.ips);
      const orgs = [...new Set(ips.map(x => x.org).filter(Boolean))];
      const prose = [];
      if (i.hosting || i.cdn) prose.push(`Traffic is served from <b>${esc(i.hosting || i.cdn)}</b>${orgs.length ? ` (${orgs.map(esc).join(', ')})` : ''} across ${kbPlural(ips.length, 'IP address')}.`);
      if (tls.issuer) {
        const left = tls.days_left;
        const when = typeof left === 'number' ? (left < 0 ? '<span class="bad">expired</span>' : left <= 21 ? `<span class="warn">expires in ${kbPlural(left, 'day')}</span>` : `valid for another ${kbPlural(left, 'day')}`) : '';
        prose.push(`The TLS certificate was issued by <b>${esc(tls.issuer)}</b>${when ? ' and is ' + when : ''}.`);
      }
      const ipRows = ips.length
        ? `<dl class="kb-dl">${ips.map(x => `<dt class="mono">${esc(x.ip)}</dt><dd>${x.asn ? `AS${esc(x.asn)} ` : ''}${esc(x.org || 'unknown owner')}<span class="sub">${[x.prefix, x.country].filter(Boolean).map(esc).join(' / ')}</span></dd>`).join('')}</dl>` : '';
      const tlsRows = kbDl([
        ['Certificate for', tls.subject ? `<span class="mono">${esc(tls.subject)}</span>` : ''],
        ['Also covers', kbList(tls.sans).length ? `<span class="mono">${kbList(tls.sans).map(esc).join(', ')}</span>` : ''],
        ['Valid', tls.not_before ? esc(`${kbDate(tls.not_before)} to ${kbDate(tls.not_after)}`) : ''],
        ['Protocol', tls.version ? esc(tls.version) : ''],
      ]);
      if (!prose.length && !ipRows && !tlsRows) return '';
      return `${prose.length ? `<p class="kb-prose">${prose.join(' ')}</p>` : ''}${ipRows}${tlsRows}`;
    });
}

function kbStackSection(n) {
  const tech = kbTech();
  return kbSection(n, 'Technology stack', ['stack'], 'Fingerprinting headers, HTML and scripts...',
    'Headers, HTML and scripts were fingerprinted and no technologies could be identified. Sites that hide their stack look like this.',
    () => {
      if (!tech.length) return '';
      const groups = {};
      tech.forEach(t => { (groups[t.category] = groups[t.category] || []).push(t); });
      const body = Object.keys(groups).sort().map(cat => `<div class="kb-group-h">${esc(cap(String(cat).replace(/[-_]/g, ' ')))}</div>` +
        groups[cat].map(t => `<div class="kb-tech"><div class="nm">${esc(t.name)}${t.version ? `<span class="mono">${esc(t.version)}</span>` : ''}</div><div class="ev">${esc(t.evidence || '')}${t.host ? ` (${esc(t.host)})` : ''}</div><div class="cf kb-src">${esc(t.confidence || '')}</div></div>`).join('')).join('');
      return `<p class="kb-prose">${kbPlural(tech.length, 'technology', 'technologies')} identified from response headers, page markup and loaded scripts. Versions are shown only when the site reveals them.</p>${body}`;
    }, tech.length || null);
}

function kbSubsSection(n) {
  const subs = kbList(kb.subdomains);
  return kbSection(n, 'Subdomains', ['subdomains'], 'Searching certificate transparency logs for subdomains...',
    'Certificate transparency logs list no subdomains for this domain.',
    () => {
      if (!subs.length) return '';
      const notable = subs.filter(s => s.interesting);
      const rest = subs.filter(s => !s.interesting);
      const shown = kbSubsExpanded ? rest : rest.slice(0, KB_SUBS_COLLAPSE);
      let h = `<p class="kb-prose"><b>${fmtNum(subs.length)}</b> ${subs.length === 1 ? 'hostname was' : 'hostnames were'} found in public certificate logs${notable.length ? `, <span class="warn">${notable.length} worth a closer look</span>` : ''}. Each one is part of the attack surface.</p>`;
      h += notable.map(s => `<div class="kb-host"><div class="h">${esc(s.name)}</div><div class="why">${esc(s.interesting)}<span>${[s.title, ...kbList(s.ips).slice(0, 2)].filter(Boolean).map(esc).join(' / ')}</span></div></div>`).join('');
      if (rest.length) {
        h += `<div class="kb-group-h">${notable.length ? 'Other hostnames' : 'Hostnames'}</div><div class="kb-cols">${shown.map(s => `<div title="${esc(s.name)}">${esc(s.name)}</div>`).join('')}</div>`;
        if (rest.length > KB_SUBS_COLLAPSE) h += `<button class="btn btn-ghost btn-sm" type="button" data-kb-subs>${kbSubsExpanded ? 'Show fewer' : `Show all ${fmtNum(rest.length)}`}</button>`;
      }
      return h;
    }, subs.length || null);
}

function kbAgentSection(n) {
  const a = kbObj(kb.agent);
  const steps = kbList(a.steps);
  const nFacts = kbList(kb.facts).filter(f => f.by === 'agent').length;
  // Extract steps read like "app bundle: 5 facts kept, 2 rejected (no supporting quote)".
  let kept = 0;
  let rejected = 0;
  let parsed = false;
  steps.filter(s => s.kind === 'extract').forEach(s => {
    const m = /(\d+) facts? kept(?:, (\d+) rejected)?/i.exec(String(s.content));
    if (m) { parsed = true; kept += Number(m[1]); rejected += Number(m[2] || 0); }
  });
  return kbSection(n, 'Agent research', ['agent'], 'The research agent is browsing the site and recording facts...',
    a.available ? 'The agent finished without taking any recorded steps.' : 'The research agent was not available for this run.',
    () => {
      if (!steps.length) return '';
      const sum = parsed
        ? `${esc(a.model || 'The agent')}: ${fmtNum(kept)} ${kept === 1 ? 'fact' : 'facts'} kept, ${fmtNum(rejected)} rejected for lack of a supporting quote.`
        : `${esc(a.model || 'The agent')} recorded ${fmtNum(nFacts)} ${nFacts === 1 ? 'fact' : 'facts'}.`;
      return `<p class="kb-prose">${sum} The kept facts appear in Organization with their sources.</p>` +
        `<details class="kb-details"><summary>Agent trace (${steps.length} steps)</summary><div class="kb-trace">${steps.map(s => `<div><span class="i">${esc(s.step)}</span><span class="k ${esc(s.kind)}">${esc((KB_STEP_LABEL[s.kind] || cap(String(s.kind))) + (s.name ? ' ' + s.name : ''))}</span><span class="c">${esc(s.content)}</span></div>`).join('')}</div></details>`;
    }, steps.length || null);
}

function kbCoverageSection(n) {
  const cov = kbObj(kb.coverage);
  const keys = Object.keys(KB_COVERAGE_LABEL).filter(k => k in cov && !['kev', 'cisa-kev', 'nvd', 'epss', 'osv', 'posture'].includes(k));
  Object.keys(cov).forEach(k => { if (!KB_COVERAGE_LABEL[k]) keys.push(k); });
  const word = { ok: 'checked', partial: 'partly checked', failed: 'failed', skipped: 'skipped' };
  const dot = { ok: 'green', partial: 'amber', failed: 'red', skipped: 'gray' };
  let h;
  if (!keys.length) h = kbActive() ? kbPending('Waiting for the first collector to report...') : kbEmpty('No collectors reported.');
  else h = `<ul class="kb-checks">${keys.map(k => `<li><span class="dlabel"><span class="dot ${dot[cov[k]] || 'gray'}"></span>${esc(KB_COVERAGE_LABEL[k] || cap(k))} <span class="kb-src">${esc(word[cov[k]] || cov[k])}</span></span></li>`).join('')}</ul>`;
  return `<section class="kb-sec"><div class="kb-sec-h"><span class="n">${esc(n)}</span><h2>Sources checked</h2></div>${h}</section>`;
}

function kbTargetHtml() {
  const secs = [kbOrgSection, kbWebSection, kbMailSection, kbDnsSection, kbHostingSection, kbStackSection, kbSubsSection, kbAgentSection];
  kbSensoEnsure();
  return kbAskHtml() + kbMasthead() +
    kbAgentCallout(kbObj(kb.agent).profile, 'The agent is researching this organization...', 'Profile') +
    kbGlance() +
    secs.map((f, i) => f(String(i + 1).padStart(2, '0'))).join('') +
    kbCoverageSection(String(secs.length + 1).padStart(2, '0'));
}

// ---- Exposure tab ----

function kbIntelRan() {
  if (kb.status === 'complete') return true;
  return KB_INTEL_SOURCES.some(s => s.keys.some(k => kbCov(k)));
}

function kbHit(h) {
  const sev = kbSev(h.severity);
  const id = h.url ? kbLink(h.url, h.id) : esc(h.id);
  const posture = h.source === 'posture';
  const matchWord = posture ? 'observed' : h.match === 'confirmed' ? 'version confirmed' : 'version not confirmed';
  const meta = [h.tech, matchWord, typeof h.epss === 'number' ? `EPSS ${(h.epss * 100).toFixed(1)}%` : ''].filter(Boolean).map(esc).join(' / ');
  return `<div class="kb-hit${h.kev ? ' kev' : ''}"><div class="kb-hit-h"><span class="id">${id}</span><span class="tag tag-sm sev-${sev}">${esc(cap(sev))}</span>${h.kev ? '<span class="tag tag-sm kev">Known exploited</span>' : ''}${h.kev_ransomware ? '<span class="tag tag-sm ransom">Ransomware use</span>' : ''}<span class="meta">${meta}</span></div>
    <div class="t">${esc(h.title)}</div>${h.detail ? `<div class="d">${esc(h.detail)}</div>` : ''}${h.evidence ? `<div class="d mono">${esc(h.evidence)}</div>` : ''}${h.fixed_version ? `<div class="fx">Fixed in ${esc(h.fixed_version)}</div>` : ''}${h.fix ? `<div class="fx">${esc(h.fix)}</div>` : ''}</div>`;
}
function kbSev(s) { return KB_SEV_RANK[s] != null ? s : 'unknown'; }

function kbBySev(list) {
  return list.slice().sort((a, b) => KB_SEV_RANK[kbSev(a.severity)] - KB_SEV_RANK[kbSev(b.severity)]);
}

function kbIntelCheckedList() {
  const ran = kbIntelRan();
  const rows = KB_INTEL_SOURCES.map(s => {
    const c = s.keys.map(kbCov).find(x => x);
    const st = c || (ran ? 'ok' : (kbActive() ? 'pending' : 'skipped'));
    const word = st === 'skipped' && s.keys.includes('osv') && ran ? 'skipped, no versioned JavaScript libraries to check'
      : { ok: 'checked', partial: 'partly checked', failed: 'failed', skipped: 'not run', pending: 'running' }[st];
    const dot = { ok: 'green', partial: 'amber', failed: 'red', skipped: 'gray', pending: 'verify' }[st];
    return `<li><span class="dlabel"><span class="dot ${dot}"></span>${esc(s.label)} <span class="kb-src">${esc(word)}</span></span></li>`;
  });
  return `<ul class="kb-checks">${rows.join('')}</ul>`;
}

function kbExposureHtml() {
  const intel = kbList(kb.intel);
  const ran = kbIntelRan();
  const sev = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  intel.forEach(h => { sev[kbSev(h.severity)] += 1; });
  const nKev = intel.filter(h => h.kev).length;
  const cell = (cls, v, k) => `<div class="${cls}${v === 0 ? ' zero' : ''}"><span class="v">${fmtNum(v)}</span><span class="k">${esc(k)}</span></div>`;
  const stat = ran || intel.length
    ? `<div class="kb-sevs">${['critical', 'high', 'medium', 'low'].map(s => cell(s, sev[s], cap(s))).join('')}${cell('kev', nKev, 'Known exploited')}</div>`
    : '';
  let lede;
  if (!intel.length && !ran) lede = kbActive() ? kbPending('Cross-referencing detected technologies against threat intelligence...') : kbEmpty('Threat intelligence was not run for this scan.');
  else if (!intel.length) lede = '<p class="kb-lede">No known exposures found. Every detected technology was checked against the sources below and none matched a published vulnerability.</p>';
  else lede = `<p class="kb-lede">${kbPlural(intel.length, 'exposure')} matched${nKev ? `, ${nKev} of them known to be exploited in the wild` : ''}. Known-exploited entries come first because attackers are already using them.</p>`;
  const mast = `<header class="kb-mast"><div class="kb-eyebrow">Exposure</div><h1 class="kb-title">${esc(kb.domain)}<span class="mono">threat intelligence</span></h1>${lede}${stat}</header>`;

  const brief = kbObj(kb.agent).brief;
  const callout = kbAgentCallout(brief, 'The agent is writing an analyst brief...', 'Analyst brief');

  const kev = kbBySev(intel.filter(h => h.kev));
  const conf = kbBySev(intel.filter(h => !h.kev && h.source === 'posture'));
  const vulns = kbBySev(intel.filter(h => !h.kev && h.source !== 'posture'));
  const state = ran ? 'done' : (kbActive() ? 'pending' : 'done');
  const grp = (n, title, list, emptyText, detail) => {
    let inner;
    if (state === 'pending') inner = kbPending('Matching technologies against threat intelligence...');
    else if (!ran && !list.length) inner = kbEmpty('Not run for this scan.');
    else if (!list.length) inner = kbEmpty(emptyText);
    else inner = detail(list);
    return `<section class="kb-sec"><div class="kb-sec-h"><span class="n">${n}</span><h2>${esc(title)}</h2><span class="c">${list.length}</span></div>${inner}</section>`;
  };
  const byTech = list => {
    const g = {};
    list.forEach(h => { (g[h.tech || 'Unattributed'] = g[h.tech || 'Unattributed'] || []).push(h); });
    return Object.keys(g).sort().map(t => `<div class="kb-group-h">${esc(t)}</div>${g[t].map(kbHit).join('')}`).join('');
  };
  const groups = grp('01', 'Known exploited', kev, 'None of the detected technologies appear on the CISA known exploited vulnerabilities list.', l => l.map(kbHit).join('')) +
    grp('02', 'Vulnerabilities by technology', vulns, 'No published vulnerabilities matched the detected technologies and versions.', byTech) +
    grp('03', 'Configuration findings', conf, 'The configuration rules raised no findings.', l => l.map(kbHit).join(''));

  const obs = kbObservations();
  const obsDone = ['website', 'mail', 'dns', 'tls'].some(k => ['ok', 'partial'].includes(kbCov(k)));
  let obsBody;
  if (!obsDone && kbActive()) obsBody = kbPending('Recon is still collecting the records these observations come from...');
  else if (!obs.length) obsBody = kbEmpty('Recon checked security headers, SPF, DMARC, CAA and certificate expiry and found nothing worth flagging.');
  else {
    obsBody = `<p class="kb-prose">These are observations from the recon records, not matches against a vulnerability database. They show how the domain is configured, and each is a hardening gap rather than a known flaw.</p>` +
      obs.map(o => `<div class="kb-hit"><div class="kb-hit-h"><span class="tag tag-sm sev-${kbSev(o.sev)}">${esc(cap(o.sev))}</span><span class="meta">${esc(o.source || '')}</span></div><div class="t">${esc(o.title)}</div>${o.detail ? `<div class="d">${esc(o.detail)}</div>` : ''}</div>`).join('');
  }
  const observations = `<section class="kb-sec"><div class="kb-sec-h"><span class="n">04</span><h2>Observations from recon</h2><span class="c">${obs.length}</span></div>${obsBody}</section>`;

  const checked = `<section class="kb-sec"><div class="kb-sec-h"><span class="n">05</span><h2>Intel sources</h2></div>
    <p class="kb-prose">${ran ? 'Sources consulted for this report:' : 'Intel sources have not run for this scan:'}</p>${kbIntelCheckedList()}</section>`;
  // Once the backend configuration checks have run they cover these observations (and appear on
  // the Findings board), so the browser-side list only shows for older runs.
  return mast + callout + groups + (kbCov('posture') ? '' : observations) + checked;
}

// ---- Shell ----

function kbShellHtml() {
  const pill = kb && kbActive() ? `<span class="kb-status"><span class="spinner" aria-hidden="true"></span>${esc(cap(kb.status))}...</span>`
    : kb ? `<span class="kb-status">${kb.status === 'failed' ? 'Collection failed' : 'Updated ' + esc(kbDate(kb.updated_ts))}</span>` : '';
  const tabs = `<div class="kb-tabs"><div class="seg seg-sm" role="group" aria-label="Knowledgebase view">
    <button type="button" data-kb-tab="target" aria-pressed="${kbTab === 'target'}">Target</button>
    <button type="button" data-kb-tab="exposure" aria-pressed="${kbTab === 'exposure'}">Exposure</button></div>${pill}</div>`;
  let body;
  if (kbRunKind === 'repo' && !kb) body = kbEmpty('The knowledgebase is built for public-domain scans. Run a scan with the Public domain target type to see the dossier and exposure view here.');
  else if (!kb) body = kbRunId
    ? kbPending('Waiting for the first recon snapshot...')
    : kbEmpty('No public-domain scan yet. Run one to build a dossier on the domain.');
  else body = kb.status === 'failed' && !kbList(kb.facts).length
    ? kbEmpty('Collection failed before any facts were recorded.')
    : (kbTab === 'target' ? kbTargetHtml() : kbExposureHtml());
  return tabs + body;
}

function kbRender() {
  const root = $('kb');
  if (!root) return;
  const typing = document.activeElement && document.activeElement.closest && document.activeElement.closest('[data-kb-ask]');
  try {
    root.innerHTML = kbShellHtml();
    const input = typing && root.querySelector('[data-kb-ask] input');
    if (input && !input.disabled) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  } catch (err) {
    root.innerHTML = `<div class="kb-tabs"></div>${kbEmpty('The knowledgebase could not be displayed (' + (err && err.message) + ').')}`;
  }
  kbCounts();
}

function kbCounts() {
  const t = $('nav-kb-target');
  const e = $('nav-kb-exposure');
  if (!t || !e) return;
  if (!kb) { t.textContent = '--'; e.textContent = '--'; return; }
  t.textContent = fmtNum(kbList(kb.facts).length);
  e.textContent = kbIntelRan() || kbList(kb.intel).length ? fmtNum(kbList(kb.intel).length) : '--';
}

function kbOpen(tab) {
  kbTab = tab;
  $('canvas').classList.add('kb-open');
  $('kb').hidden = false;
  kbRender();
}

function kbClose() {
  kbTab = null;
  $('canvas').classList.remove('kb-open');
  $('kb').hidden = true;
}

async function kbLoad() {
  if (!kbRunId || kbLoading) return;
  const id = kbRunId;
  kbLoading = true;
  try {
    const data = await get('/api/runs/' + id + '/knowledge');
    if (id !== kbRunId) return;
    kb = data;
    if (!KB_ACTIVE.includes(kb.status)) kbStopPolling();
    if (kbTab) kbRender(); else kbCounts();
    renderKpis();
  } catch (_) { /* 404 until the first snapshot; the next tick retries */ }
  finally { kbLoading = false; }
}

function kbStopPolling() {
  if (kbTimer) clearInterval(kbTimer);
  kbTimer = null;
}

// Called by app.js when a new scan starts.
function kbReset(scanKind) {
  kbStopPolling();
  kb = null;
  kbRunId = null;
  kbRunKind = scanKind;
  kbSubsExpanded = false;
  kbSensoStop();
  kbSenso = null;
  kbSensoRun = null;
  kbAsk = { q: '', busy: false, asked: '', answer: null, citations: [], error: '' };
  if (kbTab) kbRender(); else kbCounts();
}

function kbStart(id) {
  kbRunId = id;
  if (kbRunKind !== 'public') { if (kbTab) kbRender(); return; }
  kbStopPolling();
  kbTimer = setInterval(kbLoad, 2500);
  kbLoad();
  if (kbTab) kbRender();
}

// Called by app.js when the run finishes: one more load picks up the final snapshot.
async function kbFinish() {
  if (kbRunKind !== 'public') return;
  kbStopPolling();
  await kbLoad();
}

document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => {
  const view = item.dataset.view;
  if (view === 'target' || view === 'exposure') kbOpen(view);
  else if (kbTab) kbClose();
}));

$('kb').addEventListener('click', e => {
  const tabBtn = e.target.closest('[data-kb-tab]');
  if (tabBtn) {
    const view = tabBtn.dataset.kbTab;
    document.querySelectorAll('.nav-item').forEach(i => {
      if (i.dataset.view === view) i.setAttribute('aria-current', 'page'); else i.removeAttribute('aria-current');
    });
    kbOpen(view);
    return;
  }
  if (e.target.closest('[data-kb-subs]')) { kbSubsExpanded = !kbSubsExpanded; kbRender(); }
});

$('kb').addEventListener('input', e => {
  if (e.target.closest('[data-kb-ask]')) kbAsk.q = e.target.value;
});

$('kb').addEventListener('submit', e => {
  const form = e.target.closest('[data-kb-ask]');
  if (!form) return;
  e.preventDefault();
  kbAskSubmit(form.elements.q.value);
});

kbCounts();
