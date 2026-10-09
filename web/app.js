'use strict';

const API = '';
let targetId = null;
let runId = null;
let feedTimer = null;
let statsTimer = null;
let lastEventTs = null;

const $ = id => document.getElementById(id);

// Radio toggle
document.querySelectorAll('input[name=target-type]').forEach(r => {
  r.addEventListener('change', e => {
    $('repo-input').style.display = e.target.value === 'repo' ? '' : 'none';
    $('domain-input').style.display = e.target.value === 'public' ? '' : 'none';
  });
});

// Start scan
$('start-btn').addEventListener('click', async () => {
  const type = document.querySelector('input[name=target-type]:checked').value;
  const val = type === 'repo' ? $('repo-path').value.trim() : $('domain').value.trim();
  if (!val) return;

  $('start-btn').disabled = true;
  lastEventTs = null;
  $('findings-body').innerHTML = '';
  $('changes-list').querySelector('ul').innerHTML = '';

  try {
    const tRes = await post('/api/targets', {
      kind: type === 'repo' ? 'connected_repo' : 'public',
      name: val,
      repo: type === 'repo' ? val : null,
      domain: type === 'public' ? val : null,
    });
    targetId = tRes.target_id;

    const auth = $('auth-status');
    auth.className = tRes.authorized ? 'ok' : 'no';
    auth.textContent = tRes.authorized
      ? `Authorized: ${tRes.authorization_reason}`
      : `Not authorized: ${tRes.authorization_reason}`;

    const rRes = await post('/api/runs', { target_id: targetId, trigger: 'manual' });
    runId = rRes.run_id;

    startFeed();
    startStats();
  } catch (e) {
    alert('Failed to start: ' + e.message);
  } finally {
    $('start-btn').disabled = false;
  }
});

function startFeed() {
  if (feedTimer) clearInterval(feedTimer);
  feedTimer = setInterval(pollFeed, 2000);
  pollFeed();
}

async function pollFeed() {
  if (!targetId) return;
  try {
    const url = '/api/events?target_id=' + targetId + (lastEventTs ? '&since=' + encodeURIComponent(lastEventTs) : '');
    const evts = await get(url);
    if (evts.length) {
      lastEventTs = evts[0].ts;
      const feed = $('feed');
      const frag = document.createDocumentFragment();
      evts.reverse().forEach(e => {
        const row = document.createElement('div');
        row.className = 'feed-row ' + e.level;
        row.innerHTML = `<span class="t">${fmtTime(e.ts)}</span><span class="feed-tag">${esc(e.stage)}</span><span>${esc(e.message)}</span>`;
        frag.appendChild(row);
      });
      feed.insertBefore(frag, feed.firstChild);
    }

    if (runId) {
      const run = await get('/api/runs/' + runId);
      if (run.state === 'complete' || run.state === 'failed') {
        loadFindings();
        loadChanges();
      }
    }
  } catch (_) {}
}

function startStats() {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(pollStats, 5000);
  pollStats();
}

async function pollStats() {
  try {
    const s = await get('/api/stats');
    $('corpus-count').textContent = (s.advisories_total || 0).toLocaleString() + ' advisories';
    $('query-latency').textContent = Math.round(s.last_query_latency_ms || 0) + ' ms';
    $('record-count').textContent = (s.total_records || 0).toLocaleString();

    if (s.demo_mode) {
      $('demo-btn').style.display = '';
    }
  } catch (_) {}
}

async function loadFindings() {
  if (!runId) return;
  try {
    const report = await get('/api/runs/' + runId + '/report');
    let findings = report.findings || [];

    if ($('filter-direct').checked) findings = findings.filter(f => f.direct);
    if ($('filter-confirmed').checked) findings = findings.filter(f => f.match_type === 'confirmed');

    $('findings-body').innerHTML = findings.map((f, i) => `
      <tr data-idx="${i}">
        <td>${i + 1}</td>
        <td>
          ${esc(f.package || '?')}@${esc(f.version || '?')}
          ${f.status === 'inferred' ? '<span class="badge guess">Guess, unverified</span>' : ''}
          ${f.replayed ? '<span class="badge replay">Replayed for demo</span>' : ''}
        </td>
        <td><a href="${esc(f.advisory_url || '#')}" target="_blank">${esc(f.advisory_id)}</a></td>
        <td><span class="sev ${f.severity}">${f.severity}</span></td>
        <td>${f.match_type}${!f.version ? ' <span class="badge noversion">Version unknown</span>' : ''}</td>
        <td><span class="vstatus ${f.verification_status}">${f.verification_status}</span></td>
        <td style="max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(f.suggested_fix || '--')}</td>
      </tr>
    `).join('');

    // Store findings for modal
    window._findings = findings;
    document.querySelectorAll('#findings-body tr').forEach(row => {
      row.addEventListener('click', () => showEvidence(window._findings[+row.dataset.idx]));
    });
  } catch (e) {
    console.error('loadFindings', e);
  }
}

async function loadChanges() {
  if (!targetId) return;
  try {
    const data = await get('/api/targets/' + targetId + '/changes');
    const ul = $('changes-list').querySelector('ul');
    ul.innerHTML = (data.changes || []).map(c =>
      `<li>${esc(c.description)}</li>`
    ).join('') || '<li style="color:var(--muted)">No changes</li>';
  } catch (_) {}
}

// Filter listeners
$('filter-direct').addEventListener('change', loadFindings);
$('filter-confirmed').addEventListener('change', loadFindings);

// Evidence modal
function showEvidence(f) {
  $('evidence-content').innerHTML = `
    <div class="ev-block">
      <div class="kind">Stack Item</div>
      <div>${esc(f.package)}@${esc(f.version || 'unknown')}</div>
      ${f.source_url ? `<a href="${esc(f.source_url)}" target="_blank">View source</a>` : ''}
    </div>
    <div class="ev-block">
      <div class="kind">Advisory ${esc(f.advisory_id)}</div>
      <div>${esc(f.summary || '')}</div>
      <a href="${esc(f.advisory_url || '#')}" target="_blank">View on OSV</a>
    </div>
    ${(f.evidence || []).map(e => `
      <div class="ev-block">
        <div class="kind">${esc(e.kind)}</div>
        <div>${esc(e.detail)}</div>
        ${e.source_url ? `<a href="${esc(e.source_url)}" target="_blank">View source</a>` : ''}
      </div>
    `).join('')}
    <div class="ev-block">
      <div class="kind">Suggested Fix</div>
      <div>${esc(f.suggested_fix || 'See advisory')}</div>
    </div>
  `;
  $('modal-overlay').classList.add('open');
}

$('modal-close').addEventListener('click', () => $('modal-overlay').classList.remove('open'));
$('modal-overlay').addEventListener('click', e => { if (e.target === $('modal-overlay')) $('modal-overlay').classList.remove('open'); });

// Demo replay
$('demo-btn').addEventListener('click', async () => {
  const id = prompt('Advisory ID to replay:');
  if (!id) return;
  try {
    await post('/api/advisories/replay', { advisory_id: id });
    alert('Released. Next poll will pick it up.');
  } catch (e) {
    alert('Failed: ' + e.message);
  }
});

// Helpers
async function get(url) {
  const r = await fetch(API + url);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function post(url, body) {
  const r = await fetch(API + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('en-US', { hour12: false });
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
}

// Init
pollStats();
