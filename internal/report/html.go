package report

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"lain/internal/types"
)

// htmlData is the data payload embedded in the dashboard. It mirrors a scan
// result minus the raw Route struct (flattened) so the browser has everything
// it needs to render filters, search, and detail expansion.
type htmlData struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	Target     string        `json:"target"`
	Generated  string        `json:"generated"`
	Duration   string        `json:"duration"`
	Scanned    int           `json:"routesScanned"`
	Verdict    string        `json:"verdict"`
	GitHubRepo string        `json:"githubRepo"`
	Findings   []htmlFinding `json:"findings"`
}

type htmlFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	VulnType string `json:"vulnType"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Evidence string `json:"evidence"`
	Location string `json:"location"`
}

func buildHTMLData(result types.ScanResult, target, repo string) htmlData {
	verdict := "PASSED"
	for _, f := range result.Findings {
		if f.Severity == "HIGH" {
			verdict = "FAILED"
			break
		}
	}
	findings := make([]htmlFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, htmlFinding{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			VulnType: f.VulnType,
			Method:   f.Route.Method,
			Path:     f.Route.Path,
			Param:    f.Param,
			Payload:  f.Payload,
			Evidence: f.Evidence,
			Location: f.Location,
		})
	}
	return htmlData{
		Tool:       "lain",
		Version:    "0.1.0",
		Target:     target,
		Generated:  result.FinishedAt.Format(time.RFC3339),
		Duration:   result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond).String(),
		Scanned:    result.TargetsScanned,
		Verdict:    verdict,
		GitHubRepo: repo,
		Findings:   findings,
	}
}

// WriteHTMLReport writes a self-contained interactive dashboard. Findings are
// embedded as JSON — Go's json.Marshal escapes <, > and & to \u003c etc., and
// the page renders every value via textContent — so payloads gathered during
// fuzzing (e.g. real <script> XSS strings) can never execute inside the report.
func WriteHTMLReport(result types.ScanResult, target, repo, path string) error {
	data := buildHTMLData(result, target, repo)
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// json.Marshal does not escape U+2028/U+2029, which are legal inside JS
	// string literals but break HTML script parsing in some engines.
	blob := strings.ReplaceAll(string(raw), "\u2028", `\u2028`)
	blob = strings.ReplaceAll(blob, "\u2029", `\u2029`)

	doc := strings.Replace(htmlTemplate, "__DATA__", blob, 1)
	return os.WriteFile(path, []byte(doc), 0o644)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lain Security Scan Report</title>
<style>
  :root {
    --bg: #0f1115;
    --panel: #171a21;
    --panel2: #1e232d;
    --border: #2a3040;
    --text: #d7dbe3;
    --muted: #8b93a5;
    --high: #f43f5e;
    --medium: #f59e0b;
    --low: #22c55e;
    --accent: #38bdf8;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  a { color: var(--accent); }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 24px 20px 48px; }

  header {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; flex-wrap: wrap;
    padding: 20px 24px; margin-bottom: 24px;
    background: linear-gradient(135deg, #10131a, #151a23);
    border: 1px solid var(--border); border-radius: 12px;
  }
  header h1 { margin: 0; font-size: 20px; letter-spacing: .5px; }
  header h1 span { color: var(--accent); }
  header .sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .verdict {
    font-weight: 700; padding: 8px 14px; border-radius: 8px; font-size: 14px;
  }
  .verdict.pass { background: rgba(34,197,94,.15); color: var(--low); border: 1px solid var(--low); }
  .verdict.fail { background: rgba(244,63,94,.15); color: var(--high); border: 1px solid var(--high); }

  .stats {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px; margin-bottom: 20px;
  }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 16px;
  }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .8px; }
  .card .value { font-size: 26px; font-weight: 700; margin-top: 4px; }
  .card .value.high { color: var(--high); }
  .card .value.medium { color: var(--medium); }
  .card .value.low { color: var(--low); }
  .card .value.accent { color: var(--accent); }

  #sevbar {
    display: flex; height: 14px; border-radius: 999px; overflow: hidden;
    background: var(--panel2); border: 1px solid var(--border); margin-bottom: 20px;
  }
  .sev-seg { height: 100%; min-width: 2px; }

  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
  .pill {
    border: 1px solid var(--border); background: var(--panel);
    color: var(--text); padding: 7px 14px; border-radius: 999px;
    cursor: pointer; font-size: 13px; user-select: none;
  }
  .pill.active { border-color: var(--accent); color: var(--accent); }
  .pill[data-sev="HIGH"].active { border-color: var(--high); color: var(--high); }
  .pill[data-sev="MEDIUM"].active { border-color: var(--medium); color: var(--medium); }
  .pill[data-sev="LOW"].active { border-color: var(--low); color: var(--low); }
  #search {
    flex: 1; min-width: 200px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    color: var(--text); padding: 8px 12px; font-size: 14px; outline: none;
  }
  #search:focus { border-color: var(--accent); }

  .table-wrap {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    overflow: hidden;
  }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .8px;
    color: var(--muted); padding: 12px 16px; border-bottom: 1px solid var(--border);
    background: var(--panel2);
  }
  tbody td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .row { cursor: pointer; }
  .row:hover td { background: rgba(255,255,255,.02); }
  .badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    color: #fff; font-size: 12px; font-weight: 700; letter-spacing: .4px;
  }
  code {
    font-family: var(--mono); font-size: 13px;
    background: var(--panel2); border: 1px solid var(--border);
    padding: 1px 6px; border-radius: 6px;
  }
  .id { font-family: var(--mono); font-size: 12px; color: var(--muted); }

  tr.detail td { background: var(--panel2); }
  .detail-box { display: grid; gap: 10px; }
  .kv { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
  .kv .k { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-bottom: 4px; }
  .kv .v {
    font-family: var(--mono); font-size: 13px; white-space: pre-wrap;
    word-break: break-word;
  }

  .create-btn { border: 1px solid var(--accent); color: var(--accent); background: transparent; }
  .create-btn:hover { background: rgba(56,189,248,.12); }
  .create-all { border-color: var(--accent); color: var(--accent); }
  .create-all:hover { background: rgba(56,189,248,.12); }

  .modal {
    position: fixed; inset: 0; display: none; align-items: center; justify-content: center;
    background: rgba(0,0,0,.55); z-index: 10; padding: 20px;
  }
  .modal-box {
    width: 100%; max-width: 520px; background: var(--panel);
    border: 1px solid var(--border); border-radius: 12px; padding: 22px;
  }
  .modal-box h3 { margin: 0 0 12px; font-size: 17px; }
  .modal-finding {
    background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 12px; margin-bottom: 14px; font-size: 13px;
  }
  .modal-box label { display: block; margin-bottom: 12px; font-size: 13px; color: var(--muted); }
  .modal-box input {
    width: 100%; margin-top: 4px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); padding: 8px 12px; font-size: 14px; outline: none;
  }
  .modal-box input:focus { border-color: var(--accent); }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 16px; }
  .pill.primary { border-color: var(--accent); color: #fff; background: var(--accent); }
  .pill.primary:hover { filter: brightness(1.1); }
  .pill:disabled { opacity: .5; cursor: default; }
  #mi-status { margin-top: 12px; font-size: 13px; word-break: break-word; }
  #mi-status a { color: var(--low); font-weight: 700; }
  .modal-note { margin-top: 14px; font-size: 12px; }

  .empty, .no-match {
    text-align: center; color: var(--muted); padding: 48px 16px; font-size: 15px;
  }
  .empty .ok { font-size: 34px; }
  footer {
    margin-top: 28px; color: var(--muted); font-size: 13px; text-align: center;
  }
  .muted { color: var(--muted); }
  .mono { font-family: var(--mono); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1><span>lain</span> Security Scan Report</h1>
      <div class="sub" id="subline">target: —</div>
    </div>
    <div class="verdict" id="verdict">—</div>
  </header>

  <div class="stats">
    <div class="card"><div class="label">Findings</div><div class="value accent" id="stat-total">0</div></div>
    <div class="card"><div class="label">High</div><div class="value high" id="stat-high">0</div></div>
    <div class="card"><div class="label">Medium</div><div class="value medium" id="stat-medium">0</div></div>
    <div class="card"><div class="label">Low</div><div class="value low" id="stat-low">0</div></div>
    <div class="card"><div class="label">Routes scanned</div><div class="value" id="stat-routes">0</div></div>
    <div class="card"><div class="label">Duration</div><div class="value" id="stat-duration">—</div></div>
  </div>

  <div id="sevbar"></div>

  <div class="controls">
    <div id="pills" style="display:flex;gap:8px;flex-wrap:wrap;"></div>
    <input id="search" type="search" placeholder="Search title, route, evidence, finding ID…" autocomplete="off">
    <button id="create-all" class="pill create-all" style="display:none;">Create all issues</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th style="width:110px">Severity</th>
          <th>Finding</th>
          <th style="width:230px">Location</th>
          <th style="width:150px">Type</th>
          <th style="width:110px">Finding ID</th>
          <th style="width:130px">Actions</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="empty" id="empty" style="display:none;">
      <div class="ok">✅</div>
      <div>No findings — the scan passed clean.</div>
    </div>
    <div class="no-match" id="no-match" style="display:none;">
      No findings match the current filter or search.
    </div>
  </div>

  <footer>
    Generated by <strong>lain</strong> at <span id="gen-time">—</span> ·
    companion reports: <span class="mono">report.json</span>, <span class="mono">report.md</span>, <span class="mono">fix.md</span>
  </footer>
</div>

<div id="issue-modal" class="modal">
  <div class="modal-box">
    <h3 id="mi-title">Create GitHub issue</h3>
    <div class="modal-finding" id="mi-finding"></div>
    <label>GitHub token
      <input id="mi-token" type="password" placeholder="ghp_… or github_pat_…" autocomplete="off" spellcheck="false">
    </label>
    <label>Repo (owner/repo)
      <input id="mi-repo" type="text" placeholder="owner/repo" autocomplete="off" spellcheck="false">
    </label>
    <div id="mi-status"></div>
    <div class="modal-actions">
      <button id="mi-cancel" class="pill">Cancel</button>
      <button id="mi-submit" class="pill primary">Create issue</button>
    </div>
    <p class="modal-note muted">The token is sent only to api.github.com from your browser, for this one request. It is never stored in this report.</p>
  </div>
</div>

<script>
const DATA = __DATA__;
const findings = DATA.findings;

function sevColor(s) {
  return s === 'HIGH' ? 'var(--high)' : s === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';
}
function sevRank(f) { return f.severity === 'HIGH' ? 0 : f.severity === 'MEDIUM' ? 1 : 2; }
function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== '') e.textContent = text;
  return e;
}

const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
findings.forEach(function (f) { if (counts[f.severity] !== undefined) counts[f.severity]++; });

function renderHeader() {
  setText('subline', 'target: ' + DATA.target + '  ·  generated ' + DATA.generated + '  ·  ' + DATA.routesScanned + ' route(s) in ' + DATA.duration);
  const v = document.getElementById('verdict');
  v.textContent = DATA.verdict === 'PASSED' ? '✅ PASSED' : '❌ ' + DATA.verdict;
  v.className = 'verdict ' + (DATA.verdict === 'PASSED' ? 'pass' : 'fail');
  setText('stat-total', findings.length);
  setText('stat-high', counts.HIGH);
  setText('stat-medium', counts.MEDIUM);
  setText('stat-low', counts.LOW);
  setText('stat-routes', DATA.routesScanned);
  setText('stat-duration', DATA.duration);
  setText('gen-time', DATA.generated);
}

function renderBar() {
  const bar = document.getElementById('sevbar');
  bar.innerHTML = '';
  const total = findings.length || 1;
  ['HIGH', 'MEDIUM', 'LOW'].forEach(function (s) {
    if (!counts[s]) return;
    const seg = document.createElement('div');
    seg.className = 'sev-seg';
    seg.style.width = (counts[s] / total * 100).toFixed(2) + '%';
    seg.style.background = sevColor(s);
    seg.title = s + ': ' + counts[s];
    bar.appendChild(seg);
  });
}

let filter = 'all';
let query = '';

function matches(f) {
  if (filter !== 'all' && f.severity !== filter) return false;
  if (!query) return true;
  const hay = (f.title + ' ' + f.location + ' ' + f.evidence + ' ' + f.id + ' ' + f.payload).toLowerCase();
  return hay.indexOf(query) !== -1;
}

function makeRow(f) {
  const tr = el('tr', 'row');
  const tdSev = el('td');
  const badge = el('span', 'badge', f.severity);
  badge.style.background = sevColor(f.severity);
  tdSev.appendChild(badge);
  const tdLoc = el('td');
  tdLoc.appendChild(el('code', null, f.location));
  const tdBtn = el('td');
  const btn = document.createElement('button');
  btn.className = 'pill create-btn';
  btn.textContent = 'Create issue';
  btn.addEventListener('click', function (e) { e.stopPropagation(); openModal(f); });
  tdBtn.appendChild(btn);
  tr.appendChild(tdSev);
  tr.appendChild(el('td', null, f.title));
  tr.appendChild(tdLoc);
  tr.appendChild(el('td', null, f.vulnType || '—'));
  tr.appendChild(el('td', 'id', f.id || '—'));
  tr.appendChild(tdBtn);
  tr.addEventListener('click', function () { toggleDetail(tr, f); });
  return tr;
}

function kv(k, v) {
  const wrap = el('div', 'kv');
  wrap.appendChild(el('div', 'k', k));
  wrap.appendChild(el('div', 'v', v));
  return wrap;
}

function toggleDetail(tr, f) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('detail')) { next.remove(); return; }
  const d = document.createElement('tr');
  d.className = 'detail';
  const td = document.createElement('td');
  td.colSpan = 6;
  const box = el('div', 'detail-box');
  if (f.method || f.path) box.appendChild(kv('Route', f.method + ' ' + f.path));
  if (f.param) box.appendChild(kv('Parameter', f.param));
  if (f.payload) box.appendChild(kv('Payload', f.payload));
  if (f.evidence) box.appendChild(kv('Evidence', f.evidence));
  if (!box.children.length) box.appendChild(el('div', 'muted', 'No extra details.'));
  td.appendChild(box);
  d.appendChild(td);
  tr.parentNode.insertBefore(d, tr.nextSibling);
}

let visibleRows = [];

function renderTable() {
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  visibleRows = findings.filter(matches).sort(function (a, b) {
    return sevRank(a) - sevRank(b) || a.location.localeCompare(b.location);
  });
  document.getElementById('empty').style.display = findings.length ? 'none' : 'block';
  document.getElementById('no-match').style.display = (visibleRows.length === 0 && findings.length > 0) ? 'block' : 'none';
  visibleRows.forEach(function (f) { tbody.appendChild(makeRow(f)); });

  const allBtn = document.getElementById('create-all');
  if (visibleRows.length > 1) {
    allBtn.style.display = '';
    allBtn.textContent = 'Create all issues (' + visibleRows.length + ')';
  } else {
    allBtn.style.display = 'none';
  }
}

function renderPills() {
  const pills = document.getElementById('pills');
  [['all', 'All'], ['HIGH', 'High'], ['MEDIUM', 'Medium'], ['LOW', 'Low']].forEach(function (p) {
    const n = p[0] === 'all' ? findings.length : counts[p[0]];
    const btn = document.createElement('button');
    btn.className = 'pill' + (p[0] === filter ? ' active' : '');
    btn.dataset.sev = p[0];
    btn.textContent = p[1] + ' (' + n + ')';
    btn.addEventListener('click', function () {
      filter = p[0];
      document.querySelectorAll('.pill').forEach(function (x) { x.classList.remove('active'); });
      btn.classList.add('active');
      renderTable();
    });
    pills.appendChild(btn);
  });
}

document.getElementById('search').addEventListener('input', function (e) {
  query = e.target.value.toLowerCase();
  renderTable();
});

let queue = [];
let queueIndex = 0;
let queueDone = 0;
let queueFail = 0;
let queueLinks = [];

function buildIssueBody(f) {
  const BT = String.fromCharCode(96);
  return '**Finding:** ' + BT + f.id + BT + ' (' + f.severity + ')\n\n' +
    '**Vulnerability type:** ' + BT + (f.vulnType || '') + BT + '\n\n' +
    '**Location:** ' + BT + f.location + BT + '\n\n' +
    (f.param ? '**Parameter:** ' + BT + f.param + BT + '\n\n' : '') +
    (f.payload ? '**Payload:**\n\n' + BT + BT + BT + '\n' + f.payload + '\n' + BT + BT + BT + '\n\n' : '') +
    (f.evidence ? '**Evidence:**\n\n' + BT + BT + BT + '\n' + f.evidence + '\n' + BT + BT + BT + '\n\n' : '') +
    '---\n\n_Auto-generated by lain._\n\n<!-- lain-finding-id: ' + f.id + ' -->';
}

function openModal(f) {
  queue = [f];
  queueIndex = 0;
  queueDone = 0;
  queueFail = 0;
  queueLinks = [];
  document.getElementById('mi-title').textContent = 'Create GitHub issue';
  document.getElementById('mi-finding').textContent = f.severity + ' · ' + f.title + ' · ' + f.location;
  document.getElementById('mi-repo').value = DATA.githubRepo || '';
  document.getElementById('mi-token').value = '';
  document.getElementById('mi-status').textContent = '';
  document.getElementById('issue-modal').style.display = 'flex';
  document.getElementById('mi-token').focus();
}

function openBulkModal() {
  if (!visibleRows.length) return;
  queue = visibleRows.slice();
  queueIndex = 0;
  queueDone = 0;
  queueFail = 0;
  queueLinks = [];
  const c = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  queue.forEach(function (f) { if (c[f.severity] !== undefined) c[f.severity]++; });
  document.getElementById('mi-title').textContent = 'Create ' + queue.length + ' issues';
  document.getElementById('mi-finding').textContent =
    queue.length + ' finding(s) selected — HIGH: ' + c.HIGH + ', MEDIUM: ' + c.MEDIUM + ', LOW: ' + c.LOW;
  document.getElementById('mi-repo').value = DATA.githubRepo || '';
  document.getElementById('mi-token').value = '';
  document.getElementById('mi-status').textContent = '';
  document.getElementById('issue-modal').style.display = 'flex';
  document.getElementById('mi-token').focus();
}

function closeModal() {
  document.getElementById('issue-modal').style.display = 'none';
  queue = [];
}

document.getElementById('mi-cancel').addEventListener('click', closeModal);
document.getElementById('issue-modal').addEventListener('click', function (e) {
  if (e.target === this) closeModal();
});

document.getElementById('create-all').addEventListener('click', openBulkModal);

document.getElementById('mi-submit').addEventListener('click', function () {
  const token = document.getElementById('mi-token').value.trim();
  const repo = document.getElementById('mi-repo').value.trim();
  const status = document.getElementById('mi-status');
  const btn = document.getElementById('mi-submit');
  if (!token || !repo) { status.textContent = 'Provide both a GitHub token and a repo (owner/repo).'; return; }
  if (!queue.length) { closeModal(); return; }
  btn.disabled = true;

  function createOne() {
    if (queueIndex >= queue.length) {
      btn.disabled = false;
      status.textContent = '';
      if (queueFail === 0) {
        status.textContent = '✅ Created ' + queueDone + ' issue(s).';
      } else {
        status.textContent = 'Done: ' + queueDone + ' created, ' + queueFail + ' failed.';
      }
      queueLinks.forEach(function (url) {
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.textContent = ' → ' + url;
        a.style.display = 'block';
        status.appendChild(a);
      });
      return;
    }
    const f = queue[queueIndex];
    status.textContent = 'Creating issue ' + (queueIndex + 1) + ' of ' + queue.length + '…';
    fetch('https://api.github.com/repos/' + repo + '/issues', {
      method: 'POST',
      headers: {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title: '[lain] ' + f.severity + ': ' + f.title + ' — ' + f.location,
        body: buildIssueBody(f),
        labels: ['lain', 'lain:' + f.id]
      })
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, status: r.status, json: j }; }); })
      .then(function (res) {
        if (res.ok && res.json.html_url) {
          queueDone++;
          queueLinks.push(res.json.html_url);
        } else {
          queueFail++;
          queueLinks.push('failed (' + res.status + '): ' + (res.json.message || 'unknown error'));
        }
        queueIndex++;
        createOne();
      })
      .catch(function (err) {
        queueFail++;
        queueLinks.push('request failed: ' + err);
        queueIndex++;
        createOne();
      });
  }

  createOne();
});

renderHeader();
renderBar();
renderPills();
renderTable();
</script>
</body>
</html>
`