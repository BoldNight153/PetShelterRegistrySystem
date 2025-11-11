const fs = require('fs');
const path = require('path');

const workspace = process.cwd();
const analysisCsv = path.join(workspace, 'devtools/playwright/analysis.csv');
const backendLog = path.join(workspace, 'devtools/backend-dev.log');
const outCsv = path.join(workspace, 'devtools/playwright/analysis-joined.csv');

if (!fs.existsSync(analysisCsv)) {
  console.error('analysis.csv not found:', analysisCsv);
  process.exit(2);
}
if (!fs.existsSync(backendLog)) {
  console.error('backend-dev.log not found:', backendLog);
  process.exit(2);
}

const csv = fs.readFileSync(analysisCsv, 'utf8').split('\n').filter(Boolean);
const headers = csv[0].split(',').map(h=>h.trim());
const rows = csv.slice(1).map(line => {
  // naive CSV split that assumes no commas in fields (analysis.csv is simple)
  const parts = line.split(',').map(p=>p.trim());
  const obj = {};
  headers.forEach((h,i)=> obj[h]=parts[i]||'');
  return obj;
});

const backend = fs.readFileSync(backendLog, 'utf8');

// Build a list of diagnostic snippets from the backend log with timestamps so
// we can match analyzer rows to the nearest backend log entry by time.
function buildBackendDiagnostics() {
  const lines = backend.split('\n');
  const diags = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // try to find a numeric "time": <ms> field (JSON logger) or a human timestamp
    const timeMatch = /"time"\s*:\s*(\d{12,})/.exec(line) || /"time"\s*:\s*(\d+)/.exec(line);
    if (timeMatch) {
      const t = Number(timeMatch[1]);
      // build a small window of context around this line
      const start = Math.max(0, i - 3);
      const end = Math.min(lines.length - 1, i + 3);
      const snippet = lines.slice(start, end + 1).join('\n');
      diags.push({ time: t, snippet, idx: i });
    } else if (/\[diagnostic\]|diagnostic \/\w+/.test(line)) {
      // fallback: include diagnostic-only lines without explicit time
      const start = Math.max(0, i - 3);
      const end = Math.min(lines.length - 1, i + 3);
      const snippet = lines.slice(start, end + 1).join('\n');
      // no numeric time; set time to NaN and let timestamp matching skip these unless nothing else
      diags.push({ time: NaN, snippet, idx: i });
    }
  }
  return diags;
}

const backendDiags = buildBackendDiagnostics();

function findBackendContextByTime(requestTsIso) {
  if (!requestTsIso) return null;
  const reqTime = Date.parse(requestTsIso);
  if (isNaN(reqTime)) return null;

  // find the diag with minimal absolute time delta (only consider diags with numeric time)
  let best = null;
  let bestDelta = Infinity;
  const TOLERANCE_MS = 2000; // 2s tolerance
  for (const d of backendDiags) {
    if (!d || !d.time || isNaN(d.time)) continue;
    const delta = Math.abs(d.time - reqTime);
    if (delta < bestDelta) {
      bestDelta = delta;
      best = d;
    }
  }
  if (!best || bestDelta > TOLERANCE_MS) return null;

  const snippet = best.snippet;
  const cookieMatch = /cookieHeader=\s*([^\n,}]*)/m.exec(snippet) || /cookie":"([^\"]+)"/m.exec(snippet);
  const parsedMatch = /parsedCookies=\s*(\{[^\}]*\})/m.exec(snippet);
  const xcsrfMatch = /xCsrfHeader"?:?\s*"?([a-f0-9\.]+)"?/i.exec(snippet) || /x-csrf-token"?:?\s*"?([a-f0-9\.]+)"?/i.exec(snippet) || /x-csrf-token=\s*([a-f0-9\.]+)/i.exec(snippet) || /x-csrf-token"?:?\s*([^\s,\"]+)/i.exec(snippet);
  const msgMatch = /msg"?:?\s*"?([^"\n}]*)"?/i.exec(snippet) || /\[diagnostic\]\s*([^\n]*)/i.exec(snippet) || /diagnostic \/[a-zA-Z]+\s*-?\s*([^\n]*)/i.exec(snippet);

  return {
    snippet: snippet.replace(/\n/g, ' <NL> '),
    cookieHeader: cookieMatch ? cookieMatch[1].trim() : '',
    parsedCookies: parsedMatch ? parsedMatch[1].trim() : '',
    serverXcsrf: xcsrfMatch ? xcsrfMatch[1].trim() : '',
    msg: msgMatch ? msgMatch[1].trim() : ''
  };
}

const outHeaders = [
  'requestIndex','requestTs','xCsrfHeader','requestCookieHeaderPresent','snapshotTs','snapshotCsrf','responseStatus','classification','notes',
  'server_cookieHeader','server_parsedCookies','server_xCsrfHeader','server_msg'
];

const lines = [outHeaders.join(',')];
for (const r of rows) {
  const token = (r['xCsrfHeader'] || r['xCsrf Header'] || '').replace(/"/g,'');
  // prefer matching backend diagnostics by request timestamp
  const ctx = findBackendContextByTime((r['requestTs'] || '').replace(/"/g, ''));
  const out = [
    r['requestIndex']||'', r['requestTs']||'', token||'', r['requestCookieHeaderPresent']||'', r['snapshotTs']||'', r['snapshotCsrf']||'', r['responseStatus']||'', r['classification']||'', r['notes']||'',
    ctx ? '"'+ctx.cookieHeader.replace(/"/g,'""')+'"' : '',
    ctx ? '"'+ctx.parsedCookies.replace(/"/g,'""')+'"' : '',
    ctx ? ctx.serverXcsrf : '',
    ctx ? '"'+ctx.msg.replace(/"/g,'""')+'"' : ''
  ];
  lines.push(out.join(','));
}

fs.writeFileSync(outCsv, lines.join('\n'), 'utf8');
console.log('Wrote', outCsv, 'rows:', lines.length-1);
