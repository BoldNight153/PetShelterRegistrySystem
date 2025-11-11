const fs = require('fs');
const path = require('path');

const logsPath = path.join(__dirname, 'logs.json');
const outJson = path.join(__dirname, 'analysis.json');
const outCsv = path.join(__dirname, 'analysis.csv');

console.log('Reading', logsPath);
const raw = fs.readFileSync(logsPath, 'utf8');
let events;
try {
  events = JSON.parse(raw);
} catch (err) {
  console.error('Failed to parse logs.json:', err);
  process.exit(2);
}

console.log('Events:', events.length);

const snapshots = [];
const requests = [];
const responses = [];

for (let i = 0; i < events.length; i++) {
  const e = events[i];
  if (!e || !e.type) continue;
  if (e.type === 'cookies') {
    snapshots.push({ ts: new Date(e.ts), raw: e });
  } else if (e.type === 'request') {
    // normalize url
    if (typeof e.url === 'string' && e.method === 'POST' && e.url.includes('/auth/refresh')) {
      requests.push({ idx: i, ts: new Date(e.ts), raw: e });
    }
  } else if (e.type === 'response') {
    if (typeof e.url === 'string' && e.url.includes('/auth/refresh')) {
      responses.push({ idx: i, ts: new Date(e.ts), raw: e });
    }
  }
}

console.log('Snapshots:', snapshots.length, 'Requests:', requests.length, 'Responses:', responses.length);

// helper to find nearest prior snapshot
function findPriorSnapshot(ts) {
  // snapshots are in chronological order as in file
  for (let i = snapshots.length - 1; i >= 0; i--) {
    if (snapshots[i].ts <= ts) return snapshots[i];
  }
  return null;
}

// helper to find nearest response for a request
function findResponseForRequest(reqTs) {
  // find first response with ts >= reqTs and minimal delta (up to 5s)
  let best = null;
  for (const r of responses) {
    if (r.ts >= reqTs) {
      const delta = r.ts - reqTs;
      if (delta <= 5000) {
        if (!best || r.ts < best.ts) best = r;
      }
    }
  }
  return best;
}

const out = [];

for (const req of requests) {
  const e = req.raw;
  const headers = e.headers || {};
  const xcsrf = headers['x-csrf-token'] || headers['X-CSRF-Token'] || headers['x-csrf-token'.toLowerCase()];
  const cookieHeaderPresent = Object.keys(headers).some(h => h.toLowerCase() === 'cookie');
  const snapshot = findPriorSnapshot(req.ts);
  const snapshotTs = snapshot ? snapshot.ts.toISOString() : null;
  let snapshotCsrf = null;
  let snapshotHasRefresh = false;
  if (snapshot) {
    const cookies = snapshot.raw.cookies || [];
    for (const c of cookies) {
      if (c.name === 'csrfToken') snapshotCsrf = c.value;
      if (c.name === 'refreshToken') snapshotHasRefresh = true;
    }
  }
  const resp = findResponseForRequest(req.ts);
  const status = resp ? resp.raw.status : null;
  const body = resp ? resp.raw.body : null;

  let classification = 'ambiguous';
  if (status === 401) classification = 'missing_refresh_token';
  else if (status === 403) {
    if (snapshotCsrf && xcsrf) {
      if (snapshotCsrf === xcsrf) classification = 'csrf_inconclusive_equal';
      else classification = 'csrf_mismatch';
    } else {
      classification = 'csrf_missing_data';
    }
  } else if (status && status >= 200 && status < 300) {
    classification = 'ok';
  }

  const note = [];
  if (snapshot) {
    if (snapshotHasRefresh) note.push('snapshot_has_refresh');
    else note.push('snapshot_no_refresh');
    if (snapshotCsrf) note.push('snapshot_csrf_present');
    else note.push('snapshot_csrf_missing');
  } else {
    note.push('no_prior_snapshot');
  }
  if (!cookieHeaderPresent) note.push('request_cookie_header_missing');
  if (!xcsrf) note.push('request_xcsrf_missing');

  // If snapshot shows refreshToken present but server responded 401 missing refresh token,
  // and request_cookie_header_missing is true, mark as 'trace_no_cookie_header_but_snapshot_has_cookie'
  if (classification === 'missing_refresh_token' && snapshotHasRefresh && !cookieHeaderPresent) {
    note.push('snapshot_has_refresh_but_request_no_cookie_header__possible_serialization_artifact');
  }

  out.push({
    requestIndex: req.idx,
    requestTs: req.ts.toISOString(),
    requestUrl: e.url,
    requestMethod: e.method,
    xCsrfHeader: xcsrf || null,
    requestCookieHeaderPresent: cookieHeaderPresent,
    snapshotTs,
    snapshotCsrf,
    snapshotHasRefresh,
    responseStatus: status,
    responseBody: body,
    classification,
    notes: note
  });
}

fs.writeFileSync(outJson, JSON.stringify(out, null, 2));

// write CSV header
const csvLines = ['requestIndex,requestTs,requestMethod,requestUrl,xCsrfHeader,requestCookieHeaderPresent,snapshotTs,snapshotHasRefresh,snapshotCsrf,responseStatus,classification,notes'];
for (const r of out) {
  const line = [
    r.requestIndex,
    '"' + r.requestTs + '"',
    r.requestMethod,
    '"' + r.requestUrl + '"',
    '"' + (r.xCsrfHeader ? r.xCsrfHeader.replace(/"/g, '""') : '') + '"',
    r.requestCookieHeaderPresent,
    '"' + (r.snapshotTs || '') + '"',
    r.snapshotHasRefresh,
    '"' + (r.snapshotCsrf ? (r.snapshotCsrf.replace(/"/g, '""')) : '') + '"',
    r.responseStatus || '',
    r.classification,
    '"' + (r.notes.join(';') || '') + '"'
  ];
  csvLines.push(line.join(','));
}
fs.writeFileSync(outCsv, csvLines.join('\n'));

console.log('Wrote', outJson, outCsv);
