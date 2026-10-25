/* global Buffer, URL */
// Fake Jira Cloud REST v3 (the endpoints of connector-packs/jira-cloud) for tests. Requires Basic auth
// alice@example.com:jira-token-1. Records requests for assertions.
export function createFakeJira() {
  const issues = new Map([['SEC-1', { id: '10001', key: 'SEC-1', fields: { summary: 'Order IDOR', status: { name: 'To Do' }, labels: ['audit'], assignee: { displayName: 'Bob' } } }]]);
  const requests = [];
  let next = 2;
  const handler = (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      requests.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body: body ? JSON.parse(body) : null, auth: req.headers.authorization });
      const send = (status, json) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(json === undefined ? '' : JSON.stringify(json)); };
      if (req.headers.authorization !== `Basic ${Buffer.from('alice@example.com:jira-token-1').toString('base64')}`) return send(401, { errorMessages: ['unauthorized'] });
      if (req.method === 'GET' && url.pathname === '/rest/api/3/search/jql') {
        const q = (url.searchParams.get('jql') ?? '').toLowerCase();
        return send(200, { issues: [...issues.values()].filter((i) => !q.includes('text ~') || i.fields.summary.toLowerCase().includes(q.split('"')[1] ?? '')), isLast: true });
      }
      let m = /^\/rest\/api\/3\/issue\/([^/]+)$/.exec(url.pathname);
      if (m && req.method === 'GET') {
        const i = issues.get(decodeURIComponent(m[1]));
        return i ? send(200, i) : send(404, { errorMessages: ['Issue does not exist'] });
      }
      if (url.pathname === '/rest/api/3/issue' && req.method === 'POST') {
        const f = JSON.parse(body).fields;
        const key = `${f.project.key}-${next++}`;
        issues.set(key, { id: String(10000 + next), key, fields: { summary: f.summary, status: { name: 'To Do' }, labels: f.labels ?? [], assignee: null } });
        return send(201, { id: String(10000 + next), key, self: `https://jira.example/rest/api/3/issue/${key}` });
      }
      if (/^\/rest\/api\/3\/issue\/[^/]+\/comment$/.test(url.pathname) && req.method === 'POST') return send(201, { id: '900', self: `https://jira.example/comment/900` });
      if ((m = /^\/rest\/api\/3\/issue\/([^/]+)\/transitions$/.exec(url.pathname))) {
        if (req.method === 'GET') return send(200, { transitions: [{ id: '31', name: 'Done', to: { name: 'Done' } }] });
        const i = issues.get(decodeURIComponent(m[1]));
        if (i) i.fields.status = { name: 'Done' };
        return send(204);
      }
      return send(404, { errorMessages: ['not found'] });
    });
  };
  return { handler, issues, requests };
}
