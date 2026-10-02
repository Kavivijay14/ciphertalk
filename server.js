// CipherTalk relay server: accounts + live relay of ciphertext only.
// Messages are never stored. Accounts live in memory (lost on restart).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

const server = http.createServer((req, res) => {
  fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, data) => {
    if (err) { res.writeHead(500); return res.end('Server error'); }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server });
const accounts = new Map(); // email -> {id,email,name,salt,hash,status}
const online = new Map();   // id -> {ws,pub,name,status}
const send = (ws, o) => ws.send(JSON.stringify(o));
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');

function broadcast() {
  const list = [...online].map(([id, u]) => ({ id, name: u.name, status: u.status, pub: u.pub }));
  for (const u of online.values()) send(u.ws, { type: 'users', list });
}

wss.on('connection', (ws) => {
  let id = null;
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }

    if (m.type === 'auth') {
      const email = String(m.email || '').trim().toLowerCase();
      let acc = accounts.get(email);
      const fail = (text) => send(ws, { type: 'error', text });
      if (m.mode === 'signup') {
        if (!email || !m.password || !String(m.name || '').trim()) return fail('Fill in name, email and password.');
        if (acc) return fail('An account with this email already exists.');
        const salt = crypto.randomBytes(16).toString('hex');
        acc = { id: crypto.randomUUID(), email, name: String(m.name).trim().slice(0, 30), salt,
                hash: hash(m.password, salt), status: 'Hey there! I am using CipherTalk' };
        accounts.set(email, acc);
      } else if (!acc || hash(String(m.password), acc.salt) !== acc.hash) {
        return fail('Wrong email or password.');
      }
      if (online.has(acc.id)) return fail('This account is already signed in elsewhere.');
      id = acc.id;
      online.set(id, { ws, pub: m.pub, name: acc.name, status: acc.status });
      send(ws, { type: 'authed', me: { id, email, name: acc.name, status: acc.status } });
      broadcast();
    }
    if (!id) return;

    if (m.type === 'msg') {
      const t = online.get(m.to);
      if (!t) return;
      console.log(`[relay] ${online.get(id).name} -> ${t.name} | ciphertext: ${String(m.ct).slice(0, 48)}...`);
      send(t.ws, { type: 'msg', from: id, iv: m.iv, ct: m.ct, fiv: m.fiv, fct: m.fct, ts: Date.now() });
    }
    if (m.type === 'profile') {
      const acc = [...accounts.values()].find(a => a.id === id);
      acc.name = String(m.name || acc.name).trim().slice(0, 30);
      acc.status = String(m.status || '').slice(0, 80);
      Object.assign(online.get(id), { name: acc.name, status: acc.status });
      broadcast();
    }
  });
  ws.on('close', () => { if (id) { online.delete(id); broadcast(); } });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('CipherTalk running on port ' + PORT));
