// ============================================================
// OLT TERMINAL (CLI via browser)
// WebSocket  <->  Telnet ke OLT.  Untuk role admin & operator, ada audit log.
//
// Kredensial OLT TIDAK pernah dikirim ke browser — login otomatis dilakukan di server.
// Pasang di server.js:
//   const server = app.listen(PORT, ...);
//   require('./olt-terminal-backend')(app, server, { requireAuth, OLT_CONFIG, db });
// Butuh paket:  npm install ws
// ============================================================
const crypto = require('crypto');
const net = require('net');
const { StringDecoder } = require('string_decoder');
const { WebSocketServer } = require('ws');

const WS_PATH        = '/ws/olt-terminal';
const TICKET_TTL_MS  = 30 * 1000;          // tiket sekali pakai, berlaku 30 detik
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;    // putus otomatis kalau 15 menit tidak ada input
const MAX_SESSIONS_PER_USER = 3;
const CONNECT_TIMEOUT_MS = 10 * 1000;
const ALLOWED_ROLES  = ['admin', 'operator'];   // role yang boleh memakai terminal

// Telnet bytes
const IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240;
const OPT_ECHO = 1, OPT_SGA = 3, OPT_TTYPE = 24, OPT_NAWS = 31;

module.exports = function setupOltTerminal(app, server, { requireAuth, OLT_CONFIG, db }) {
  db.exec(`CREATE TABLE IF NOT EXISTS olt_terminal_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    username TEXT, olt TEXT, event TEXT, detail TEXT, ip TEXT
  )`);
  const insAudit = db.prepare('INSERT INTO olt_terminal_audit (username, olt, event, detail, ip) VALUES (?,?,?,?,?)');
  const audit = (u, olt, ev, detail, ip) => { try { insAudit.run(u, olt, ev, (detail || '').slice(0, 500), ip || ''); } catch (e) { /* abaikan */ } };

  const tickets = new Map();               // ticket -> {username, role, olt, exp}
  const active  = new Map();               // username -> jumlah sesi

  const allowed = (req, res, next) =>
    req.user && ALLOWED_ROLES.includes(req.user.role) ? next() : res.status(403).json({ success: false, message: 'Akses ditolak — terminal OLT hanya untuk admin / operator' });

  // 1) Minta tiket (dipanggil dengan Authorization header biasa)
  app.post('/api/olt-terminal/ticket', requireAuth, allowed, (req, res) => {
    const olt = String((req.body && req.body.olt) || '');
    if (!OLT_CONFIG[olt]) return res.status(404).json({ success: false, message: 'OLT tidak ditemukan' });
    const t = crypto.randomBytes(24).toString('hex');
    tickets.set(t, { username: req.user.username, role: req.user.role, olt, exp: Date.now() + TICKET_TTL_MS });
    for (const [k, v] of tickets) if (v.exp < Date.now()) tickets.delete(k);
    res.json({ success: true, ticket: t, path: WS_PATH });
  });

  // 2) Riwayat audit
  app.get('/api/olt-terminal/audit', requireAuth, allowed, (req, res) => {
    // admin melihat semua; operator hanya riwayat miliknya sendiri
    const rows = req.user.role === 'admin'
      ? db.prepare('SELECT ts, username, olt, event, detail, ip FROM olt_terminal_audit ORDER BY id DESC LIMIT 200').all()
      : db.prepare('SELECT ts, username, olt, event, detail, ip FROM olt_terminal_audit WHERE username = ? ORDER BY id DESC LIMIT 200').all(req.user.username);
    res.json({ success: true, rows });
  });

  // 3) WebSocket
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  server.on('upgrade', (req, socket, head) => {
    let url;
    try { url = new URL(req.url, 'http://x'); } catch (e) { return socket.destroy(); }
    if (url.pathname !== WS_PATH) return;                       // biarkan upgrade lain (kalau ada)
    const t = url.searchParams.get('ticket');
    const info = t && tickets.get(t);
    if (t) tickets.delete(t);                                    // sekali pakai
    if (!info || info.exp < Date.now() || !ALLOWED_ROLES.includes(info.role)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      return socket.destroy();
    }
    if ((active.get(info.username) || 0) >= MAX_SESSIONS_PER_USER) {
      socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
      return socket.destroy();
    }
    wss.handleUpgrade(req, socket, head, ws => handleSession(ws, info, req.socket.remoteAddress));
  });

  function handleSession(ws, info, ip) {
    const cfg = OLT_CONFIG[info.olt];
    const { username, olt } = info;
    if (!cfg) { ws.close(); return; }

    active.set(username, (active.get(username) || 0) + 1);
    audit(username, olt, 'open', `${cfg.host}:${cfg.port || 23}`, ip);

    const send = o => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
    const sock = net.createConnection({ host: cfg.host, port: cfg.port || 23 });
    sock.setNoDelay(true);
    sock.setTimeout(CONNECT_TIMEOUT_MS);

    const dec = new StringDecoder('utf8');
    let cols = 100, rows = 30, connected = false, closed = false;
    let sentUser = false, sentPass = false, tail = '';
    const optState = {};                    // opsi telnet yang sudah disetujui
    let ps = 'data', cmd = 0, sb = [];     // parser telnet
    let line = '', lastActivity = Date.now();

    const idle = setInterval(() => {
      if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) { send({ t: 's', msg: 'Sesi diputus: tidak ada aktivitas 15 menit.' }); end('idle'); }
    }, 30000);

    function end(reason) {
      if (closed) return; closed = true;
      clearInterval(idle);
      try { sock.destroy(); } catch (e) {}
      try { ws.close(); } catch (e) {}
      const n = (active.get(username) || 1) - 1;
      if (n <= 0) active.delete(username); else active.set(username, n);
      audit(username, olt, 'close', reason, ip);
    }

    const nawsFrame = () => Buffer.from([IAC, SB, OPT_NAWS, cols >> 8, cols & 255, rows >> 8, rows & 255, IAC, SE]);
    const reply = (...b) => { if (!sock.destroyed) sock.write(Buffer.from(b)); };

    function onOption(c, opt) {
      if (c === WILL) {
        if ((opt === OPT_ECHO || opt === OPT_SGA)) { if (!optState['r' + opt]) { optState['r' + opt] = 1; reply(IAC, DO, opt); } }
        else reply(IAC, DONT, opt);
      } else if (c === DO) {
        if (opt === OPT_NAWS) { if (!optState.naws) { optState.naws = 1; reply(IAC, WILL, OPT_NAWS); sock.write(nawsFrame()); } }
        else if (opt === OPT_TTYPE) { if (!optState.ttype) { optState.ttype = 1; reply(IAC, WILL, OPT_TTYPE); } }
        else if (opt === OPT_SGA) { if (!optState.sga) { optState.sga = 1; reply(IAC, WILL, OPT_SGA); } }
        else reply(IAC, WONT, opt);
      }
    }

    // Parser telnet: pisahkan data biasa dari perintah IAC (aman walau terpotong antar paket)
    function parse(buf) {
      const out = [];
      for (const b of buf) {
        if (ps === 'data') { if (b === IAC) ps = 'iac'; else out.push(b); }
        else if (ps === 'iac') {
          if (b === IAC) { out.push(255); ps = 'data'; }
          else if (b === SB) { ps = 'sb'; sb = []; }
          else if (b === DO || b === DONT || b === WILL || b === WONT) { cmd = b; ps = 'opt'; }
          else ps = 'data';
        }
        else if (ps === 'opt') { onOption(cmd, b); ps = 'data'; }
        else if (ps === 'sb') { if (b === IAC) ps = 'sbiac'; else sb.push(b); }
        else if (ps === 'sbiac') {
          if (b === SE) {
            // SB TTYPE SEND  ->  IS xterm
            if (sb[0] === OPT_TTYPE && sb[1] === 1) sock.write(Buffer.concat([Buffer.from([IAC, SB, OPT_TTYPE, 0]), Buffer.from('xterm'), Buffer.from([IAC, SE])]));
            ps = 'data';
          } else { sb.push(b); ps = 'sb'; }
        }
      }
      return Buffer.from(out);
    }

    sock.on('connect', () => {
      connected = true; sock.setTimeout(0);
      send({ t: 's', msg: `Terhubung ke ${olt} (${cfg.host}). Login otomatis…`, ok: true });
    });

    sock.on('data', chunk => {
      const data = parse(chunk);
      if (!data.length) return;
      const text = dec.write(data);
      if (!text) return;
      send({ t: 'o', d: text });

      // login otomatis (hanya sekali per prompt)
      tail = (tail + text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')).slice(-120);
      if (!sentUser && /(user(name)?|login)\s*:\s*$/i.test(tail)) { sentUser = true; tail = ''; sock.write(cfg.username + '\r\n'); }
      else if (!sentPass && /password\s*:\s*$/i.test(tail)) { sentPass = true; tail = ''; sock.write(cfg.password + '\r\n'); }
    });

    sock.on('timeout', () => { send({ t: 's', msg: 'Koneksi ke OLT timeout.', err: true }); end('connect-timeout'); });
    sock.on('error', e => { send({ t: 's', msg: 'Gagal terhubung: ' + e.message, err: true }); end('error: ' + e.message); });
    sock.on('close', () => { send({ t: 's', msg: 'Koneksi ke OLT ditutup.' }); end('olt-closed'); });

    ws.on('message', raw => {
      let m; try { m = JSON.parse(raw.toString()); } catch (e) { return; }
      lastActivity = Date.now();
      if (m.t === 'i' && typeof m.d === 'string' && connected && !sock.destroyed) {
        // catat perintah yang diketik (per baris)
        for (const ch of m.d) {
          if (ch === '\r' || ch === '\n') { if (line.trim()) audit(username, olt, 'cmd', line.trim(), ip); line = ''; }
          else if (ch === '\x7f' || ch === '\b') line = line.slice(0, -1);
          else if (ch >= ' ') line += ch;
        }
        sock.write(m.d.replace(/\r(?!\n)/g, '\r\n'));
      } else if (m.t === 'r') {
        cols = Math.max(20, Math.min(400, m.cols | 0)); rows = Math.max(5, Math.min(200, m.rows | 0));
        if (optState.naws && connected) sock.write(nawsFrame());
      }
    });
    ws.on('close', () => end('browser-closed'));
    ws.on('error', () => end('ws-error'));
  }
};
